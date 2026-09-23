"""Local workbench: synchronous API compatibility plus cancellable background jobs."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .analyzer import MAX_INPUT, analyze, profile_limits
from .dialogs import choose_file
from .jobs import Job
from .export_api import handle as export_request
from .runtime import AnalysisCancelled
from .tooling import ToolConfig
from .projects import ProjectStore
from .workspace_api import handle as workspace_request, authorized

STATIC = Path(__file__).with_name('static')
ALLOWED = {'.apk', '.aab', '.dex', '.zip', '.jar', '.smali', '.java', '.kt', '.proto', '.pb', '.desc',
           '.protoset', '.bin', '.so', '.xml', '.json', '.txt', '.xapk', '.apks', '.obb', '.dat', '.arsc'}


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, allow_decoders=False, tool_config=None, desktop_tools=False, projects_root=None):
        if desktop_tools and address[0] not in {'127.0.0.1', 'localhost', '::1'}:
            raise ValueError('Desktop tool configuration requires a loopback listener')
        self.jobs_lock = threading.Lock()
        self.jobs = {}
        super().__init__(address, Handler)
        self.allow_decoders = allow_decoders
        self.tool_config = tool_config or ToolConfig()
        self.desktop_tools = desktop_tools
        self.config_token = secrets.token_urlsafe(24)
        self.analysis_lock = threading.BoundedSemaphore(1)
        self.export_lock = threading.BoundedSemaphore(1)
        self.projects = ProjectStore(projects_root)

    def get_job(self, key):
        with self.jobs_lock:
            now = time.monotonic()
            self.jobs = {k: job for k, job in self.jobs.items() if job.finished is None or now - job.finished < 3600}
            return self.jobs.get(key)

    def start_job(self, target, name, options, cleanup=None, digest=None, task=None):
        # The caller owns analysis_lock; the worker assumes that ownership until cleanup.
        job = Job(name)
        job.private = task is not None
        config = self.tool_config
        with self.jobs_lock:
            while len(self.jobs) >= 2:
                done = next((k for k, old in self.jobs.items() if old.finished is not None), None)
                if done is None:
                    raise ValueError('Job capacity reached')
                del self.jobs[done]
            self.jobs[job.id] = job
        def work():
            status, result, error = 'failed', None, None
            try:
                if task:
                    result = task(progress=job.update, cancel=job.cancel.is_set)
                else:
                    result = analyze(target, display_name=name, tool_config=config, progress=job.update,
                                     cancel=job.cancel.is_set, input_digest=digest, **options)
                status = 'completed'
            except AnalysisCancelled:
                status = 'cancelled'
            except Exception as exc:
                error = str(exc) if isinstance(exc, (ValueError, OSError)) else 'Analysis failed; check the input format or use CLI diagnostics.'
            finally:
                job.update({**job.snapshot()['progress'], 'stage': 'cleaning', 'file': name})
                try:
                    if cleanup:
                        cleanup.cleanup()
                except OSError:
                    if result:
                        result['warnings'].append('Some temporary files could not be deleted; check the system temp directory.')
                finally:
                    self.analysis_lock.release()
                    if job.cancel.is_set():
                        status, result = 'cancelled', None
                    job.finish(status, result, error)
        job.thread = threading.Thread(target=work, name='ProtoHunter analysis', daemon=True)
        try:
            job.thread.start()
        except Exception:
            with self.jobs_lock:
                self.jobs.pop(job.id, None)
            raise
        return job

    def server_close(self):
        with self.jobs_lock:
            active = list(self.jobs.values())
        for job in active:
            job.request_cancel()
        for job in active:
            if job.thread:
                job.thread.join(timeout=5)
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    server_version = 'ProtoHunter/' + __version__

    def setup(self):
        super().setup()
        self.connection.settimeout(60)

    def respond(self, status, payload, content_type='application/json; charset=utf-8'):
        if not isinstance(payload, bytes):
            payload = json.dumps(payload, ensure_ascii=True).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def local_desktop(self):
        try:
            host = urlsplit('http://' + self.headers.get('Host', ''))
            return (self.server.desktop_tools and host.hostname in {'127.0.0.1', 'localhost', '::1'}
                    and host.port == self.server.server_port)
        except ValueError:
            return False

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/api/status':
            desktop = self.local_desktop()
            self.respond(200, {'version': __version__, 'tools': self.server.tool_config.status(private=desktop),
                'allow_decoders': self.server.allow_decoders, 'desktop_tools': desktop,
                'native_picker': desktop and os.name == 'nt', 'config_token': self.server.config_token if desktop else None,
                'max_upload_bytes': MAX_INPUT, 'profiles': {p: profile_limits(p) for p in ('standard', 'games')}})
            return
        if path.startswith('/api/jobs/'):
            parts = path.strip('/').split('/')
            if len(parts) not in (3, 4) or (len(parts) == 4 and parts[3] != 'result'):
                self.respond(404, {'error': 'Not found'}); return
            job = self.server.get_job(parts[2])
            if not job:
                self.respond(404, {'error': 'Job not found or expired'}); return
            if getattr(job, 'private', False) and not authorized(self):
                self.respond(403, {'error': 'Desktop token required'}); return
            if len(parts) == 4:
                if job.status != 'completed':
                    self.respond(409, {'error': 'Report is not ready', 'status': job.status}); return
                self.respond(200, job.report)
            else:
                self.respond(200, job.snapshot())
            return
        names = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css', '/icon.svg': 'icon.svg', '/workspace.js': 'workspace.js', '/investigation.js': 'investigation.js'}
        if path not in names:
            self.respond(404, {'error': 'Not found'}); return
        file = STATIC / names[path]
        types = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml'}
        self.respond(200, file.read_bytes(), types[file.suffix])

    def validate_options(self, query):
        options = {key: query.get(key, [default])[0] for key, default in [('profile', 'standard'), ('decode', 'none'), ('scan_mode', 'deep')]}
        mode = query.get('investigate', ['false'])[0]
        if mode not in {'true', 'false'}: raise ValueError('Invalid investigation option')
        options['investigate'] = mode == 'true'
        profile_limits(options['profile'])
        if options['scan_mode'] not in {'fast', 'deep'} or options['decode'] not in {'none', 'auto', 'jadx', 'apktool', 'both'}:
            raise ValueError('Unknown scan mode or decoder')
        if options['decode'] != 'none' and not self.server.allow_decoders:
            raise ValueError('External decoders are disabled. Start with --allow-decoders.')
        return options

    def read_json(self, limit=16384):
        length = int(self.headers.get('Content-Length', '-1'))
        if not 0 <= length <= limit:
            raise ValueError(f'JSON request limit is {limit // 1024} KiB')
        result = json.loads(self.rfile.read(length) or b'{}')
        if not isinstance(result, dict):
            raise ValueError('Expected a JSON object')
        return result

    def do_POST(self):
        request = urlsplit(self.path)
        path = request.path
        origin = self.headers.get('Origin')
        if (origin and urlsplit(origin).netloc != self.headers.get('Host')) or self.headers.get('Sec-Fetch-Site') == 'cross-site':
            self.respond(403, {'error': 'Cross-origin requests are not allowed'}); return
        if path == '/api/bot-compare':
            from .bot_api import handle
            handle(self); return
        if path == '/api/export-sections':
            export_request(self); return
        if path == '/api/workspace':
            workspace_request(self); return
        desktop_request = path in {'/api/tools', '/api/choose-tool', '/api/local-file'}
        expected = 'application/json' if desktop_request else 'application/octet-stream'
        if self.headers.get('Content-Type', '').split(';')[0] != expected:
            self.respond(415, {'error': 'Use ' + expected}); return
        if desktop_request and (not self.local_desktop() or not secrets.compare_digest(self.headers.get('X-ProtoHunter-Config-Token', ''), self.server.config_token)):
            self.respond(403, {'error': 'Tool/local-file settings are available only in the trusted desktop interface'}); return
        owned = False
        temporary = None
        try:
            if self.headers.get('Transfer-Encoding'):
                raise ValueError('Chunked requests are not supported')
            if path.startswith('/api/jobs/') and path.endswith('/cancel'):
                parts = path.strip('/').split('/')
                if len(parts) != 4 or self.headers.get('Content-Length', '0') != '0':
                    raise ValueError('Cancel requests must have an empty body')
                job = self.server.get_job(parts[2])
                if not job:
                    self.respond(404, {'error': 'Job not found'}); return
                if getattr(job, 'private', False) and not authorized(self):
                    self.respond(403, {'error': 'Desktop token required'}); return
                job.request_cancel()
                self.respond(200, job.snapshot()); return
            if path not in {'/api/analyze', '/api/demo', '/api/jobs', '/api/tools', '/api/choose-tool', '/api/local-file'}:
                self.respond(404, {'error': 'Not found'}); return
            query = parse_qs(request.query)
            options = self.validate_options(query)
            if not desktop_request:
                length = int(self.headers.get('Content-Length', '-1'))
                limit = profile_limits(options['profile'])['input']
                if not 0 <= length <= limit:
                    self.respond(413, {'error': f'Upload limit is {limit // 1024**2} MiB; Content-Length is required'}); return
                filename = query.get('name', ['input.apk'])[0].replace('\\', '/').rsplit('/', 1)[-1]
                if not filename or len(filename) > 200 or any(ord(c) < 32 for c in filename):
                    raise ValueError('Invalid filename')
                if path != '/api/demo' and Path(filename).suffix.lower() not in ALLOWED:
                    raise ValueError('Unsupported file extension')
            if not self.server.analysis_lock.acquire(blocking=False):
                self.respond(429, {'error': 'Another analysis or settings action is running'}); return
            owned = True
            if desktop_request:
                body = self.read_json()
                if path == '/api/tools':
                    if not all(isinstance(body.get(key, ''), str) for key in ToolConfig.__dataclass_fields__):
                        raise ValueError('Tool paths must be strings')
                    if 'use_bundled' in body and not isinstance(body['use_bundled'], bool):
                        raise ValueError('use_bundled must be a boolean')
                    prefer_bundled = body.get('use_bundled', False)
                    values = {key: body.get(key, '') for key in ToolConfig.__dataclass_fields__}
                    if prefer_bundled:
                        for key in ('apktool_jar', 'java', 'jadx', 'il2cpp', 'dotnet'):
                            values[key] = ''
                    config = ToolConfig(**values)
                    config.save(prefer_bundled=prefer_bundled)
                    self.server.tool_config = config
                    result = {'tools': config.status(private=True), 'checks': config.probe()}
                elif path == '/api/choose-tool':
                    kind = body.get('kind')
                    if kind not in {'apktool', 'java', 'jadx', 'il2cpp', 'dotnet', 'apksigner', 'zipalign'}:
                        raise ValueError('Choose a supported tool')
                    result = {'path': choose_file(kind)}
                else:
                    chosen = choose_file('input')
                    if not chosen:
                        self.server.analysis_lock.release(); owned = False
                        self.respond(200, {'cancelled': True}); return
                    target = Path(chosen)
                    if target.suffix.lower() not in ALLOWED or target.stat().st_size > profile_limits(options['profile'])['input']:
                        raise ValueError('Unsupported or oversized local input')
                    job = self.server.start_job(target, target.name, options)
                    owned = False
                    self.respond(202, {'job_id': job.id, 'name': target.name, 'local': True}); return
            else:
                temporary = tempfile.TemporaryDirectory(prefix='protohunter-upload-')
                target = Path(temporary.name, 'input' + Path(filename).suffix.lower())
                digest = hashlib.sha256()
                with target.open('wb') as stream:
                    remaining = length
                    while remaining:
                        chunk = self.rfile.read(min(1024**2, remaining))
                        if not chunk:
                            raise ValueError('Upload ended early')
                        stream.write(chunk); digest.update(chunk); remaining -= len(chunk)
                if path == '/api/jobs':
                    job = self.server.start_job(target, filename, options, cleanup=temporary, digest=digest.hexdigest())
                    owned = False; temporary = None
                    self.respond(202, {'job_id': job.id, 'name': filename}); return
                if path == '/api/demo':
                    result = analyze(Path(__file__).with_name('demo.smali'), investigate=options['investigate'])
                    result['input']['demo'] = True
                else:
                    result = analyze(target, display_name=filename, tool_config=self.server.tool_config,
                                     input_digest=digest.hexdigest(), **options)
            if temporary:
                temporary.cleanup(); temporary = None
            self.server.analysis_lock.release(); owned = False
            self.respond(200, result)
        except (ValueError, OSError) as exc:
            if owned and temporary is None:
                self.server.analysis_lock.release(); owned = False
            self.respond(400, {'error': str(exc)})
        except Exception:
            if owned and temporary is None:
                self.server.analysis_lock.release(); owned = False
            self.respond(500, {'error': 'Request failed. Check the input or use CLI diagnostics.'})
        finally:
            try:
                if temporary:
                    temporary.cleanup()
            finally:
                if owned:
                    self.server.analysis_lock.release()


def serve(host='127.0.0.1', port=8765, allow_decoders=False, tool_config=None, desktop_tools=False):
    with Server((host, port), allow_decoders, tool_config=tool_config, desktop_tools=desktop_tools) as server:
        print(f'ProtoHunter: http://{host}:{server.server_port} (Ctrl+C to stop)', flush=True)
        if host not in {'127.0.0.1', 'localhost', '::1'}:
            print('Warning: no authentication. Use only on a trusted network / protected preview.', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
