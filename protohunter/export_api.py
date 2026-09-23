"""Section downloads: small references normally, bounded report fallback for demo/expired jobs."""
import json
import tempfile
from .exports import export_zip, download_name
from .workspace_api import authorized

MAX_REPORT = 64 * 1024**2


def handle(handler):
    if handler.headers.get('Content-Type', '').split(';')[0] != 'application/json':
        handler.respond(415, {'error': 'Use application/json'}); return
    if not handler.server.export_lock.acquire(blocking=False):
        handler.respond(429, {'error': 'Another export is running'}); return
    started = False
    owned = True
    def reply(status, data):
        nonlocal owned
        if owned:
            handler.server.export_lock.release(); owned = False
        handler.respond(status, data)
    try:
        if handler.headers.get('Transfer-Encoding'):
            raise ValueError('Chunked export requests are not supported')
        body = handler.read_json(limit=MAX_REPORT)
        if 'job' in body:
            if not isinstance(body['job'], str):
                raise ValueError('Invalid job ID')
            job = handler.server.get_job(body['job'])
            if not job:
                reply(404, {'error': 'Report job expired'}); return
            if getattr(job, 'private', False) and not authorized(handler):
                reply(403, {'error': 'Desktop token required'}); return
            if job.status != 'completed':
                reply(409, {'error': 'Report is not ready'}); return
            report = job.report
        elif 'project' in body:
            if not authorized(handler):
                reply(403, {'error': 'Desktop token required'}); return
            store = handler.server.projects
            data = store.load(body['project'])
            run = next((r for r in data['runs'] if r['id'] == body.get('run') and r['operation'] == 'inspect' and r['status'] == 'completed'), None)
            if not run:
                raise ValueError('Completed inspection run not found')
            path = store.safe(data['id'], run['path'] + '/report.json')
            if path.stat().st_size > MAX_REPORT:
                raise ValueError('Report exceeds 64 MiB; use the project sections folder')
            report = json.loads(path.read_text(encoding='utf-8'))
        else:
            report = body.get('report')
        with tempfile.SpooledTemporaryFile(max_size=8 * 1024**2) as archive:
            export_zip(report, archive)
            size = archive.tell(); archive.seek(0)
            handler.send_response(200)
            handler.send_header('Content-Type', 'application/zip')
            handler.send_header('Content-Disposition', 'attachment; filename="' + download_name(report) + '"')
            handler.send_header('Content-Length', str(size))
            handler.send_header('Cache-Control', 'no-store')
            handler.send_header('X-Content-Type-Options', 'nosniff')
            handler.end_headers(); started = True
            while True:
                chunk = archive.read(1024**2)
                if not chunk:
                    break
                handler.wfile.write(chunk)
    except (BrokenPipeError, ConnectionResetError):
        pass
    except (ValueError, OSError, TypeError, RecursionError) as exc:
        if not started:
            reply(400, {'error': str(exc)})
    finally:
        if owned:
            handler.server.export_lock.release()
