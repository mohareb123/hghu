"""Small local-only workbench server. Uploads are discarded after analysis."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .analyzer import MAX_INPUT, analyze, tools, profile_limits

STATIC = Path(__file__).with_name("static")
ALLOWED = {".apk", ".aab", ".dex", ".zip", ".jar", ".smali", ".java", ".kt", ".proto",
           ".pb", ".desc", ".protoset", ".bin", ".so", ".xml", ".json", ".txt", ".xapk", ".apks", ".obb", ".dat", ".arsc"}


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, allow_decoders=False):
        super().__init__(address, Handler)
        self.allow_decoders = allow_decoders
        self.analysis_lock = threading.BoundedSemaphore(1)


class Handler(BaseHTTPRequestHandler):
    server_version = "ProtoHunter/" + __version__

    def setup(self):
        super().setup()
        self.connection.settimeout(60)

    def respond(self, status, payload, content_type="application/json; charset=utf-8"):
        if not isinstance(payload, bytes):
            payload = json.dumps(payload, ensure_ascii=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/status":
            self.respond(200, {"version": __version__, "tools": tools(), "allow_decoders": self.server.allow_decoders,
                               "max_upload_bytes": MAX_INPUT, "profiles": {p: profile_limits(p) for p in ("standard", "games")}})
            return
        names = {"/": "index.html", "/app.js": "app.js", "/style.css": "style.css", "/icon.svg": "icon.svg"}
        if path not in names:
            self.respond(404, {"error": "Not found"})
            return
        file = STATIC / names[path]
        types = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}
        self.respond(200, file.read_bytes(), types.get(file.suffix) or "application/octet-stream")

    def do_POST(self):
        request = urlsplit(self.path)
        if request.path not in {"/api/analyze", "/api/demo"}:
            self.respond(404, {"error": "Not found"})
            return
        # Same-origin checks + non-simple content type prevent cross-site upload requests.
        origin = self.headers.get("Origin")
        if (origin and urlsplit(origin).netloc != self.headers.get("Host")) or self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.respond(403, {"error": "Cross-origin requests are not allowed"})
            return
        if self.headers.get("Content-Type", "").split(";")[0] != "application/octet-stream":
            self.respond(415, {"error": "Use application/octet-stream"})
            return
        try:
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Chunked uploads are not supported")
            query = parse_qs(request.query)
            profile = query.get("profile", ["standard"])[0]
            limits = profile_limits(profile)
            length = int(self.headers.get("Content-Length", "-1"))
            if not 0 <= length <= limits["input"]:
                self.respond(413, {"error": f"Upload limit is {limits['input'] // 1024**2} MiB for this profile; Content-Length is required"})
                return
            query = parse_qs(request.query)
            mode = query.get("decode", ["none"])[0]
            if mode not in {"none", "auto", "jadx", "apktool", "both"}:
                raise ValueError("Unknown decoder")
            if mode != "none" and not self.server.allow_decoders:
                raise ValueError("External decoders are disabled. Start with --allow-decoders to enable them.")
            filename = query.get("name", ["input.apk"])[0].replace("\\", "/").rsplit("/", 1)[-1]
            if not filename or len(filename) > 200 or any(ord(c) < 32 for c in filename):
                raise ValueError("Invalid filename")
            suffix = Path(filename).suffix.lower()
            if request.path == "/api/analyze" and suffix not in ALLOWED:
                raise ValueError("Unsupported file extension")
            if not self.server.analysis_lock.acquire(blocking=False):
                self.respond(429, {"error": "Another analysis is running. Try again shortly."})
                return
            try:
                result = self.process_upload(request, suffix, length, filename, mode, profile)
            finally:
                self.server.analysis_lock.release()
            self.respond(200, result)
        except (ValueError, OSError) as exc:
            self.respond(400, {"error": str(exc)})
        except Exception:
            # No target contents or internal paths in unexpected-error responses.
            self.respond(500, {"error": "Analysis failed. Check the input format or use the CLI for diagnosis."})

    def process_upload(self, request, suffix, length, filename, mode, profile):
        with tempfile.TemporaryDirectory(prefix="protohunter-upload-") as tmp:
            target = Path(tmp, "input" + suffix)
            with target.open("wb") as stream:
                remaining = length
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Upload ended early")
                    stream.write(chunk)
                    remaining -= len(chunk)
            if request.path == "/api/demo":
                report = analyze(Path(__file__).with_name("demo.smali"))
                report["input"]["demo"] = True
            else:
                report = analyze(target, mode, display_name=filename, profile=profile)
            return report


def serve(host="127.0.0.1", port=8765, allow_decoders=False):
    with Server((host, port), allow_decoders) as server:
        print(f"ProtoHunter: http://{host}:{server.server_port} (Ctrl+C to stop)", flush=True)
        if host not in {"127.0.0.1", "localhost", "::1"}:
            print("Warning: no authentication. Use only on a trusted network / protected preview.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
