"""In-memory progress for one active analysis; finished reports expire after one hour."""
import secrets
import threading
import time


class Job:
    def __init__(self, name):
        self.id = secrets.token_urlsafe(24)
        self.name = name
        self.started = time.monotonic()
        self.finished = None
        self.status = 'running'
        self.progress = {'stage': 'starting', 'file': name, 'files_scanned': 0}
        self.report = None
        self.error = None
        self.cancel = threading.Event()
        self.lock = threading.Lock()
        self.thread = None

    def update(self, progress):
        with self.lock:
            self.progress = dict(progress)

    def snapshot(self):
        with self.lock:
            return {'id': self.id, 'name': self.name, 'status': self.status, 'progress': dict(self.progress),
                    'elapsed_seconds': round((self.finished or time.monotonic()) - self.started, 1), 'error': self.error}

    def finish(self, status, report=None, error=None):
        with self.lock:
            self.status, self.report, self.error = status, report, error
            self.finished = time.monotonic()

    def request_cancel(self):
        with self.lock:
            if self.finished is None:
                self.cancel.set()
                self.status = 'cancelling'
