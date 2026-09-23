"""Bounded optional comparison of user-supplied texts; no filesystem paths/engines."""
from .botmatch import compare


def handle(handler):
    if handler.headers.get('Content-Type', '').split(';')[0] != 'application/json':
        handler.respond(415, {'error': 'Use application/json'}); return
    if not handler.server.export_lock.acquire(False):
        handler.respond(429, {'error': 'Another export/comparison is running'}); return
    status = 200
    try:
        if handler.headers.get('Transfer-Encoding'): raise ValueError('Chunked requests unsupported')
        body = handler.read_json(limit=32 * 1024**2)
        result = compare(body.get('protocol_report'), body.get('files'))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        status, result = 400, {'error': str(exc)}
    finally:
        handler.server.export_lock.release()
    handler.respond(status, result)
