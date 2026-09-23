"""Trusted-desktop-only API. No arbitrary server paths accepted for project import."""
import json
import os
import secrets
from .dialogs import choose_file


def authorized(handler):
    return handler.local_desktop() and secrets.compare_digest(
        handler.headers.get('X-ProtoHunter-Config-Token', ''), handler.server.config_token)


def handle(handler):
    if not authorized(handler):
        handler.respond(403, {'error': 'Workspaces are available only in the trusted loopback desktop interface'}); return
    if handler.headers.get('Content-Type', '').split(';')[0] != 'application/json':
        handler.respond(415, {'error': 'Use application/json'}); return
    owned = False
    try:
        if handler.headers.get('Transfer-Encoding'):
            raise ValueError('Chunked requests are not supported')
        body = handler.read_json(limit=8 * 1024**2)
        action = body.get('action'); project_id = body.get('project')
        store = handler.server.projects
        if not handler.server.analysis_lock.acquire(blocking=False):
            handler.respond(429, {'error': 'Another analysis/workspace operation is running'}); return
        owned = True
        if action in {'create', 'run'}:
            if action == 'create':
                selected = choose_file('input')
                if not selected:
                    handler.server.analysis_lock.release(); owned = False
                    handler.respond(200, {'cancelled': True}); return
                def task(**callbacks):
                    return store.create(selected, **callbacks)
            else:
                if not handler.server.allow_decoders:
                    raise ValueError('Enable --allow-decoders for workspace operations')
                operation = body.get('operation')
                options = body.get('options', {})
                if not isinstance(options, dict) or set(options) - {'binary', 'metadata', 'keystore', 'alias', 'store_pass', 'key_pass'}:
                    raise ValueError('Unsupported operation options')
                for key in ('keystore', 'alias', 'store_pass', 'key_pass'):
                    if key in options and not isinstance(options[key], str):
                        raise ValueError('Signing options must be strings')
                store.load(project_id)
                config = handler.server.tool_config
                def task(**callbacks):
                    return store.run(project_id, operation, body.get('unit', 'main'), config=config, **callbacks, **options)
            job = handler.server.start_job(None, 'Workspace: ' + action, {}, task=task)
            owned = False
            handler.respond(202, {'job_id': job.id}); return
        if action == 'list':
            result = {'projects': store.list()}
        elif action == 'get':
            result = store.load(project_id)
        elif action == 'report':
            data = store.load(project_id)
            run = next((r for r in reversed(data['runs']) if r['operation'] == 'inspect' and r['unit'] == body.get('unit') and r['status'] == 'completed' and (not body.get('run') or r['id'] == body['run'])), None)
            if not run:
                raise ValueError('Run inspection first')
            path = store.safe(project_id, run['path'] + '/report.json')
            if path.stat().st_size > 64 * 1024**2:
                raise ValueError('Report exceeds the 64 MiB viewer limit; open the project folder')
            result = json.loads(path.read_text(encoding='utf-8'))
        elif action == 'files':
            result = store.files(project_id)
        elif action == 'read':
            result = store.read(project_id, body.get('path', ''))
        elif action in {'save', 'diff'}:
            result = store.edit(project_id, body.get('path', ''), body.get('text'), body.get('sha256'), preview=action == 'diff')
        elif action == 'restore':
            result = store.restore(project_id, body.get('edit'), body.get('sha256'))
        elif action == 'search':
            result = store.search(project_id, body.get('query'))
        elif action == 'candidates':
            result = store.candidates(project_id)
        elif action == 'choose-keystore':
            result = {'path': choose_file('keystore')}
        elif action == 'open-folder':
            if os.name != 'nt':
                raise ValueError('Open-folder is Windows-only; use the CLI project directory on other systems')
            os.startfile(str(store.path(project_id)))
            result = {'opened': True}
        else:
            raise ValueError('Unknown workspace action')
        handler.server.analysis_lock.release(); owned = False
        handler.respond(200, result)
    except (OSError, ValueError, KeyError) as exc:
        if owned:
            handler.server.analysis_lock.release(); owned = False
        handler.respond(400, {'error': str(exc)})
    except Exception:
        if owned:
            handler.server.analysis_lock.release(); owned = False
        handler.respond(500, {'error': 'Workspace action failed; check the selected project and tool configuration'})
    finally:
        if owned:
            handler.server.analysis_lock.release()
