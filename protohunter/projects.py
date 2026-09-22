"""Persistent, local-only workspaces for external decompilers and reversible text edits.

Not a sandbox: tools are trusted executables. Never execute generated scripts or APKs.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import time
import uuid
import zipfile

from .analyzer import analyze
from .runtime import AnalysisCancelled, stop_decoder
from .tooling import ToolConfig, settings_path

MAX_INPUT = 2 * 1024**3
MAX_EXPANDED = 4 * 1024**3
MAX_TEXT = 1024**2
TEXT = {'.smali', '.xml', '.yml', '.yaml', '.json', '.txt', '.java', '.kt', '.cs', '.h', '.c', '.cpp',
        '.proto', '.properties', '.ini', '.cfg', '.html', '.js', '.css', '.log', '.py', '.md'}


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, data):
    temp = path.with_name('.' + uuid.uuid4().hex + '.tmp')
    try:
        temp.write_text(json.dumps(data, ensure_ascii=True, indent=2), encoding='utf-8')
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked(cancel):
    if cancel and cancel():
        raise AnalysisCancelled('Operation cancelled; partial output remains in its run folder')


def copy_stream(source, destination, limit, progress=None, cancel=None):
    digest = hashlib.sha256(); size = 0
    with destination.open('xb') as out:
        while True:
            checked(cancel)
            chunk = source.read(min(1024**2, limit - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ValueError('Project input/expanded-byte budget exceeded')
            out.write(chunk); digest.update(chunk)
            if progress:
                progress({'stage': 'importing', 'file': destination.name, 'completed_bytes': size})
    return size, digest.hexdigest()


class ProjectStore:
    def __init__(self, root=None):
        self.root = Path(root) if root else settings_path().parent / 'Projects'

    def path(self, project_id):
        if not isinstance(project_id, str) or not re.fullmatch('[0-9a-f]{32}', project_id):
            raise ValueError('Invalid project ID')
        root = self.root.resolve()
        path = root / project_id
        if not path.is_dir() or path.is_symlink() or path.resolve().parent != root:
            raise ValueError('Project not found')
        return path

    def safe(self, project_id, relative):
        if not isinstance(relative, str) or not relative or any(c in relative for c in ('\\', ':', '\x00')):
            raise ValueError('Invalid project-relative path')
        parts = PurePosixPath(relative)
        if parts.is_absolute() or any(p in ('.', '..') for p in parts.parts):
            raise ValueError('Path must stay inside the project')
        root = self.path(project_id)
        target = root.joinpath(*parts.parts)
        current = root
        for part in parts.parts:
            current = current / part
            if current.is_symlink() or (hasattr(current, 'is_junction') and current.is_junction()):
                raise ValueError('Project symlinks/junctions are not followed')
        if not target.resolve().is_relative_to(root.resolve()):
            raise ValueError('Path escapes the project')
        return target

    def load(self, project_id):
        path = self.safe(project_id, 'project.json')
        if path.stat().st_size > 4 * MAX_TEXT:
            raise ValueError('Invalid project manifest size')
        result = json.loads(path.read_text(encoding='utf-8'))
        if result.get('id') != project_id or result.get('schema') != 1:
            raise ValueError('Unsupported project manifest')
        return result

    def save(self, data):
        atomic_json(self.safe(data['id'], 'project.json'), data)

    def list(self):
        if not self.root.exists():
            return []
        result = []
        for p in sorted(self.root.iterdir(), key=lambda p: p.name):
            if len(result) >= 500:
                break
            if re.fullmatch('[0-9a-f]{32}', p.name):
                try:
                    data = self.load(p.name)
                    result.append({k: data[k] for k in ('id', 'name', 'created', 'input', 'units')})
                except (OSError, ValueError, KeyError):
                    continue
        return sorted(result, key=lambda item: item['created'], reverse=True)

    @contextmanager
    def locked(self, project_id):
        # OS lock releases on process exit; also coordinates CLI and desktop instances.
        with self.safe(project_id, '.lock').open('a+b') as stream:
            stream.seek(0)
            if not stream.read(1):
                stream.write(b'0'); stream.flush()
            stream.seek(0)
            try:
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise ValueError('Project is busy in another operation') from exc
            try:
                yield
            finally:
                stream.seek(0)
                if os.name == 'nt':
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(stream, fcntl.LOCK_UN)

    def create(self, source, progress=None, cancel=None):
        source = Path(source)
        suffix = source.suffix.lower()
        if suffix not in {'.apk', '.xapk', '.apks', '.zip'} or not source.is_file():
            raise ValueError('Project input must be APK, XAPK, APKS or ZIP containing APK members')
        if source.stat().st_size > MAX_INPUT:
            raise ValueError('Project input limit is 2 GiB')
        self.root.mkdir(parents=True, exist_ok=True)
        project_id = uuid.uuid4().hex
        root = self.root / project_id
        root.mkdir()
        try:
            for name in ('input', 'packages', 'runs', 'history'):
                (root / name).mkdir()
            original = root / 'input' / ('source' + suffix)
            with source.open('rb') as stream:
                size, digest = copy_stream(stream, original, MAX_INPUT, progress, cancel)
            if not zipfile.is_zipfile(original):
                raise ValueError('Input is not a valid ZIP-based Android package')
            units = []
            if suffix == '.apk':
                units.append({'id': 'main', 'name': source.name, 'path': 'input/source.apk', 'sha256': digest})
            else:
                expanded = 0
                with zipfile.ZipFile(original) as archive:
                    if len(archive.infolist()) > 40000:
                        raise ValueError('Bundle exceeds 40,000 entries')
                    for info in archive.infolist():
                        checked(cancel)
                        if info.is_dir() or not info.filename.lower().endswith('.apk'):
                            continue
                        if len(units) >= 32:
                            raise ValueError('Bundle exceeds 32 APK units; import a smaller bundle')
                        if len(info.filename) > 1024:
                            raise ValueError('APK member name exceeds the project manifest limit')
                        if info.flag_bits & 1 or info.file_size > MAX_INPUT or info.file_size / max(1, info.compress_size) > 250:
                            raise ValueError('Encrypted, oversized or high-ratio APK member')
                        unit = f'unit-{len(units) + 1:03d}'
                        path = root / 'packages' / (unit + '.apk')
                        with archive.open(info) as stream:
                            n, member_hash = copy_stream(stream, path, min(MAX_INPUT, MAX_EXPANDED - expanded), progress, cancel)
                        expanded += n
                        if not zipfile.is_zipfile(path):
                            raise ValueError('Invalid APK member: ' + info.filename[:200])
                        units.append({'id': unit, 'name': info.filename, 'path': 'packages/' + path.name, 'sha256': member_hash})
                if not units:
                    raise ValueError('No APK members found in this bundle')
            data = {'schema': 1, 'id': project_id, 'name': source.name, 'created': now(),
                    'input': {'size': size, 'sha256': digest, 'path': 'input/' + original.name},
                    'units': units, 'decoded': {}, 'runs': [], 'changes': []}
            self.save(data)
            return data
        except BaseException:
            shutil.rmtree(root)
            raise

    def unit(self, data, unit_id):
        found = next((x for x in data['units'] if x['id'] == unit_id), None)
        if not found:
            raise ValueError('Choose an APK unit from this project')
        return found

    def candidates(self, project_id):
        data = self.load(project_id); result = {'binaries': [], 'metadata': []}; entries = 0
        for unit in data['units']:
            with zipfile.ZipFile(self.safe(project_id, unit['path'])) as archive:
                entries += len(archive.infolist())
                if entries > 40000:
                    raise ValueError('Unity discovery exceeds 40,000 entries')
                for info in archive.infolist():
                    leaf = PurePosixPath(info.filename).name.lower()
                    kind = 'binaries' if leaf == 'libil2cpp.so' else 'metadata' if leaf == 'global-metadata.dat' else None
                    if kind and not info.is_dir():
                        result[kind].append({'unit': unit['id'], 'member': info.filename, 'size': info.file_size})
        return result

    def extract_unity(self, project_id, candidate, destination, cancel):
        if not isinstance(candidate, dict):
            raise ValueError('Select a Unity binary and metadata pair')
        unit = self.unit(self.load(project_id), candidate.get('unit'))
        with zipfile.ZipFile(self.safe(project_id, unit['path'])) as archive:
            info = archive.getinfo(candidate.get('member', ''))
            if info.file_size > 512 * MAX_TEXT or info.flag_bits & 1 or info.file_size / max(1, info.compress_size) > 250:
                raise ValueError('Unity member exceeds safe extraction limits')
            with archive.open(info) as stream:
                copy_stream(stream, destination, 512 * MAX_TEXT, cancel=cancel)

    def _execute(self, command, root, run, progress, cancel, timeout, env=None):
        log_path = root / run['path'] / (f'step-{len(run["commands"]):02d}.log')
        run['commands'].append(command)
        proc = None
        try:
            with log_path.open('wb') as log:
                proc = subprocess.Popen(command, cwd=root / run['path'], stdin=subprocess.DEVNULL,
                    stdout=log, stderr=log, env=env, start_new_session=os.name != 'nt',
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
                deadline = time.monotonic() + timeout
                while proc.poll() is None:
                    checked(cancel)
                    if time.monotonic() > deadline:
                        raise ValueError(f'Tool timed out after {timeout} seconds; inspect the run log')
                    if log_path.stat().st_size > 16 * MAX_TEXT:
                        raise ValueError('Tool log exceeded 16 MiB; stopped')
                    if progress:
                        with log_path.open('rb') as reader:
                            reader.seek(max(0, log_path.stat().st_size - 4000))
                            tail = reader.read(4000).decode('utf-8', 'replace')
                        progress({'stage': run['operation'], 'file': run['unit'], 'log': tail})
                    try:
                        proc.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        pass
                if proc.returncode:
                    raise ValueError(f'Tool exited with code {proc.returncode}; inspect {log_path.name}. Partial outputs are retained.')
        finally:
            if proc and proc.poll() is None:
                stop_decoder(proc)

    def run(self, project_id, operation, unit_id='main', config=None, progress=None, cancel=None, **options):
        if operation not in {'jadx', 'apktool', 'il2cpp', 'inspect', 'build', 'sign'}:
            raise ValueError('Unknown workspace operation')
        config = config or ToolConfig.load()
        with self.locked(project_id):
            data = self.load(project_id); unit = self.unit(data, unit_id); root = self.path(project_id)
            if len(data['runs']) >= 200:
                raise ValueError('This project has reached 200 runs; create a new project')
            run_id = uuid.uuid4().hex
            run = {'id': run_id, 'operation': operation, 'unit': unit_id, 'status': 'running', 'started': now(),
                   'path': 'runs/' + run_id, 'commands': []}
            folder = root / run['path']; folder.mkdir()
            data['runs'].append(run); self.save(data)
            pending_decode = None
            def revision():
                prefix = data['decoded'].get(unit_id, '')
                return {'decoded': prefix, 'edits': [c['id'] for c in data['changes'] if c['path'].startswith(prefix + '/')] }
            def execute(command, env=None):
                self._execute(command, root, run, progress, cancel, 900, env)
            def command(tool):
                value = config.command(tool)
                if not value:
                    raise ValueError(f'{tool} is not configured; set its trusted local path first')
                return value
            try:
                checked(cancel)
                input_path = self.safe(project_id, unit['path'])
                if operation in {'jadx', 'apktool'}:
                    output = folder / operation
                    args = ['--no-res', '-d', str(output), str(input_path)] if operation == 'jadx' else ['d', '-f', '-p', str(folder / 'framework'), '-o', str(output), str(input_path)]
                    execute(command(operation) + args)
                    if not output.is_dir() or not any(output.iterdir()):
                        raise ValueError('Tool returned no output files')
                    if operation == 'apktool':
                        if not (output / 'apktool.yml').is_file():
                            raise ValueError('Apktool output is missing apktool.yml; not marked buildable')
                        pending_decode = run['path'] + '/apktool'
                elif operation == 'il2cpp':
                    available = self.candidates(project_id)
                    binary, metadata = options.get('binary'), options.get('metadata')
                    for candidate, key in ((binary, 'binaries'), (metadata, 'metadata')):
                        if not isinstance(candidate, dict) or not any(x['unit'] == candidate.get('unit') and x['member'] == candidate.get('member') for x in available[key]):
                            raise ValueError('Choose existing Unity members; cross-split pairing is explicit')
                    self.extract_unity(project_id, binary, folder / 'libil2cpp.so', cancel)
                    self.extract_unity(project_id, metadata, folder / 'global-metadata.dat', cancel)
                    output = folder / 'il2cpp'; output.mkdir()
                    run['pair'] = {'binary': binary, 'metadata': metadata}
                    execute(command('il2cpp') + [str(folder / 'libil2cpp.so'), str(folder / 'global-metadata.dat'), str(output)])
                    known = [output / name for name in ('dump.cs', 'script.json', 'stringliteral.json', 'il2cpp.h')]
                    known.extend((output / 'DummyDll').glob('*.dll'))
                    if not any(p.is_file() and p.stat().st_size for p in known):
                        raise ValueError('Il2CppDumper produced no recognized output; check compatibility, RequireAnyKey=false and the log')
                    run['note'] = 'DummyDll/type layouts are not original C# method bodies. Generated scripts are never executed.'
                elif operation == 'inspect':
                    source = self.safe(project_id, data['decoded'][unit_id]) if unit_id in data['decoded'] else input_path
                    views = []
                    for tool in ('jadx', 'il2cpp'):
                        previous = next((r for r in reversed(data['runs'][:-1]) if r['operation'] == tool and r['unit'] == unit_id and r['status'] == 'completed'), None)
                        if previous:
                            views.append((tool, self.safe(project_id, previous['path'] + '/' + tool)))
                    report = analyze(source, display_name=data['name'] + ' / ' + unit['id'], profile='games', scan_mode='deep', progress=progress, cancel=cancel, extra_inputs=views)
                    report['warnings'].append('JADX/IL2CPP views derive from the imported original; Apktool sources may contain edits. These are distinct static views, not a rebuilt runtime trace.')
                    atomic_json(folder / 'report.json', report)
                elif operation == 'build':
                    if unit_id not in data['decoded']:
                        raise ValueError('Decode this APK unit using Apktool before building')
                    decoded = self.safe(project_id, data['decoded'][unit_id])
                    framework = self.safe(project_id, data['decoded'][unit_id].rsplit('/', 1)[0] + '/framework')
                    run['source_revision'] = revision()
                    output = folder / 'unsigned.apk'
                    execute(command('apktool') + ['b', str(decoded), '-p', str(framework), '-o', str(output)])
                    if not output.is_file() or not zipfile.is_zipfile(output):
                        raise ValueError('Build did not produce a valid APK/ZIP')
                    run['artifact'] = run['path'] + '/unsigned.apk'
                    run['note'] = 'Unsigned single APK unit; not an install-ready merged XAPK. Signing is required.'
                else:
                    previous = next((r for r in reversed(data['runs'][:-1]) if r['operation'] == 'build' and r['unit'] == unit_id and r['status'] == 'completed'), None)
                    if not previous:
                        raise ValueError('Build this unit before signing')
                    if previous.get('source_revision') != revision():
                        raise ValueError('Project edits changed since the last build; rebuild before signing')
                    key = Path(options.get('keystore', '')).expanduser()
                    if not key.is_file() or not options.get('alias') or not options.get('store_pass'):
                        raise ValueError('Signing needs your keystore, alias and password; passwords are never saved')
                    aligned = folder / 'aligned.apk'; signed = folder / 'signed.apk'
                    execute(command('zipalign') + ['-P', '16', '-f', '4', str(self.safe(project_id, previous['artifact'])), str(aligned)])
                    environment = dict(os.environ, PROTOHUNTER_KS_PASS=options['store_pass'],
                                       PROTOHUNTER_KEY_PASS=options.get('key_pass') or options['store_pass'])
                    try:
                        execute(command('apksigner') + ['sign', '--ks', str(key.resolve()), '--ks-key-alias', options['alias'],
                            '--ks-pass', 'env:PROTOHUNTER_KS_PASS', '--key-pass', 'env:PROTOHUNTER_KEY_PASS',
                            '--out', str(signed), str(aligned)], env=environment)
                    finally:
                        environment.clear()
                    execute(command('apksigner') + ['verify', '--verbose', '--print-certs', str(signed)])
                    execute(command('zipalign') + ['-c', '-P', '16', '4', str(signed)])
                    if not signed.is_file() or not zipfile.is_zipfile(signed):
                        raise ValueError('No valid signed APK was produced')
                    run['artifact'] = run['path'] + '/signed.apk'
                    run['note'] = 'Verified by configured apksigner/zipalign; signed with your key, not the original publisher key. Splits must use the same key.'
                checked(cancel)
                if pending_decode:
                    data['decoded'][unit_id] = pending_decode
                run['status'] = 'completed'
            except BaseException as exc:
                run['status'] = 'cancelled' if isinstance(exc, AnalysisCancelled) else 'failed'
                run['error'] = str(exc)[:2000]
                raise
            finally:
                run['finished'] = now(); self.save(data)
            return data

    def editable(self, data, relative):
        return any(relative.startswith(prefix + '/') for prefix in data['decoded'].values()) and Path(relative).suffix.lower() in TEXT - {'.py', '.log'}

    def read(self, project_id, relative):
        data = self.load(project_id)
        if not isinstance(relative, str) or not relative.startswith('runs/'):
            raise ValueError('Only generated run files are exposed in the viewer')
        path = self.safe(project_id, relative)
        if not path.is_file():
            raise ValueError('Not a file')
        size = path.stat().st_size
        if path.suffix.lower() not in TEXT:
            return {'path': relative, 'size': size, 'editable': False, 'binary': True, 'text': '', 'sha256': None}
        with path.open('rb') as stream:
            content = stream.read(MAX_TEXT)
        try:
            text = content.decode('utf-8'); valid = b'\x00' not in content
        except UnicodeError:
            text = content.decode('utf-8', 'replace'); valid = False
        return {'path': relative, 'text': text, 'size': size, 'truncated': size > MAX_TEXT,
                'editable': size <= MAX_TEXT and valid and self.editable(data, relative) and path.stat().st_nlink == 1,
                'sha256': sha(content) if size <= MAX_TEXT else None}

    def files(self, project_id):
        data = self.load(project_id); base = self.safe(project_id, 'runs'); result = []
        for root, directories, names in os.walk(base, followlinks=False):
            directories[:] = sorted(d for d in directories if not Path(root, d).is_symlink() and not (hasattr(Path(root, d), 'is_junction') and Path(root, d).is_junction()))
            for name in sorted(names):
                if len(result) >= 20000:
                    return {'files': result, 'truncated': True}
                path = Path(root, name); relative = path.relative_to(self.path(project_id)).as_posix()
                try:
                    safe = self.safe(project_id, relative)
                    if safe.is_file():
                        result.append({'path': relative, 'size': safe.stat().st_size, 'editable': self.editable(data, relative)})
                except ValueError:
                    continue
        return {'files': result, 'truncated': False}

    def edit(self, project_id, relative, content, expected, preview=False):
        if not isinstance(content, str) or len(content.encode('utf-8')) > MAX_TEXT or '\x00' in content:
            raise ValueError('Editor accepts UTF-8 text up to 1 MiB without NUL characters')
        with self.locked(project_id):
            current = self.read(project_id, relative)
            if not current['editable']:
                raise ValueError('Only current Apktool text outputs are editable; JADX/IL2CPP are read-only')
            if current['sha256'] != expected:
                raise ValueError('File changed since opening it. Reload before saving; no data overwritten.')
            if '\r\n' in current['text'] and '\n' not in current['text'].replace('\r\n', '') and '\r' not in content:
                content = content.replace('\n', '\r\n')
            delta = ''.join(difflib.unified_diff(current['text'].splitlines(True), content.splitlines(True), fromfile='before', tofile='after'))
            if preview:
                return {'diff': delta[:200000], 'truncated': len(delta) > 200000}
            data = self.load(project_id)
            if len(data['changes']) >= 1000:
                raise ValueError('Project edit-history limit reached (1000)')
            target = self.safe(project_id, relative)
            edit_id = uuid.uuid4().hex; backup = self.safe(project_id, 'history/' + edit_id + '.bak')
            shutil.copyfile(target, backup)
            temp = target.with_name('.' + edit_id + '.tmp')
            try:
                temp.write_bytes(content.encode('utf-8')); temp.replace(target)
            finally:
                temp.unlink(missing_ok=True)
            data['changes'].append({'id': edit_id, 'path': relative, 'backup': backup.relative_to(self.path(project_id)).as_posix(),
                                    'before': expected, 'after': sha(content.encode('utf-8')), 'time': now()})
            self.save(data)
            return self.read(project_id, relative)

    def restore(self, project_id, edit_id, expected):
        data = self.load(project_id)
        entry = next((c for c in data['changes'] if c['id'] == edit_id), None)
        if not entry:
            raise ValueError('Edit backup not found')
        path = self.safe(project_id, entry['backup'])
        if path.stat().st_size > MAX_TEXT:
            raise ValueError('Invalid backup size')
        # A new history entry is created; optimistic hash checking prevents stale restores.
        return self.edit(project_id, entry['path'], path.read_bytes().decode('utf-8'), expected)

    def search(self, project_id, query):
        if not isinstance(query, str) or not 2 <= len(query) <= 200:
            raise ValueError('Search accepts a literal string of 2–200 characters')
        listing = self.files(project_id); hits = []; scanned = 0; consumed = 0; skipped = 0
        for entry in listing['files']:
            if Path(entry['path']).suffix.lower() not in TEXT:
                continue
            if entry['size'] > MAX_TEXT:
                skipped += 1; continue
            if scanned >= 5000 or consumed + entry['size'] > 64 * MAX_TEXT or len(hits) >= 300:
                return {'hits': hits, 'scanned': scanned, 'skipped': skipped, 'truncated': True}
            file = self.read(project_id, entry['path']); scanned += 1; consumed += entry['size']
            for number, line in enumerate(file['text'].splitlines(), 1):
                if query.casefold() in line.casefold():
                    hits.append({'path': entry['path'], 'line': number, 'text': line[:500]})
                    if len(hits) >= 300:
                        break
        return {'hits': hits, 'scanned': scanned, 'skipped': skipped, 'truncated': listing['truncated'] or skipped > 0 or len(hits) >= 300}
