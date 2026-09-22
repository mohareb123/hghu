"""Portable bundle metadata and opt-in integrity verification (not a signature)."""
import hashlib
import json
from pathlib import Path, PurePosixPath


def metadata(base):
    path = Path(base) / 'bundle-manifest.json'
    try:
        if path.stat().st_size > 2 * 1024**2:
            return {}
        data = json.loads(path.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) and data.get('schema') == 1 and isinstance(data.get('files'), dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def paths(base):
    base = Path(base)
    return {'apktool_jar': base / 'tools/apktool.jar', 'java': base / 'tools/java/bin/java.exe',
            'jadx': base / 'tools/jadx', 'il2cpp': base / 'tools/il2cpp/Il2CppDumper.exe'}


def verify(base):
    base = Path(base).resolve()
    manifest = metadata(base)
    if not manifest:
        return {'ok': False, 'checked': 0, 'errors': ['No valid bundle-manifest.json found']}
    errors = []; checked = 0
    for relative, expected in manifest['files'].items():
        parsed = PurePosixPath(relative)
        path = base / relative
        if parsed.is_absolute() or '..' in parsed.parts or '\\' in relative or ':' in relative or not path.resolve().is_relative_to(base):
            errors.append('Unsafe manifest path: ' + relative); continue
        if not path.is_file() or path.is_symlink():
            errors.append('Missing file: ' + relative); continue
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024**2), b''):
                digest.update(chunk)
        checked += 1
        if digest.hexdigest() != expected:
            errors.append('Changed file: ' + relative)
    return {'ok': not errors and checked > 0, 'checked': checked, 'errors': errors,
            'note': 'Local checksums detect changes; they are not a publisher signature.'}
