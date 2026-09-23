"""Optional, bounded source fingerprint comparison; never imports or executes bot code."""
from collections import defaultdict
from pathlib import Path
import os
import re
import zipfile
from .investigation import CATEGORIES, classify, addresses

MAX_FILES = 500
MAX_BYTES = 8 * 1024**2
MAX_FILE = 512 * 1024
EXTENSIONS = {'.py', '.js', '.ts', '.java', '.kt', '.cs', '.go', '.rs', '.c', '.h', '.cpp', '.proto', '.smali', '.json', '.txt', '.lua', '.yaml', '.ini'}
DECL = re.compile(r'(?m)^[ \t]*(?:(?:public|private|export|abstract|final|data|internal)\s+)*(?:class|message|struct)\s+(\w+)|^[ \t]*\.class[ \t]+[^\r\n;]{0,512}?\bL([^;\r\n]{1,512});')
FUNCTION = re.compile(r'\b(?:def|function|func|fn)\s+(\w+)|\b(\w+)\s*\([^;{}\n]{0,1024}\)\s*\{')
FIELD = re.compile(r'\b([A-Za-z_]\w*)\s*(?::[\w<>\[\].]+)?\s*=|\b(?:set|get|has)([A-Z]\w*)\s*\(')
OPCODE = re.compile(r'\b(?:opcode|packet_?id|command_?id)\s*(?::[\w.]+)?\s*=\s*(0x[\da-f]+|\d+)\b', re.I)


def normal(value): return re.sub(r'[^a-z0-9]', '', value.casefold())


def words(value):
    return set(re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', value).lower().replace('_', ' ').split()) - {'packet', 'req', 'resp', 'request', 'response', 'message', 'cs'}


def validate_files(files):
    if not isinstance(files, list) or not files or len(files) > MAX_FILES: raise ValueError('BOT MODE expects 1–500 source files')
    total = 0
    for file in files:
        if not isinstance(file, dict) or not isinstance(file.get('name'), str) or not isinstance(file.get('text'), str): raise ValueError('Invalid bot source entry')
        if len(file['name']) > 500 or Path(file['name']).suffix.lower() not in EXTENSIONS: raise ValueError('Unsupported bot source filename')
        size = len(file['text'].encode('utf-8')); total += size
        if size > MAX_FILE or total > MAX_BYTES: raise ValueError('Bot source limit: 512 KiB/file, 8 MiB total')
    return files


def read_project(path):
    path = Path(path); files = []; total = 0; omitted = 0
    def append(name, data):
        nonlocal total
        if len(files) >= MAX_FILES or len(data) > MAX_FILE or total + len(data) > MAX_BYTES: raise ValueError('Bot project exceeds 500 files / 512 KiB per file / 8 MiB total; choose a smaller source subset')
        text = data.decode('utf-8-sig')
        total += len(data); files.append({'name': name[:500], 'text': text})
    if path.is_symlink(): raise ValueError('Bot project symlinks are not followed')
    if path.is_file() and zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > 20000: raise ValueError('Too many ZIP entries')
            for info in infos:
                if info.is_dir(): continue
                if Path(info.filename).suffix.lower() not in EXTENSIONS: omitted += 1; continue
                if info.file_size > MAX_FILE or info.file_size > max(1, info.compress_size) * 250: raise ValueError('Bot ZIP member exceeds size/ratio limits')
                append(info.filename, archive.read(info))
    elif path.is_dir():
        visited = 0
        for root, dirs, names in os.walk(path, followlinks=False):
            visited += len(dirs) + len(names)
            if visited > 20000: raise ValueError('Bot directory inventory limit (20000)')
            dirs[:] = sorted(d for d in dirs if d not in {'.git', 'node_modules', '.venv', 'venv', 'dist', 'build', '__pycache__'} and not Path(root, d).is_symlink())
            for name in sorted(names):
                file = Path(root, name)
                if file.is_symlink() or file.suffix.lower() not in EXTENSIONS: omitted += 1; continue
                if file.stat().st_size > MAX_FILE: raise ValueError('Bot source file exceeds 512 KiB')
                append(file.relative_to(path).as_posix(), file.read_bytes())
    elif path.is_file():
        if path.stat().st_size > MAX_FILE: raise ValueError('Bot source file exceeds 512 KiB')
        with path.open('rb') as stream: append(path.name, stream.read(MAX_FILE + 1))
    else: raise ValueError('Bot project not found')
    return validate_files(files), omitted


def fingerprints(files):
    records = []
    for file in validate_files(files):
        text = file['text']; declarations = list(DECL.finditer(text))
        if not declarations: declarations = list(FUNCTION.finditer(text))
        segments = [(next(x for x in m.groups() if x), m.start(), declarations[i + 1].start() if i + 1 < len(declarations) else len(text)) for i, m in enumerate(declarations)] or [(Path(file['name']).stem, 0, len(text))]
        for name, start, end in segments:
            if len(name) > 512: raise ValueError('Bot symbol name exceeds 512 characters')
            body = text[start:end]
            records.append({'name': name, 'source': file['name'], 'line': text.count('\n', 0, start) + 1,
                'fields': sorted({normal(a or b) for a, b in FIELD.findall(body)})[:256],
                'functions': sorted({normal(a or b) for a, b in FUNCTION.findall(body)})[:256],
                'addresses': sorted(set(addresses(body)))[:100],
                'opcodes': sorted({str(int(n, 0) if n.lower().startswith('0x') else int(n)) for n in OPCODE.findall(body)})[:100]})
            if len(records) > 2000: raise ValueError('Bot symbol limit (2000); choose a smaller source subset')
    return records


def compare(protocol_report, files):
    if not isinstance(protocol_report, dict) or not protocol_report.get('meta', {}).get('enabled'): raise ValueError('Run protocol investigation first')
    files = validate_files(files)
    candidates = []
    for category in CATEGORIES:
        rows = protocol_report.get(category.lower(), [])
        if not isinstance(rows, list): raise ValueError('Invalid protocol report')
        candidates.extend(rows)
    if len(candidates) > 10000: raise ValueError('Candidate limit (10000)')
    prepared = []; inverted = defaultdict(set)
    for index, item in enumerate(candidates):
        if not isinstance(item, dict) or not isinstance(item.get('name'), str): raise ValueError('Invalid candidate')
        raw = item['name']
        name = (raw[1:-1] if raw.startswith('L') and raw.endswith(';') else raw).replace('$Builder', '').split('/')[-1].split('.')[-1].split('$')[-1]
        evidence = item.get('feature_evidence', {})
        fp = {'name': normal(name), 'words': words(name), 'type': item.get('type'),
              'fields': {normal(x) for x in item.get('fields', [])[:200]},
              'functions': {normal(x['reference'].split('->')[-1].split('(')[0]) for hits in evidence.values() for x in hits[:20] if isinstance(x, dict) and isinstance(x.get('reference'), str)},
              'addresses': {x['reference'] for x in evidence.get('address', [])[:20]},
              'opcodes': set(item.get('opcodes', []))}
        prepared.append(fp)
        for value in fp['words'] | fp['fields'] | fp['addresses'] | fp['opcodes'] | {fp['name']}:
            inverted[value].add(index)
    matches = []; missing = []; comparisons = 0
    for old in fingerprints(files):
        indexes = set()
        for value in words(old['name']) | set(old['fields']) | set(old['addresses']) | set(old['opcodes']) | {normal(old['name'])}: indexes.update(inverted.get(value, ()))
        ranked = []
        evaluated = 0
        for index in sorted(indexes)[:2000]:
            if comparisons >= 200000: break
            comparisons += 1; evaluated += 1
            new = prepared[index]; reasons = []; score = 0
            exact = normal(old['name']) == new['name']
            if exact: score += .45; reasons.append({'feature': 'exact_name', 'weight': .45})
            else:
                shared = words(old['name']) & new['words']
                if shared: score += .12; reasons.append({'feature': 'name_tokens', 'shared': sorted(shared), 'weight': .12})
            for key, weight in [('fields', .25), ('functions', .10), ('addresses', .12), ('opcodes', .08)]:
                left = set(old[key]); shared = left & new[key]
                if shared:
                    points = weight * len(shared) / len(left | new[key]); score += points
                    reasons.append({'feature': key, 'shared': sorted(shared), 'weight': round(points, 4)})
            if score:
                ranked.append({'new_id': candidates[index]['id'], 'new_name': candidates[index]['name'], 'match': round(score, 4), 'reasons': reasons})
        ranked.sort(key=lambda row: (-row['match'], row['new_name']))
        accepted = bool(ranked and ranked[0]['match'] >= .45)
        truncated = evaluated < len(indexes)
        status = 'UNRESOLVED' if truncated and not accepted else 'AMBIGUOUS' if accepted and len(ranked) > 1 and ranked[0]['match'] - ranked[1]['match'] < .08 else 'CANDIDATE' if accepted else 'MISSING'
        row = {**old, 'status': status, 'candidates': ranked[:3], 'search_truncated': truncated,
               'compatibility_proven': False, 'note': 'MISSING = no candidate above threshold in analyzed evidence, not proof of removal. Match is similarity, not probability.'}
        matches.append(row)
        if status == 'MISSING': missing.append(row)
    return {'bot_matches': matches, 'missing_from_new_version': missing,
            'bot_comparison': {'files': len(files), 'symbols': len(matches), 'threshold': .45, 'ambiguous_margin': .08,
                               'comparison_budget': 200000, 'comparisons': comparisons, 'name_only_maximum': .45, 'note': 'No code execution. Lexical fingerprints only; human verification required. No compatibility probability is estimated.'}}
