"""Lossless section exports from an existing report; never re-analyzes or executes input."""
import io
import json
from pathlib import Path
import re
import tempfile
import zipfile

from .runtime import AnalysisCancelled

# Stable filenames are an export contract, independent of localized UI labels.
SECTIONS = {
    'protocol_report': ('protocol_report', 'تحقيق البروتوكولات / Protocol investigation'),
    'dependency_graph': ('dependency_graph', 'مخطط الاعتماد / Dependency graph'),
    'servers': ('server', 'السيرفرات / Server evidence groups'),
    'endpoints': ('endpoint', 'الروابط والعناوين / Endpoints'),
    'protocols': ('protocol', 'البروتوكولات / Protocols'),
    'protobuf': ('protobuf', 'Protobuf / gRPC'),
    'smali': ('smali', 'Smali'),
    'native': ('native', 'Native / Unity / IL2CPP'),
    'bundles': ('bundle', 'الحزم وSplit APK / Bundles'),
    'sources': ('source', 'ملفات المصدر / Source previews'),
    'research': ('research', 'أدلة البحث / Research'),
    'flow': ('flow', 'مراجع الاستدعاء / Call references'),
    'coverage': ('coverage', 'سجل التغطية / Coverage'),
    'files': ('files', 'الملفات المفحوصة / Scanned files'),
    'summary': ('summary', 'ملخص الفحص / Summary'),
    'input': ('input', 'بيانات المدخل / Input provenance'),
    'limits': ('limits', 'حدود الفحص / Budgets'),
    'coverage_summary': ('coverage_summary', 'ملخص التغطية / Coverage summary'),
    'research_plan': ('research_plan', 'خطة البحث / Research plan'),
    'warnings': ('warnings', 'تحذيرات / Warnings'),
    'limitations': ('limitations', 'قيود الاستنتاج / Limitations'),
}
STAGES = ('login', 'session', 'transport', 'messages', 'security', 'serialization', 'discovery')
NOTE = ('نتائج ثابتة ضمن حدود التقرير؛ القسم الفارغ لا يثبت غياب البيانات. '
        'راجع warnings وlimitations وcoverage. ملفات المصدر هنا هي المحتويات/المعاينات '
        'المحفوظة في التقرير، وليست ضمانًا لاسترجاع كل المصدر.\n'
        'Static evidence only. Empty means not observed in this report, not proven absent.\n'
        'Exports may contain sensitive endpoints, tokens or literals: review before sharing.')


def check(cancel):
    if cancel and cancel():
        raise AnalysisCancelled('Section export cancelled')


def sections(report):
    if not isinstance(report, dict) or not isinstance(report.get('input'), dict) or not isinstance(report.get('summary'), dict):
        raise ValueError('Expected an analysis report with input and summary objects')
    if len(report) > 128:
        raise ValueError('Too many report sections (maximum 128)')
    result = []
    for key, (stem, title) in SECTIONS.items():
        default = {} if key in {'input', 'summary', 'limits', 'coverage_summary', 'research_plan'} else []
        result.append((stem, key, title, report.get(key, default), key in report))
    result.append(('metadata', 'metadata', 'Report metadata',
                   {k: report[k] for k in ('version', 'generated_at') if k in report}, True))
    # Preserve future/custom top-level fields without letting report keys name disk paths.
    for number, key in enumerate(sorted(set(report) - set(SECTIONS) - {'version', 'generated_at'}), 1):
        result.append((f'extra/field-{number:03}', key, str(key), report[key], True))
    research = report.get('research', [])
    if isinstance(research, list):
        for stage in STAGES:
            result.append(('research_stages/' + stage, 'research.' + stage, stage,
                           [r for r in research if isinstance(r, dict) and r.get('stage') == stage], 'research' in report))
    return result


def write_json(stream, value, cancel=None):
    encoder = json.JSONEncoder(ensure_ascii=False, indent=2, allow_nan=False)
    for number, chunk in enumerate(encoder.iterencode(value)):
        if number % 256 == 0:
            check(cancel)
        stream.write(chunk)
    stream.write('\n')


def write_text(stream, value, title, report, present, cancel):
    stream.write(f'ProtoHunter — {title}\nInput: {report["input"].get("name", "")}\n'
                 f'Generated: {report.get("generated_at", "")}\nSource section present: {present}\n')
    if isinstance(value, list):
        stream.write(f'Records: {len(value)}\n')
    stream.write(NOTE + '\n\n')
    if value == [] or value == {}:
        stream.write('لا توجد سجلات في هذا القسم من التقرير / No records in this section.\n')
        return
    rows = value if isinstance(value, list) else [value]
    for number, row in enumerate(rows, 1):
        check(cancel)
        stream.write(f'=== {number} ===\n')
        if isinstance(row, dict):
            for key, item in row.items():
                stream.write(str(key) + ':\n')
                if isinstance(item, str):
                    stream.write(item + '\n')
                else:
                    write_json(stream, item, cancel)
        elif isinstance(row, str):
            stream.write(row + '\n')
        else:
            write_json(stream, row, cancel)
        stream.write('\n')


def write_all(report, open_text, cancel=None, progress=None):
    entries = sections(report)
    index = {'format': 'protohunter-sections-v1', 'input': report['input'],
             'report_version': report.get('version'), 'generated_at': report.get('generated_at'),
             'scope': 'Complete supplied report, independent of UI filters; original extraction limits remain.',
             'sections': []}
    for stem, key, title, value, present in entries:
        check(cancel)
        if progress:
            progress({'stage': 'exporting', 'file': stem, 'sections_written': len(index['sections']), 'sections_total': len(entries)})
        for extension in ('json', 'txt'):
            with open_text(stem + '.' + extension) as stream:
                if extension == 'json':
                    write_json(stream, value, cancel)
                else:
                    write_text(stream, value, title, report, present, cancel)
        index['sections'].append({'key': key, 'title': title, 'json': stem + '.json', 'txt': stem + '.txt',
                                  'kind': 'derived' if stem.startswith('research_stages/') else 'metadata' if stem == 'metadata' else 'original',
                                  'source_fields': ['research'] if stem.startswith('research_stages/') else [k for k in ('version', 'generated_at') if k in report] if stem == 'metadata' else [key] if present else [],
                                  'present_in_report': present, 'records': len(value) if isinstance(value, list) else None})
    with open_text('index.json') as stream:
        write_json(stream, index, cancel)
    with open_text('README.txt') as stream:
        stream.write('ProtoHunter — organized TXT + JSON exports\n\n' + NOTE + '\n\n'
                     'server = grouped host evidence; endpoint = individual URLs/IPs/routes.\n'
                     'protocol = protocol evidence, not reconstructed protocol implementations.\n'
                     'research_stages = filtered copies of research, not additional findings.\n'
                     'index.json maps every original report field to its exported filename.\n'
                     'TXT and JSON use UTF-8. Empty sections are still included.\n'
                     'JADX/Apktool/Il2CppDumper raw outputs remain in their original project run folders.\n')
    check(cancel)
    return index


def export_directory(report, destination, cancel=None, progress=None):
    """Create a new directory transactionally; never overwrite previous exports."""
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('Section output directory already exists; choose a new directory')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.protohunter-sections-', dir=destination.parent) as temp:
        staging = Path(temp) / 'sections'; staging.mkdir()
        def open_text(relative):
            path = staging / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            return path.open('w', encoding='utf-8', errors='backslashreplace', newline='\n')
        index = write_all(report, open_text, cancel, progress)
        if destination.exists() or destination.is_symlink():
            raise ValueError('Section output directory was created by another operation')
        staging.rename(destination)
    return index


def export_zip(report, stream, cancel=None):
    # ZIP CRC checks, fixed entry paths, streaming encoding; no huge in-memory ZIP copy.
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as archive:
        def open_text(relative):
            return io.TextIOWrapper(archive.open(relative, 'w', force_zip64=True), encoding='utf-8',
                                    errors='backslashreplace', newline='\n')
        return write_all(report, open_text, cancel)


def download_name(report):
    name = re.sub(r'[^a-zA-Z0-9._-]', '_', str(report['input'].get('name', 'analysis')))[:80].strip('.') or 'analysis'
    return name + '.sections.zip'
