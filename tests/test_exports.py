import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout, redirect_stderr

from protohunter.analyzer import analyze
from protohunter.cli import main
from protohunter.exports import SECTIONS, export_directory, export_zip
from protohunter.runtime import AnalysisCancelled


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.report = analyze(Path(__file__).resolve().parents[1] / 'protohunter/demo.smali')

    def test_all_fields_pairs_and_evidence_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, 'sections')
            index = export_directory(self.report, root)
            for key, (stem, _) in SECTIONS.items():
                self.assertEqual(json.loads((root / (stem + '.json')).read_text(encoding='utf-8')), self.report[key])
                self.assertTrue((root / (stem + '.txt')).is_file())
            meta = json.loads((root / 'metadata.json').read_text())
            self.assertEqual(meta['generated_at'], self.report['generated_at'])
            self.assertEqual(meta['version'], self.report['version'])
            self.assertIn('server.json', [s['json'] for s in index['sections']])
            self.assertIn(self.report['servers'][0]['host'], (root / 'server.txt').read_text(encoding='utf-8'))
            self.assertIn(self.report['sources'][0]['content'], (root / 'source.txt').read_text(encoding='utf-8'))

    def test_utf8_empty_and_research_stage_exports(self):
        self.report['input']['name'] = 'تطبيق.apk'
        self.report['servers'] = []
        self.report['research'] = [{'stage':'login','target':'اسم','source':'base.apk!مثال.smali','line':7,'offset':10,'confidence':'high'}]
        result = io.BytesIO(); export_zip(self.report, result)
        with zipfile.ZipFile(result) as archive:
            self.assertEqual(json.loads(archive.read('server.json')), [])
            self.assertIn('لا توجد سجلات', archive.read('server.txt').decode('utf-8'))
            self.assertEqual(json.loads(archive.read('research_stages/login.json')), self.report['research'])
            self.assertEqual(json.loads(archive.read('research_stages/session.json')), [])
            self.assertIn('تطبيق.apk', archive.read('protocol.txt').decode('utf-8'))

    def test_zip_matches_directory_and_unknown_keys_cannot_write_paths(self):
        self.report['metadata'] = {'custom':'preserved'}
        self.report['../../evil.txt'] = {'value':'<script>not executed</script>'}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, 'sections'); export_directory(self.report, root)
            stream = io.BytesIO(); export_zip(self.report, stream)
            with zipfile.ZipFile(stream) as archive:
                self.assertIsNone(archive.testzip())
                self.assertTrue(all('..' not in name for name in archive.namelist()))
                for name in archive.namelist():
                    self.assertEqual(archive.read(name), (root / name).read_bytes())
                self.assertEqual(json.loads(archive.read('extra/field-001.json')), self.report['../../evil.txt'])
                index = json.loads(archive.read('index.json'))
                reconstructed = {}
                for entry in index['sections']:
                    value = json.loads(archive.read(entry['json']))
                    if entry['kind'] == 'metadata':
                        reconstructed.update(value)
                    elif entry['kind'] == 'original' and entry['present_in_report']:
                        reconstructed[entry['source_fields'][0]] = value
                self.assertEqual(reconstructed, self.report)

    def test_cancel_is_transactional_and_existing_exports_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, 'sections'); events = []
            with self.assertRaises(AnalysisCancelled):
                export_directory(self.report, root, cancel=lambda: bool(events), progress=events.append)
            self.assertFalse(root.exists())
            self.assertEqual(list(Path(tmp).iterdir()), [])
            export_directory(self.report, root)
            original = (root / 'server.json').read_bytes()
            with self.assertRaisesRegex(ValueError, 'already exists'):
                export_directory(self.report, root)
            self.assertEqual((root / 'server.json').read_bytes(), original)

    def test_cli_auto_and_explicit_directories(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            source = Path(tmp, 'sample.txt'); source.write_text('https://example.invalid')
            target = Path(tmp, 'report.json')
            self.assertEqual(main(['analyze', str(source), '-o', str(target)]), 0)
            self.assertTrue(Path(tmp, 'report.sections/server.json').exists())
            self.assertEqual(main(['analyze', str(source), '-o', str(target)]), 0)
            self.assertTrue(Path(tmp, 'report.sections-2/protocol.txt').exists())
            self.assertEqual(main(['analyze', str(source), '--sections-dir', str(Path(tmp, 'custom'))]), 0)
            self.assertTrue(Path(tmp, 'custom/index.json').exists())
            self.assertEqual(main(['analyze', str(source), '--sections-dir', str(Path(tmp, 'custom'))]), 2)
            conflict = Path(tmp, 'conflict')
            self.assertEqual(main(['analyze', str(source), '-o', str(conflict / 'server.json'), '--sections-dir', str(conflict)]), 2)
            self.assertFalse(conflict.exists())
            self.assertEqual(source.read_text(), 'https://example.invalid')
