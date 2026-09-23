import hashlib
import io
from pathlib import Path
import random
import re
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from protohunter.analyzer import Analyzer, analyze
from protohunter.research import TARGETS
from protohunter.runtime import AnalysisCancelled, binary_strings


def packed(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return stream.getvalue()


class PerformanceTests(unittest.TestCase):
    def test_windowed_strings_equal_original_including_long_runs_and_boundaries(self):
        data = (random.Random(123).randbytes(2 * 1024**2) + b'\xff' + b'A' * 70000 + b'\xff' +
                ('B' * 70000).encode('utf-16le') + b'\xffHTTPS\0')
        for utf16 in (False, True):
            pattern = rb'(?:[\x20-\x7e]\x00){3,16384}' if utf16 else rb'[\x20-\x7e]{3,16384}'
            expected = [(m.start(), m.group()) for m in re.finditer(pattern, data)]
            for window in (65537, 1024**2):
                self.assertEqual(list(binary_strings(data, utf16=utf16, window=window)), expected)

    def test_short_prefilter_preserves_research_protocols_and_domains(self):
        tokens = [term for terms in TARGETS.values() for term in terms if len(term) < 6]
        tokens += ['QUIC', 'grpc/', 'a.co', 'a.b/c', 'TLSv1']
        data = b'\xff'.join(t.encode() for t in tokens) + b'\xff' + b'\xff'.join(t.encode('utf-16le') for t in tokens)
        actual = Analyzer()
        actual.consume('library.so', data)
        original = Analyzer()
        for utf16 in (False, True):
            for offset, raw in binary_strings(data, utf16=utf16):
                original.scan_text(raw.decode('utf-16le' if utf16 else 'ascii'), 'library.so', offset=offset)
        self.assertEqual(actual.research.hits, original.research.hits)
        for category in ('endpoints', 'protocols', 'protobuf'):
            self.assertEqual(actual.report[category], original.report[category])

    def test_memory_members_fast_skips_and_hashes(self):
        content = b'https://login.example.invalid/\0TCP\0'
        apk = packed({'assets/config.txt': content, 'res/image.png': content})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'game.xapk'); path.write_bytes(packed({'base.apk': apk}))
            events = []
            deep = analyze(path, progress=events.append)
            fast = analyze(path, scan_mode='fast')
            self.assertEqual(deep['summary']['small_members_in_memory'], 2)
            self.assertEqual(fast['summary']['skipped_media'], 1)
            media = next(row for row in fast['coverage'] if row['source'].endswith('image.png'))
            self.assertEqual(media['status'], 'skipped')
            self.assertEqual(media['bytes_hashed'], 0)
            self.assertTrue(any(event['stage'] == 'scanning' for event in events))
            for row in deep['coverage']:
                if row['kind'] == 'file':
                    self.assertEqual(row['sha256'], hashlib.sha256(content).hexdigest())
            self.assertEqual(deep['input']['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertFalse(fast['coverage_summary']['semantic_completeness_guaranteed'])

    def test_large_staged_member_hash_reused(self):
        content = b'\0' * (2 * 1024**2 + 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'game.apk'); path.write_bytes(packed({'lib/test.so': content}))
            with patch('protohunter.analyzer.sha256_buffer', side_effect=AssertionError('Duplicate leaf hash')):
                report = analyze(path)
            leaf = next(r for r in report['coverage'] if r['kind'] == 'file')
            self.assertEqual(leaf['sha256'], hashlib.sha256(content).hexdigest())

    def test_cancellation_propagates_out_of_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'game.apk'); path.write_bytes(packed({'one.txt': b'abc'}))
            cancelled = [False]
            def progress(event):
                if event['stage'] == 'expanding':
                    cancelled[0] = True
            with self.assertRaises(AnalysisCancelled):
                analyze(path, progress=progress, cancel=lambda: cancelled[0])

    def test_root_digest_not_rehashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'config.txt'); path.write_text('https://a.example.invalid')
            with patch('protohunter.analyzer.sha256_buffer', side_effect=AssertionError('Duplicate hash')):
                report = analyze(path)
            self.assertEqual(report['input']['sha256'], report['coverage'][0]['sha256'])

    def test_invalid_mode(self):
        with self.assertRaises(ValueError):
            Analyzer(scan_mode='pretend-complete')
