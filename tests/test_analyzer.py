import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from protohunter.analyzer import analyze
from protohunter.cli import main
from protohunter.formats import descriptors, dex_strings, wire


def vint(value):
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def field(number, value):
    if isinstance(value, int):
        return vint(number << 3) + vint(value)
    if isinstance(value, str):
        value = value.encode()
    return vint((number << 3) | 2) + vint(len(value)) + value


def sample_descriptor():
    member = field(1, 'device_id') + field(3, 1) + field(4, 1) + field(5, 9)
    message = field(1, 'Event') + field(2, member)
    method = field(1, 'Send') + field(2, '.demo.Event') + field(3, '.demo.Event') + field(6, 1)
    service = field(1, 'Telemetry') + field(2, method)
    file = field(1, 'telemetry.proto') + field(2, 'demo') + field(4, message) + field(6, service) + field(12, 'proto3')
    return field(1, file)


def sample_dex(text):
    data = bytearray(116)
    data[:8] = b'dex\n035\0'
    struct.pack_into('<I', data, 40, 0x12345678)
    struct.pack_into('<II', data, 56, 1, 112)
    struct.pack_into('<I', data, 112, 116)
    data += vint(len(text)) + text.encode() + b'\0'
    struct.pack_into('<I', data, 32, len(data))
    struct.pack_into('<I', data, 36, 112)
    return bytes(data)


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def file(self, name, content):
        path = self.root / name
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        return path

    def test_endpoints_and_confidence(self):
        result = analyze(self.file('config.txt', 'https://api.example.com/v1\nwss://events.example.net/socket\n10.0.0.1:8443\n999.0.0.1\nhttps://[2001:db8::1]:443/path\nexample.org\n'))
        endpoints = result['endpoints']
        self.assertEqual(len(endpoints), 5)
        self.assertTrue(all(item['source'] == 'config.txt' for item in endpoints))
        self.assertEqual(endpoints[0]['line'], 1)
        self.assertEqual(endpoints[-1]['confidence'], 'low')
        self.assertIn('2001:db8::1', {x['host'] for x in endpoints})

    def test_http_url_not_rpc_path(self):
        report = analyze(self.file('url.txt', 'https://safe.example.com/api'))
        self.assertFalse(report['protobuf'])

    def test_ipv6_url_without_path(self):
        report = analyze(self.file('ipv6.txt', 'http://[::1]'))
        self.assertEqual(report['endpoints'][0]['host'], '::1')

    def test_empty_dex_table(self):
        raw = bytearray(sample_dex('unused'))
        struct.pack_into('<II', raw, 56, 0, 0)
        self.assertEqual(list(dex_strings(raw)), [])

    def test_smali_inventory_and_retrofit(self):
        content = '''.class public Ltest/Client;
.super Ljava/lang/Object;
.field public name:Ljava/lang/String;
.method public fetch()V
    .annotation runtime Lretrofit2/http/GET;
        value = "/v1/status"
    .end annotation
    invoke-static {}, Lio/grpc/ManagedChannelBuilder;->forTarget()V
    return-void
.end method
'''
        result = analyze(self.file('Client.smali', content))
        cls = result['smali'][0]
        self.assertEqual(cls['value'], 'Ltest/Client;')
        self.assertEqual(cls['method_count'], 1)
        self.assertEqual(cls['field_count'], 1)
        self.assertEqual(cls['invokes'][0]['line'], 8)
        self.assertEqual(result['endpoints'][0]['method'], 'GET')
        self.assertIn('gRPC', {x['value'] for x in result['protocols']})

    def test_java_retrofit(self):
        result = analyze(self.file('Client.java', '@GET("/v2/items") Call<Item> items();'))
        self.assertEqual(result['endpoints'][0]['value'], '/v2/items')

    def test_dex_string_offsets(self):
        raw = sample_dex('https://api.example.com/test')
        self.assertEqual(list(dex_strings(raw)), [(116, 'https://api.example.com/test')])
        report = analyze(self.file('classes.dex', raw))
        self.assertEqual(report['endpoints'][0]['offset'], 116)
        self.assertIsNone(report['endpoints'][0]['line'])
        self.assertFalse(report['smali'])

    def test_embedded_dex_descriptor(self):
        raw = wire(sample_descriptor())[1][0]
        report = analyze(self.file('embedded.dex', sample_dex(raw.decode('latin-1'))))
        findings = [x for x in report['protobuf'] if x['kind'] == 'embedded DEX descriptor']
        self.assertEqual(findings[0]['descriptor']['name'], 'telemetry.proto')

    def test_generated_field_numbers(self):
        report = analyze(self.file('Message.smali', '.field public static final DEVICE_ID_FIELD_NUMBER:I = 0x12'))
        finding = report['protobuf'][0]
        self.assertEqual(finding['field_number'], 18)
        self.assertEqual(finding['field_name'], 'DEVICE_ID')
        self.assertEqual(finding['confidence'], 'medium')

    def test_bad_dex_is_warning(self):
        report = analyze(self.file('bad.dex', b'dex\n035\0'))
        self.assertTrue(any('Invalid DEX' in x for x in report['warnings']))

    def test_descriptor_structure(self):
        parsed = descriptors(sample_descriptor())[0]
        self.assertEqual(parsed['package'], 'demo')
        self.assertEqual(parsed['messages'][0]['fields'][0]['number'], 1)
        self.assertEqual(parsed['messages'][0]['fields'][0]['type'], 'string')
        self.assertTrue(parsed['services'][0]['methods'][0]['server_streaming'])
        report = analyze(self.file('schema.desc', sample_descriptor()))
        self.assertEqual(report['protobuf'][0]['kind'], 'descriptor')
        self.assertEqual(report['protobuf'][0]['confidence'], 'high')

    def test_descriptor_single_file(self):
        single = wire(sample_descriptor())[1][0]
        self.assertEqual(descriptors(single)[0]['name'], 'telemetry.proto')

    def test_unrelated_pb_not_schema(self):
        report = analyze(self.file('payload.pb', field(1, 'hello')))
        self.assertFalse(report['protobuf'])

    def test_malformed_descriptor_warning(self):
        report = analyze(self.file('bad.desc', b'\x0a\xff'))
        self.assertTrue(any('descriptor' in warning for warning in report['warnings']))

    def test_proto_source(self):
        report = analyze(self.file('chat.proto', 'syntax = "proto3"; package demo; message Chat { string id = 1; }'))
        self.assertEqual(report['protobuf'][0]['package'], 'demo')
        self.assertIn(('message', 'Chat'), report['protobuf'][0]['declarations'])

    def test_apk_archive_and_traversal(self):
        path = self.root / 'demo.apk'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('classes.dex', sample_dex('https://api.example.com'))
            archive.writestr('assets/schema.desc', sample_descriptor())
            archive.writestr('../../escape.txt', 'https://evil.example.com')
        report = analyze(path)
        self.assertEqual(report['summary']['files_scanned'], 2)
        self.assertEqual(report['summary']['unique_hosts'], 1)
        self.assertTrue(any('Unsafe' in x for x in report['warnings']))
        self.assertFalse((self.root.parent / 'escape.txt').exists())

    def test_zip_bomb_ratio_skipped(self):
        path = self.root / 'bomb.zip'
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('large.txt', b'a' * 1000000)
        report = analyze(path)
        self.assertEqual(report['summary']['files_scanned'], 0)
        self.assertTrue(any('high-ratio' in x for x in report['warnings']))

    def test_symlinks_not_scanned(self):
        self.file('test.txt', 'https://api.example.org')
        try:
            (self.root / 'loop').symlink_to(self.root, target_is_directory=True)
        except OSError:
            self.skipTest('Host does not permit creating symlinks')
        report = analyze(self.root)
        self.assertEqual(report['summary']['files_scanned'], 1)

    def test_missing_decoder(self):
        path = self.root / 'test.apk'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('classes.dex', sample_dex('hi'))
        with patch('protohunter.analyzer.shutil.which', return_value=None):
            report = analyze(path, 'both')
        self.assertTrue(any('jadx not installed' in x for x in report['warnings']))
        self.assertTrue(any('apktool not installed' in x for x in report['warnings']))

    def test_cli_json(self):
        path = self.file('a.txt', 'https://api.example.net')
        output = self.root / 'report.json'
        self.assertEqual(main(['analyze', str(path), '-o', str(output)]), 0)
        self.assertEqual(json.loads(output.read_text())['summary']['unique_endpoints'], 1)

    def test_cli_refuses_overwrite(self):
        path = self.file('a.txt', 'hello')
        self.assertEqual(main(['analyze', str(path), '-o', str(path)]), 2)
        self.assertEqual(path.read_text(), 'hello')

    def test_utf16_string_carving(self):
        report = analyze(self.file('data.bin', 'https://api.example.com'.encode('utf-16le')))
        self.assertEqual(report['endpoints'][0]['host'], 'api.example.com')

    def test_finding_limit_visible(self):
        with patch('protohunter.analyzer.MAX_FINDINGS', 1):
            report = analyze(self.file('a.txt', 'https://example.com\nhttps://example.net'))
        self.assertEqual(report['summary']['findings'], 1)
        self.assertTrue(any('limit reached' in x for x in report['warnings']))

    def test_invalid_archive(self):
        with self.assertRaisesRegex(ValueError, 'Invalid ZIP'):
            analyze(self.file('bad.apk', 'not a zip'))


if __name__ == '__main__':
    unittest.main()
