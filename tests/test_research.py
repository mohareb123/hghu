import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from protohunter.analyzer import Analyzer, analyze
from protohunter.android import resource_strings
from protohunter.cli import main
from test_games import zip_bytes
from test_analyzer import sample_dex

LOGIN = '''.class public LN2/c;
.super Ljava/lang/Object;
.field public static final appKey:Ljava/lang/String; = "synthetic-key"
.field public static final appSecret:Ljava/lang/String; = "synthetic-not-a-real-secret"
.field public static final region:Ljava/lang/String; = "TEST"
.field public static final port:I = 0x1f90
.method public login()V
 .locals 3
 const-string v0, "https://gateway.example.invalid/v1/"
 const-string v1, "CSMajorLoginReq"
 const-string v2, "CSMajorLoginResp"
 invoke-static {}, Ldemo/Session;->GetLoginData()V
 return-void
.end method
.method public unrelated()V
 const-string v0, "https://cdn.example.invalid/image"
 return-void
.end method
'''


def binary_xml(strings, utf8=True):
    encoded = []
    offsets = []
    cursor = 0
    for value in strings:
        offsets.append(cursor)
        raw = value.encode('utf-8' if utf8 else 'utf-16le')
        unit_count = len(value.encode('utf-16le')) // 2
        if utf8:
            def length(n):
                return bytes([n]) if n < 128 else bytes([128 | (n >> 8), n & 255])
            item = length(unit_count) + length(len(raw)) + raw + b'\0'
        else:
            item = struct.pack('<H', unit_count) + raw + b'\0\0'
        encoded.append(item)
        cursor += len(item)
    blob = b''.join(encoded)
    start = 28 + len(strings) * 4
    size = start + len(blob)
    pool = struct.pack('<HHIIIIII', 1, 28, size, len(strings), 0, 256 if utf8 else 0, start, 0)
    pool += b''.join(struct.pack('<I', value) for value in offsets) + blob
    return struct.pack('<HHI', 3, 8, 8 + len(pool)) + pool


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def file(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode() if isinstance(content, str) else content)
        return path

    def test_named_login_targets_and_field_sources(self):
        result = analyze(self.file('N2/c.smali', LOGIN))
        targets = {x['target'] for x in result['research']}
        self.assertTrue({'CSMajorLoginReq', 'CSMajorLoginResp', 'N2/c.smali', 'GetLoginData', 'appKey', 'appSecret', 'region', 'port'} <= targets)
        req = next(x for x in result['research'] if x['target'] == 'CSMajorLoginReq')
        self.assertEqual(req['class_name'], 'LN2/c;')
        self.assertEqual(req['method_name'], 'public login()V')
        self.assertGreater(req['line'], 0)

    def test_session_variants(self):
        result = analyze(self.file('session.txt', 'getToken account_id server_timestamp serverId VodkaConfig'))
        targets = {x['target'] for x in result['research']}
        self.assertTrue({'token', 'accountId', 'serverTimestamp', 'serverId', 'VodkaConfig'} <= targets)

    def test_message_families_keep_candidate_names(self):
        text = 'CSPlayerInfoReq TeamInvite ChatMessage RoomData MatchStart FriendList GuildInfo InventoryItem'
        result = analyze(self.file('classes.dex', sample_dex(text)))
        messages = [x for x in result['research'] if x['stage'] == 'messages']
        self.assertEqual({x['target'] for x in messages}, {'Player', 'Team', 'Chat', 'Room', 'Match', 'Friend', 'Guild', 'Inventory'})
        self.assertIn('CSPlayerInfoReq', {x['value'] for x in messages})
        self.assertTrue(all(x['confidence'] == 'low' for x in messages))
        self.assertTrue(all(x['line'] is None for x in messages))

    def test_prototcp_paths(self):
        path = self.file('prototcp/account.proto', 'message Account {}')
        result = analyze(path.parent.parent)
        targets = {x['target'] for x in result['research']}
        self.assertTrue({'prototcp', 'account.proto'} <= targets)

    def test_smali_invokes_are_not_runtime_transitions(self):
        result = analyze(self.file('N2/c.smali', LOGIN))
        call = result['flow'][0]
        self.assertEqual(call['callee'], 'Ldemo/Session;->GetLoginData()V')
        self.assertFalse(call['runtime_transition_proven'])

    def test_commented_invoke_is_not_a_call(self):
        source = '.class public Ldemo/X;\n.method public login()V\n# invoke-static {}, Ldemo/Session;->GetLoginData()V\n.end method'
        result = analyze(self.file('X.smali', source))
        self.assertFalse(result['flow'])
        self.assertFalse(result['smali'][0]['invokes'])

    def test_focus_is_not_merely_same_file(self):
        result = analyze(self.file('N2/c.smali', LOGIN))
        first, second = result['endpoints']
        self.assertTrue(first['research_relevance']['focused'])
        self.assertIn('same_smali_method_as_research_reference', first['research_relevance']['reasons'])
        self.assertFalse(second['research_relevance']['focused'])
        self.assertIn('same_file_as_research_reference', second['research_relevance']['reasons'])

    def test_port_and_region_unbound_candidates(self):
        result = analyze(self.file('N2/c.smali', LOGIN))
        port = next(x for x in result['research'] if x['target'] == 'port')
        region = next(x for x in result['research'] if x['target'] == 'region')
        self.assertEqual(port['port_literal_candidate'], 8080)
        self.assertEqual(region['region_literal_candidate'], 'TEST')
        self.assertFalse(port['bound_to_endpoint'])

    def test_proto_tag_not_a_port_value(self):
        result = analyze(self.file('account.proto', 'message Account { int32 port = 8080; }'))
        self.assertTrue(any(x['target'] == 'port' for x in result['research']))
        self.assertFalse(any('port_literal_candidate' in x for x in result['research']))

    def test_research_independent_of_generic_result_cap(self):
        with patch('protohunter.analyzer.MAX_FINDINGS', 0):
            result = analyze(self.file('a.txt', 'https://example.invalid\nCSMajorLoginReq\ntoken'))
        self.assertEqual(result['summary']['findings'], 0)
        self.assertTrue({'CSMajorLoginReq', 'token'} <= {x['target'] for x in result['research']})
        self.assertEqual(result['coverage'][0]['status'], 'partial')

    def test_research_limit_explicit(self):
        with patch('protohunter.research.MAX_RESEARCH', 1):
            result = analyze(self.file('a.txt', 'CSMajorLoginReq token accountId'))
        self.assertTrue(result['research_plan']['truncated'])
        self.assertEqual(result['coverage'][0]['status'], 'partial')

    def test_missing_is_not_absent(self):
        result = analyze(self.file('a.txt', 'nothing relevant'))
        self.assertTrue(all(x['status'] == 'not_observed_in_scanned_content' for x in result['research_plan']['targets']))
        self.assertFalse(result['coverage_summary']['semantic_completeness_guaranteed'])




    def test_native_crypto_names(self):
        result = analyze(self.file('lib.bin', b'\0AES_encrypt\0SSL_connect\0HMAC_Init_ex\0'))
        targets = {x['target'] for x in result['research']}
        self.assertTrue({'AES', 'SSL', 'HMAC'} <= targets)




    def test_hash_covers_non_string_bytes(self):
        content = b'\x00\xff\x00nothing\x01\x02\x03'
        result = analyze(self.file('data.bin', content))
        coverage = result['coverage'][0]
        self.assertEqual(coverage['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(coverage['bytes_hashed'], len(content))
        self.assertEqual(result['coverage_summary']['fully_hashed_files'], 1)

    def test_skipped_file_has_reason_and_no_hash(self):
        target = self.file('too-large.bin', b'abcde')
        with patch('protohunter.analyzer.MAX_FILE', 4):
            result = analyze(target)
        entry = result['coverage'][0]
        self.assertEqual(entry['status'], 'skipped')
        self.assertEqual(entry['bytes_hashed'], 0)
        self.assertTrue(entry['reason'])
        self.assertNotIn('sha256', entry)
        self.assertIsNotNone(result['input']['sha256'])  # Root hash != semantic extraction.

    def test_nested_depth_coverage_incomplete(self):
        data = zip_bytes({'file.txt': b'token'})
        for n in range(5):
            data = zip_bytes({f'{n}.apk': data})
        result = analyze(self.file('game.xapk', data))
        self.assertFalse(result['coverage_summary']['inventory_complete_within_opened_inputs'])
        self.assertTrue(any(x['status'] == 'unexpanded' for x in result['coverage']))

    def test_byte_budget_lists_skipped_members(self):
        path = self.file('a.zip', zip_bytes({'one.txt': b'token', 'two.txt': b'login'}))
        engine = Analyzer()
        engine.limits['expanded'] = 1
        result = engine.run(path)
        self.assertEqual(result['coverage_summary']['file_statuses']['skipped'], 2)

    def test_invalid_dex_hashed_but_partial(self):
        result = analyze(self.file('bad.dex', b'dex\n035\0bad'))
        self.assertEqual(result['coverage'][0]['status'], 'partial')
        self.assertEqual(result['coverage'][0]['bytes_hashed'], 11)

    def test_resource_pools_utf8_utf16(self):
        values = ['token', 'CSMajorLoginReq', 'https://login.example.invalid', 'مرحبا']
        for utf8 in (True, False):
            with self.subTest(utf8=utf8):
                data = binary_xml(values, utf8)
                self.assertEqual([text for _, text in resource_strings(data)], values)
                result = analyze(self.file('AndroidManifest.xml', data))
                self.assertTrue(any(x['target'] == 'CSMajorLoginReq' for x in result['research']))
                self.assertIn('Android_binary_resource_string_pools', result['coverage'][0]['methods'])

    def test_corrupt_resource_range(self):
        data = bytearray(binary_xml(['token']))
        struct.pack_into('<I', data, 8 + 28, 100000)
        with self.assertRaises(ValueError):
            list(resource_strings(data))
        result = analyze(self.file('AndroidManifest.xml', data))
        self.assertEqual(result['coverage'][0]['status'], 'partial')


if __name__ == '__main__':
    unittest.main()
