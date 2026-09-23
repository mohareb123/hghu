import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from protohunter.analyzer import analyze
from protohunter.bytecode import dex_events, smali_events
from protohunter.investigation import RULES, LIMITS, priority, proto_definitions, addresses
from protohunter.botmatch import compare, fingerprints, read_project

LOGIN = '''.class public Lsample/LoginClient;
.super Ljava/lang/Object;
.method public static login()V
    .locals 2
    new-instance v0, Lsample/CSMajorLoginReq$Builder;
    invoke-virtual {v0, v1}, Lsample/CSMajorLoginReq$Builder;->setAppKey(Ljava/lang/String;)V
    invoke-virtual {v0, v1}, Lsample/CSMajorLoginReq$Builder;->setAppSecret(Ljava/lang/String;)V
    invoke-virtual {v0, v1}, Lsample/CSMajorLoginReq$Builder;->setAccountId(Ljava/lang/String;)V
    invoke-virtual {v0, v1}, Lsample/CSMajorLoginReq$Builder;->setRegion(Ljava/lang/String;)V
    invoke-virtual {v0, v1}, Lsample/CSMajorLoginReq$Builder;->setServerId(Ljava/lang/String;)V
    invoke-virtual {v0, v1}, Lsample/CSMajorLoginResp;->getToken()Ljava/lang/String;
    invoke-virtual {v0}, Lsample/CSMajorLoginReq;->toByteArray()[B
    const-string v1, "https://login.example.invalid:443/login"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    invoke-static {}, Lsample/Transport;->send()V
    return-void
.end method
'''
BUILDER = '''.class public Lsample/CSMajorLoginReq$Builder;
.super Lcom/google/protobuf/GeneratedMessageLite$Builder;
.field private appKey:Ljava/lang/String;
'''
TRANSPORT = '''.class public Lsample/Transport;
.super Ljava/lang/Object;
.method public static send()V
    .locals 2
    invoke-virtual {v0, v1}, Ljava/net/Socket;->connect(Ljava/net/SocketAddress;)V
    return-void
.end method
'''


def dex_fixture(payload=False):
    """Minimal real DEX tables/code, not a string pretending to be an invoke."""
    values = ['Lsample/Client;', 'Ljava/lang/Object;', 'Ljava/net/Socket;', 'Ljava/net/SocketAddress;', 'V', 'login', 'connect']
    data = bytearray(256); data[:8] = b'dex\n035\0'
    struct.pack_into('<I', data, 40, 0x12345678)
    struct.pack_into('<II', data, 56, len(values), 112)
    for i, text in enumerate(values):
        offset = len(data); data.extend(bytes([len(text)]) + text.encode() + b'\0'); struct.pack_into('<I', data, 112 + i * 4, offset)
    def align():
        while len(data) % 4: data.append(0)
    align(); types = len(data)
    for index in range(5): data.extend(struct.pack('<I', index))
    struct.pack_into('<II', data, 64, 5, types)
    params = len(data); data.extend(struct.pack('<IH', 1, 3)); align()
    protos = len(data); data.extend(struct.pack('<III', 4, 4, 0)); data.extend(struct.pack('<III', 4, 4, params)); struct.pack_into('<II', data, 72, 2, protos)
    methods = len(data); data.extend(struct.pack('<HHI', 0, 0, 5)); data.extend(struct.pack('<HHI', 2, 1, 6)); struct.pack_into('<II', data, 88, 2, methods)
    classes = len(data); data.extend(bytes(32)); struct.pack_into('<II', data, 96, 1, classes)
    align(); code = len(data)
    instructions = [0x206e, 1, 0x0010, 0x000e] if not payload else [0x0300, 2, 3, 0, 0x206e, 1, 0x0010, 0x000e]
    data.extend(struct.pack('<HHHHII', 2, 0, 2, 0, 0, len(instructions)))
    data.extend(struct.pack('<' + 'H'*len(instructions), *instructions))
    class_data = len(data)
    def uleb(value):
        result = bytearray()
        while value >= 128: result.append((value & 127) | 128); value >>= 7
        result.append(value); return result
    data.extend(b'\0\0\1\0\0\x09' + uleb(code))
    struct.pack_into('<IIIIIIII', data, classes, 0, 1, 1, 0, 0xffffffff, 0, class_data, 0)
    struct.pack_into('<II', data, 32, len(data), 112)
    return bytes(data)


class InvestigationTests(unittest.TestCase):
    def report(self, files, **options):
        with tempfile.TemporaryDirectory() as tmp:
            for name, content in files.items():
                path = Path(tmp, name); path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content if isinstance(content, bytes) else content.encode())
            return analyze(tmp, investigate=True, **options)

    def test_score_exact_once_and_full_static_path(self):
        data = self.report({'Login.smali': LOGIN, 'Builder.smali': BUILDER, 'Transport.smali': TRANSPORT})
        result = data['protocol_report']
        item = next(x for x in result['auth'] if x['name'] == 'Lsample/CSMajorLoginReq;')
        self.assertEqual(item['score'], 58, item['score_reasons'])
        self.assertEqual(item['priority'], 'RELATED'); self.assertEqual(item['confidence'], 'HIGH')
        self.assertFalse(item['runtime_use_proven']); self.assertFalse(item['data_flow_proven'])
        self.assertEqual(item['network_path'][-1], 'Ljava/net/Socket;->connect(Ljava/net/SocketAddress;)V')
        self.assertIn('appSecret', item['fields']); self.assertIn('region', item['fields'])
        graph = data['dependency_graph']; ids = {n['id'] for n in graph['nodes']}
        self.assertTrue(all(e['source'] in ids and e['target'] in ids for e in graph['edges']))
        path = item['network_path_node_ids']
        for a, b in zip(path, path[1:]): self.assertTrue(any(e['source']==a and e['target']==b and e['kind']=='calls' for e in graph['edges']))
        self.assertEqual(len(item['score_reasons']), 9)

    def test_unused_proto_and_resource_only_are_not_important(self):
        data = self.report({'res/raw/schema.proto': 'package unused; message LoginPacket { string token = 1; }', 'assets/config.json': '{"url":"https://unused.example.invalid"}'})['protocol_report']
        proto = next(x for x in data['auth'] if x['name']=='unused.LoginPacket')
        self.assertEqual(proto['score'], -23); self.assertEqual(proto['fields'], ['token']); self.assertFalse(proto['network'])
        address = next(x for x in data['unknown'] if x['name']=='https://unused.example.invalid')
        self.assertEqual(address['score'], -18)

    def test_unused_generated_constructor_is_not_proto_usage(self):
        source = BUILDER + '.method public constructor <init>()V\n invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n return-void\n.end method\n'
        result = self.report({'Builder.smali':source})['protocol_report']
        item = next(x for x in result['auth'] if x['name']=='Lsample/CSMajorLoginReq;')
        self.assertFalse(item['executable_reference'])
        self.assertNotIn('proto_executable_reference', [r['rule'] for r in item['score_reasons']])
        self.assertIn('unused_proto_definition', [r['rule'] for r in item['score_reasons']])

    def test_names_comments_and_literals_do_not_create_network_edges(self):
        fake = LOGIN.replace('Lsample/Transport;->send()V', 'Lsample/Fake;->connect()V')
        fake += '\n# invoke-static {}, Ljava/net/Socket;->connect()V\n'
        data = self.report({'Login.smali':fake,'Builder.smali':BUILDER})
        item = next(x for x in data['protocol_report']['auth'] if x['name']=='Lsample/CSMajorLoginReq;')
        self.assertFalse(item['network']); self.assertNotEqual(item['confidence'], 'HIGH')
        self.assertNotIn('crypto_on_network_path', [r['rule'] for r in item['score_reasons']])
        events = list(smali_events('.class public LX;\n.method x()V\n const-string v0, "invoke-static {}, Ljava/net/Socket;->connect()V"\n.end method', 'fake.smali'))
        self.assertFalse(any(e[0]=='calls' for e in events))

    def test_real_dex_instructions_and_payload_skip(self):
        calls = [e for e in dex_events(dex_fixture(), 'classes.dex') if e[0]=='calls']
        self.assertEqual(len(calls), 1); self.assertIn('Socket;->connect', calls[0][2])
        self.assertIsInstance(calls[0][3]['offset'], int)
        self.assertFalse(any(e[0]=='calls' for e in dex_events(dex_fixture(payload=True), 'payload.dex')))
        result = self.report({'classes.dex':dex_fixture()})
        self.assertTrue(any(x['network'] for rows in [result['protocol_report'][k.lower()] for k in ('UNKNOWN','TRANSPORT')] for x in rows))
        broken = self.report({'classes.dex':dex_fixture()[:100]})
        self.assertTrue(broken['protocol_report']['meta']['truncated'])

    def test_cycles_overloads_and_rule_boundaries(self):
        cyc = TRANSPORT.replace('return-void', 'invoke-static {}, Lsample/Transport;->send()V\n return-void')
        data = self.report({'Login.smali':LOGIN,'Transport.smali':cyc})
        self.assertLess(len(data['dependency_graph']['nodes']), 100)
        self.assertEqual(sum(x for x in RULES.values() if x>0), 58)
        self.assertEqual([priority(x) for x in [-1,0,19,20,39,40,59,60,79,80]], ['IGNORE','UNKNOWN','UNKNOWN','POSSIBLE','POSSIBLE','RELATED','RELATED','REQUIRED','REQUIRED','CRITICAL'])

    def test_overloads_do_not_create_false_transport_path(self):
        result = self.report({'Login.smali':LOGIN, 'Builder.smali':BUILDER, 'Transport.smali':TRANSPORT.replace('send()V', 'send(I)V')})
        item = next(x for x in result['protocol_report']['auth'] if x['name']=='Lsample/CSMajorLoginReq;')
        self.assertFalse(item['network'])

    def test_graph_budget_and_cancellation(self):
        with patch.dict(LIMITS, nodes=3):
            data = self.report({'Login.smali':LOGIN})
        self.assertTrue(data['protocol_report']['meta']['truncated'])
        self.assertLessEqual(len(data['dependency_graph']['nodes']), 3)
        from protohunter.runtime import AnalysisCancelled
        def cancel(): raise AnalysisCancelled('test')
        with self.assertRaises(AnalysisCancelled):
            list(dex_events(dex_fixture(), 'classes.dex', cancel))

    def test_proto_nested_fields_ignore_comments(self):
        text = '// message Fake {}\nmessage Real { string token=1; enum E { FAKE=0; } message Nested { int32 id=1; } oneof x { string region=2; } }'
        self.assertEqual(proto_definitions(text, 'pkg'), [('pkg.Real',['token','region']),('pkg.Real.Nested',['id'])])

    def test_bot_matching_optional_and_does_not_execute(self):
        protocol = self.report({'Login.smali':LOGIN,'Builder.smali':BUILDER,'Transport.smali':TRANSPORT})['protocol_report']
        files = [{'name':'old.py','text':'class CSMajorLoginReq:\n appKey="x"\n appSecret="x"\n accountId=0\n region="x"\n serverId=0\n\nclass GamePacketX:\n pass\nraise RuntimeError("must never run")'}]
        result = compare(protocol, files)
        match = next(x for x in result['bot_matches'] if x['name']=='CSMajorLoginReq')
        self.assertIn(match['status'], ('CANDIDATE','AMBIGUOUS')); self.assertGreater(match['candidates'][0]['match'], .45)
        self.assertFalse(match['compatibility_proven'])
        self.assertEqual(result['missing_from_new_version'][0]['name'], 'GamePacketX')
        self.assertFalse(protocol['bot_matches'])
        with self.assertRaises(ValueError): fingerprints([{'name':'old.py','text':'x'*(512*1024+1)}])

    def test_bot_archive_read_without_extracting_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp,'bot.zip')
            with zipfile.ZipFile(path,'w') as z: z.writestr('../old.py','class LoginPacket: pass')
            files, omitted=read_project(path)
            self.assertEqual(files[0]['name'],'../old.py'); self.assertEqual(omitted,0)
            self.assertEqual(list(Path(tmp).iterdir()),[path])

    def test_literal_addresses_validate_and_preserve_ports(self):
        self.assertEqual(list(addresses('999.2.3.4 https://example.invalid:99999')), [])
        values = set(addresses('example.invalid:443 [2001:db8::1]:443 2001:db8::2'))
        self.assertIn('example.invalid:443', values)
        self.assertIn('[2001:db8::1]:443', values)
        self.assertIn('2001:db8::2', values)

    def test_ipv6_and_repeated_evidence(self):
        result = self.report({'addresses.txt':'[2001:db8::1]:443 2001:db8::2 https://[2001:db8::3]:443/a'})
        self.assertTrue({'2001:db8::1','2001:db8::2','2001:db8::3'}.issubset({r.get('host') for r in result['endpoints']}))
        data = self.report({'Login.smali':LOGIN.replace('    return-void', '    invoke-static {}, Lsample/Transport;->send()V\n'*20 + '    return-void'),'Builder.smali':BUILDER,'Transport.smali':TRANSPORT})
        self.assertTrue(all(i['score']<=58 for category in data['protocol_report'] if isinstance(data['protocol_report'][category],list) for i in data['protocol_report'][category] if 'score' in i))
