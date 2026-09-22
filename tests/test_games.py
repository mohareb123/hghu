"""Synthetic game-package tests. No proprietary assets or live game traffic."""
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from protohunter.analyzer import Analyzer, analyze, profile_limits
from protohunter.formats import embedded_descriptors
from protohunter.native import elf_info, il2cpp_header, il2cpp_literals
from test_analyzer import sample_descriptor, sample_dex


def zip_bytes(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return output.getvalue()


def sample_elf(bits=64, endian='<'):
    """Minimal ELF with .dynstr, .dynsym and a DT_NEEDED dependency."""
    data = bytearray(1024)
    data[:7] = b'\x7fELF' + bytes([2 if bits == 64 else 1, 1 if endian == '<' else 2, 1])
    names = b'\0.shstrtab\0.dynstr\0.dynsym\0.dynamic\0'
    strings = b'\0SSL_connect\0google::protobuf::Message::SerializeToString\0libssl.so\0'
    data[64:64 + len(names)] = names
    data[128:128 + len(strings)] = strings
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                (1, 3, 0, 0, 64, len(names), 0, 0, 1, 0),
                (11, 3, 0, 0, 128, len(strings), 0, 0, 1, 0)]
    symbol_size = 24 if bits == 64 else 16
    for i, (name, defined) in enumerate([(1, False), (13, True)]):
        if bits == 64:
            struct.pack_into(endian + 'IBBHQQ', data, 256 + i * symbol_size, name, 18, 0, 1 if defined else 0, 0x1234 if defined else 0, 0)
        else:
            struct.pack_into(endian + 'IIIBBH', data, 256 + i * symbol_size, name, 0x1234 if defined else 0, 0, 18, 0, 1 if defined else 0)
    sections.append((19, 11, 0, 0, 256, 2 * symbol_size, 2, 0, 8, symbol_size))
    dynamic_format = endian + ('qQ' if bits == 64 else 'iI')
    dynamic_size = struct.calcsize(dynamic_format)
    struct.pack_into(dynamic_format, data, 320, 1, strings.index(b'libssl'))
    struct.pack_into(dynamic_format, data, 320 + dynamic_size, 0, 0)
    sections.append((27, 6, 0, 0, 320, 2 * dynamic_size, 2, 0, 8, dynamic_size))
    section_format = endian + ('IIQQQQIIQQ' if bits == 64 else 'IIIIIIIIII')
    section_size = struct.calcsize(section_format)
    for i, section in enumerate(sections):
        struct.pack_into(section_format, data, 512 + section_size * i, *section)
    header_format = endian + ('HHIQQQIHHHHHH' if bits == 64 else 'HHIIIIIHHHHHH')
    struct.pack_into(header_format, data, 16, 3, 183 if bits == 64 else 40, 1, 0, 0, 512, 0,
                     64 if bits == 64 else 52, 0, 0, section_size, 5, 1)
    return bytes(data)


def sample_metadata():
    literal = b'https://game.example.invalid/login'
    identifiers = b'Google.Protobuf\0NetworkClient\0'
    data = bytearray(512)
    struct.pack_into('<IIIIIIII', data, 0, 0xFAB11BAF, 29, 256, 8, 264, len(literal), 400, len(identifiers))
    struct.pack_into('<II', data, 256, len(literal), 0)
    data[264:264 + len(literal)] = literal
    data[400:400 + len(identifiers)] = identifiers
    return bytes(data)


class GameTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def file(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_elf_width_and_endianness(self):
        for bits in (32, 64):
            for endian in ('<', '>'):
                with self.subTest(bits=bits, endian=endian):
                    parsed = elf_info(sample_elf(bits, endian))
                    self.assertEqual(parsed['bits'], bits)
                    self.assertEqual(parsed['symbol_count'], 2)
                    self.assertEqual(parsed['needed_libraries'], ['libssl.so'])
                    self.assertEqual(parsed['network_symbols'][0]['role'], 'import')
                    self.assertEqual(parsed['network_symbols'][1]['role'], 'defined')
                    self.assertEqual(parsed['network_symbols'][0]['string_offset'], 129)

    def test_elf_out_of_bounds(self):
        data = bytearray(sample_elf())
        struct.pack_into('<Q', data, 40, len(data) * 2)
        with self.assertRaises(ValueError):
            elf_info(data)

    def test_sectionless_elf(self):
        data = bytearray(sample_elf())
        struct.pack_into('<Q', data, 40, 0)
        result = elf_info(data)
        self.assertFalse(result['symbols'])
        self.assertIn('No section table', result['notes'][0])

    def test_elf_invalid_symbol_size(self):
        data = bytearray(sample_elf())
        struct.pack_into('<Q', data, 512 + 3 * 64 + 56, 1)
        with self.assertRaisesRegex(ValueError, 'symbol size'):
            elf_info(data)

    def test_elf_analysis_markers(self):
        result = analyze(self.file('libnetwork.so', sample_elf()))
        self.assertEqual(result['native'][0]['elf']['architecture'], 'AArch64')
        self.assertIn('TLS', {x['value'] for x in result['protocols']})
        self.assertTrue(result['protobuf'])
        self.assertEqual(result['native'][0]['confidence'], 'high')

    def test_il2cpp_strings(self):
        data = sample_metadata()
        header = il2cpp_header(data)
        self.assertEqual(header['version'], 29)
        self.assertEqual(list(il2cpp_literals(data, header))[0][0], 264)
        result = analyze(self.file('global-metadata.dat', data))
        self.assertEqual(result['native'][0]['metadata']['literal_count'], 1)
        self.assertEqual(result['endpoints'][0]['host'], 'game.example.invalid')
        self.assertEqual(result['endpoints'][0]['offset'], 264)

    def test_il2cpp_rejects_custom_version(self):
        data = bytearray(sample_metadata())
        struct.pack_into('<I', data, 4, 99)
        result = analyze(self.file('global-metadata.dat', data))
        self.assertFalse(result['native'])
        self.assertTrue(any('Unsupported IL2CPP' in w for w in result['warnings']))

    def test_il2cpp_invalid_literal_range(self):
        data = bytearray(sample_metadata())
        struct.pack_into('<II', data, 256, 99999, 0)
        with self.assertRaisesRegex(ValueError, 'outside string data'):
            list(il2cpp_literals(data, il2cpp_header(data)))

    def test_il2cpp_invalid_header_range(self):
        data = bytearray(sample_metadata())
        struct.pack_into('<I', data, 16, 99999)
        with self.assertRaises(ValueError):
            il2cpp_header(data)

    def test_embedded_native_descriptor(self):
        from protohunter.formats import wire
        descriptor = wire(sample_descriptor())[1][0]
        data = sample_elf() + b'\xff\0' + descriptor + b'\0trailing data'
        candidates = list(embedded_descriptors(data))
        self.assertEqual(candidates[0][0], 1026)
        result = analyze(self.file('libmessages.so', data))
        found = [x for x in result['protobuf'] if x['kind'] == 'native descriptor candidate']
        self.assertEqual(found[0]['descriptor']['messages'][0]['name'], 'Event')
        self.assertEqual(found[0]['confidence'], 'medium')

    def test_bare_proto_filename_not_schema(self):
        self.assertEqual(list(embedded_descriptors(b'\x0a\x0bhello.proto\x00')), [])

    def test_xapk_multi_split_sources(self):
        base = zip_bytes({'classes.dex': sample_dex('https://game.example.invalid/login')})
        arm = zip_bytes({'lib/arm64-v8a/libil2cpp.so': sample_elf(), 'assets/global-metadata.dat': sample_metadata()})
        manifest = json.dumps({'package_name': 'test.synthetic.game', 'version_name': '1.0', 'split_apks': [{'file': 'base.apk'}, {'file': 'config.arm64.apk'}]}).encode()
        bundle = zip_bytes({'base.apk': base, 'config.arm64.apk': arm, 'manifest.json': manifest})
        result = analyze(self.file('game.xapk', bundle), profile='games')
        self.assertEqual(result['summary']['files_scanned'], 4)
        self.assertEqual(result['summary']['native_modules'], 2)
        self.assertTrue(any(x['kind'] == 'bundle manifest' for x in result['bundles']))
        self.assertTrue(any(x['source'].startswith('base.apk!') for x in result['endpoints']))
        server = result['servers'][0]
        self.assertEqual(len(server['sources']), 2)
        self.assertIn('authentication', server['role_hints'])
        self.assertEqual(server['role_hint_confidence'], 'low')

    def test_directory_of_splits(self):
        self.file('base.apk', zip_bytes({'classes.dex': sample_dex('https://game.example.invalid')}))
        self.file('config.apk', zip_bytes({'lib/libnet.so': sample_elf()}))
        result = analyze(self.root, profile='games')
        self.assertEqual(result['summary']['files_scanned'], 2)
        self.assertTrue(result['native'])

    def test_nested_depth_limit(self):
        data = zip_bytes({'server.txt': b'https://deep.example.invalid'})
        for i in range(5):
            data = zip_bytes({f'nested{i}.apk': data})
        result = analyze(self.file('deep.xapk', data))
        self.assertFalse(result['endpoints'])
        self.assertTrue(any('depth limit' in x for x in result['warnings']))

    def test_nested_archive_global_byte_budget(self):
        data = zip_bytes({'one.apk': zip_bytes({'a.txt': b'https://one.example.invalid'})})
        analyzer = Analyzer('games')
        analyzer.limits['expanded'] = 32
        result = analyzer.run(self.file('small.xapk', data))
        self.assertFalse(result['endpoints'])
        self.assertTrue(any('budget reached' in w for w in result['warnings']))

    def test_member_size_profiles(self):
        path = self.file('small.so', sample_elf())
        with patch('protohunter.analyzer.MAX_FILE', 100):
            standard = analyze(path)
            games = analyze(path, profile='games')
        self.assertFalse(standard['native'])
        self.assertTrue(games['native'])

    def test_obb_zip_and_raw(self):
        result = analyze(self.file('data.obb', zip_bytes({'a.txt': b'https://assets.example.invalid'})))
        self.assertEqual(result['summary']['unique_hosts'], 1)
        result = analyze(self.file('raw.obb', b'UnityFS\0https://assets.example.invalid'))
        self.assertEqual(result['summary']['unique_hosts'], 1)

    def test_unsafe_windows_name_and_symlink(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            archive.writestr('C:/bad.txt', 'https://unsafe.example.invalid')
            info = zipfile.ZipInfo('symlink.txt')
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, b'https://unsafe.example.invalid')
        result = analyze(self.file('unsafe.zip', output.getvalue()))
        self.assertFalse(result['endpoints'])
        self.assertEqual(len([w for w in result['warnings'] if 'Unsafe' in w]), 2)

    def test_smali_owner_context(self):
        content = b'.class public Lgame/Client;\n.method public login()V\n const-string v0, "https://login.example.invalid"\n.end method'
        result = analyze(self.file('Client.smali', content))
        self.assertEqual(result['endpoints'][0]['class_name'], 'Lgame/Client;')
        self.assertEqual(result['endpoints'][0]['method_name'], 'public login()V')
        self.assertEqual(result['servers'][0]['locations'][0]['method_name'], 'public login()V')

    def test_json_escaped_url(self):
        result = analyze(self.file('config.json', br'{"server":"https:\/\/game.example.invalid\/login"}'))
        self.assertEqual(result['endpoints'][0]['value'], 'https://game.example.invalid/login')

    def test_large_native_not_skipped_in_games(self):
        path = self.root / 'liblarge.so'
        with path.open('wb') as stream:
            stream.write(sample_elf())
            stream.seek(17 * 1024**2)
            stream.write(b'\0https://large.example.invalid\0')
        result = analyze(path, profile='games')
        self.assertEqual(result['summary']['files_scanned'], 1)
        self.assertTrue(result['native'])
        self.assertEqual(result['endpoints'][0]['host'], 'large.example.invalid')
        self.assertEqual(result['endpoints'][0]['offset'], 17 * 1024**2 + 1)

    def test_host_group_case_normalization(self):
        result = analyze(self.file('hosts.txt', b'API.EXAMPLE.COM\nhttps://api.example.com/login'))
        self.assertEqual(result['summary']['unique_hosts'], 1)
        self.assertEqual(result['servers'][0]['occurrences'], 2)

    def test_invalid_profile(self):
        with self.assertRaisesRegex(ValueError, 'Unknown'):
            profile_limits('unlimited')

    def test_nested_decoders_keep_source_prefix(self):
        bundle = self.file('game.xapk', zip_bytes({'base.apk': zip_bytes({'classes.dex': sample_dex('hi')})}))
        with patch.object(Analyzer, 'decode') as decode:
            analyze(bundle, 'both')
            self.assertEqual(decode.call_count, 1)
            self.assertEqual(decode.call_args.args[2], 'base.apk!')


if __name__ == '__main__':
    unittest.main()
