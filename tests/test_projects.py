import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from protohunter.projects import ProjectStore, MAX_TEXT
from protohunter.runtime import AnalysisCancelled
from protohunter.tooling import ToolConfig


def zip_bytes(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return out.getvalue()


class FakeConfig:
    def __init__(self, mode=None):
        self.mode = mode

    def command(self, tool):
        return [sys.executable, str(Path(__file__).with_name('fixture_engine.py').resolve()), self.mode or tool]


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.store = ProjectStore(self.base / 'projects')
        self.source = self.base / 'game.apk'
        self.source.write_bytes(zip_bytes({'assets/config.txt': 'https://login.example.invalid',
            'lib/arm64-v8a/libil2cpp.so': b'\x7fELFfake', 'assets/bin/Data/Managed/Metadata/global-metadata.dat': b'fake metadata'}))
        self.data = self.store.create(self.source)
        self.id = self.data['id']

    def tearDown(self):
        self.temp.cleanup()

    def decode(self):
        data = self.store.run(self.id, 'apktool', config=FakeConfig())
        return data['decoded']['main'] + '/Example.smali'

    def test_full_pipeline_edit_inspect_build_sign_preserves_original(self):
        original = self.source.read_bytes(); path = self.decode()
        self.store.run(self.id, 'jadx', config=FakeConfig())
        candidates = self.store.candidates(self.id)
        data = self.store.run(self.id, 'il2cpp', config=FakeConfig(), binary=candidates['binaries'][0], metadata=candidates['metadata'][0])
        dump = data['runs'][-1]['path'] + '/il2cpp/dump.cs'
        self.assertFalse(self.store.read(self.id, dump)['editable'])
        current = self.store.read(self.id, path)
        content = current['text'].replace('CSMajorLoginReq', 'CSMajorLoginResp')
        diff = self.store.edit(self.id, path, content, current['sha256'], preview=True)
        self.assertIn('+', diff['diff'])
        self.store.edit(self.id, path, content, current['sha256'])
        data = self.store.run(self.id, 'inspect')
        report = json.loads(self.store.safe(self.id, data['runs'][-1]['path'] + '/report.json').read_text())
        self.assertEqual(report['input']['derived_views'], ['jadx', 'il2cpp'])
        self.assertTrue(any(r['target'] == 'CSMajorLoginResp' for r in report['research']))
        self.assertTrue(any(r['source'].startswith('il2cpp/') for r in report['research']))
        data = self.store.run(self.id, 'build', config=FakeConfig())
        artifact = self.store.safe(self.id, data['runs'][-1]['artifact'])
        with zipfile.ZipFile(artifact) as archive:
            self.assertIn(b'CSMajorLoginResp', archive.read('fixture-smali.txt'))
        key = self.base / 'own-key.jks'; key.touch()
        data = self.store.run(self.id, 'sign', config=FakeConfig(), keystore=str(key), alias='own', store_pass='do-not-store-this', key_pass='nor-this')
        self.assertEqual(data['runs'][-1]['status'], 'completed')
        self.assertTrue(self.store.safe(self.id, data['runs'][-1]['artifact']).is_file())
        manifest = self.store.safe(self.id, 'project.json').read_text()
        self.assertNotIn('do-not-store-this', manifest); self.assertNotIn('nor-this', manifest)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(self.store.safe(self.id, 'input/source.apk').read_bytes(), original)

    def test_edit_conflict_backup_restore_and_history(self):
        path = self.decode(); old = self.store.read(self.id, path)
        current = self.store.edit(self.id, path, old['text'] + '# change\n', old['sha256'])
        with self.assertRaisesRegex(ValueError, 'changed since opening'):
            self.store.edit(self.id, path, old['text'], old['sha256'])
        change = self.store.load(self.id)['changes'][-1]
        restored = self.store.restore(self.id, change['id'], current['sha256'])
        self.assertEqual(restored['text'], old['text'])
        self.assertEqual(len(self.store.load(self.id)['changes']), 2)

    def test_readonly_and_size_limits(self):
        data = self.store.run(self.id, 'jadx', config=FakeConfig())
        path = data['runs'][-1]['path'] + '/jadx/Example.java'
        value = self.store.read(self.id, path)
        with self.assertRaisesRegex(ValueError, 'read-only'):
            self.store.edit(self.id, path, value['text'], value['sha256'])
        editable = self.decode(); target = self.store.safe(self.id, editable)
        target.write_bytes(b'A' * (MAX_TEXT + 1))
        value = self.store.read(self.id, editable)
        self.assertTrue(value['truncated']); self.assertFalse(value['editable'])

    def test_traversal_absolute_windows_ads_and_symlinks(self):
        for path in ('../outside', '/etc/passwd', 'runs/../../outside', 'C:/Windows/test', 'runs/a:secret', 'runs\\..\\x'):
            with self.assertRaises(ValueError):
                self.store.safe(self.id, path)
        with self.assertRaises(ValueError):
            self.store.path('../other')
        outside = self.base / 'outside.txt'; outside.write_text('secret')
        link = self.store.path(self.id) / 'runs' / 'link.txt'
        try:
            link.symlink_to(outside)
        except OSError:
            return  # Windows may deny symlink creation without developer/admin rights.
        with self.assertRaises(ValueError):
            self.store.read(self.id, 'runs/link.txt')
        self.assertFalse(any(f['path'].endswith('link.txt') for f in self.store.files(self.id)['files']))

    def test_bundle_uses_generated_paths_and_cross_split_unity(self):
        bundle = self.base / 'game.xapk'
        bundle.write_bytes(zip_bytes({'../../base.apk': zip_bytes({'assets/global-metadata.dat': b'meta'}),
                                      'split-arm64.apk': zip_bytes({'lib/arm64-v8a/libil2cpp.so': b'ELF'})}))
        data = self.store.create(bundle); self.assertEqual(len(data['units']), 2)
        self.assertFalse((self.base / 'base.apk').exists())
        candidates = self.store.candidates(data['id'])
        self.assertNotEqual(candidates['binaries'][0]['unit'], candidates['metadata'][0]['unit'])
        data = self.store.run(data['id'], 'il2cpp', data['units'][1]['id'], FakeConfig(),
                              binary=candidates['binaries'][0], metadata=candidates['metadata'][0])
        self.assertEqual(data['runs'][-1]['status'], 'completed')

    def test_cancel_import_removes_only_new_project(self):
        before = len(self.store.list())
        with self.assertRaises(AnalysisCancelled):
            self.store.create(self.source, cancel=lambda: True)
        self.assertEqual(len(self.store.list()), before)
        self.assertTrue(self.source.exists())

    def test_failure_and_cancel_keep_logs_not_completed_decode(self):
        with self.assertRaisesRegex(ValueError, 'code 7'):
            self.store.run(self.id, 'apktool', config=FakeConfig('fail'))
        data = self.store.load(self.id)
        self.assertEqual(data['runs'][-1]['status'], 'failed'); self.assertFalse(data['decoded'])
        events = []
        with self.assertRaises(AnalysisCancelled):
            self.store.run(self.id, 'apktool', config=FakeConfig('wait'), progress=events.append, cancel=lambda: bool(events))
        data = self.store.load(self.id)
        self.assertEqual(data['runs'][-1]['status'], 'cancelled')
        self.assertTrue(self.store.safe(self.id, data['runs'][-1]['path'] + '/step-00.log').exists())

    def test_os_lock_and_reopen_persistence(self):
        with self.store.locked(self.id):
            with self.assertRaisesRegex(ValueError, 'busy'):
                with ProjectStore(self.store.root).locked(self.id):
                    pass
        self.assertEqual(ProjectStore(self.store.root).load(self.id)['input'], self.data['input'])

    def test_search_and_stale_signature(self):
        path = self.decode()
        self.assertTrue(self.store.search(self.id, 'CSMajor')['hits'])
        self.store.run(self.id, 'build', config=FakeConfig())
        current = self.store.read(self.id, path)
        self.store.edit(self.id, path, current['text']+'# edited', current['sha256'])
        with self.assertRaisesRegex(ValueError, 'rebuild'):
            self.store.run(self.id, 'sign', config=FakeConfig())

    def test_tool_commands_for_jadx_distribution_and_dotnet_dll(self):
        java = self.base / 'java.exe'; java.touch()
        jadx = self.base / 'jadx'; (jadx / 'lib').mkdir(parents=True); (jadx / 'lib/core.jar').touch()
        dll = self.base / 'Il2CppDumper.dll'; dll.touch()
        dotnet = self.base / 'dotnet.exe'; dotnet.touch()
        config = ToolConfig(java=str(java), jadx=str(jadx), il2cpp=str(dll), dotnet=str(dotnet))
        self.assertEqual(config.command('jadx'), [str(java), '-cp', str(jadx.resolve() / 'lib/*'), 'jadx.cli.JadxCLI'])
        self.assertEqual(config.command('il2cpp'), [str(dotnet), str(dll.resolve())])
        with patch('protohunter.tooling.shutil.which', return_value=None):
            with self.assertRaisesRegex(ValueError, '.NET'):
                ToolConfig(il2cpp=str(dll)).command('il2cpp')
