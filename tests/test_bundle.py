import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from protohunter.bundle import metadata, verify
from protohunter.tooling import ToolConfig
from packaging_import_helper import load_packaging_module


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.files = {}
        for name in ('tools/apktool.jar', 'tools/java/bin/java.exe', 'tools/jadx/lib/core.jar', 'tools/il2cpp/Il2CppDumper.exe'):
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'fixture')
            self.files[name] = hashlib.sha256(b'fixture').hexdigest()
        self.manifest = self.root / 'bundle-manifest.json'
        self.manifest.write_text(json.dumps({'schema':1, 'versions':{'test':'fixture'}, 'files':self.files}))
        self.settings = self.root / 'settings.json'
        self.patches = [patch('protohunter.tooling.app_directory', return_value=self.root),
                        patch('protohunter.tooling.settings_path', return_value=self.settings),
                        patch('protohunter.tooling.shutil.which', return_value=None),
                        patch.dict(os.environ, {}, clear=True)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def test_all_three_discovered_with_no_path_java_or_dotnet(self):
        config = ToolConfig.load()
        self.assertEqual(config.command('apktool'), [str(self.root / 'tools/java/bin/java.exe'), '-jar', str(self.root / 'tools/apktool.jar')])
        self.assertEqual(config.command('jadx')[-1], 'jadx.cli.JadxCLI')
        self.assertEqual(config.command('il2cpp'), [str(self.root / 'tools/il2cpp/Il2CppDumper.exe')])
        self.assertTrue(config.status()['bundle']['ready'])
        self.assertNotIn('java_path', config.status())

    def test_old_absolute_settings_migrate_without_losing_optional_signing_paths(self):
        self.settings.write_text(json.dumps({'java':'Z:/missing/java.exe','jadx':'Z:/missing/jadx','apksigner':'preserved.jar'}))
        config = ToolConfig.load()
        self.assertEqual(config.java, '')
        self.assertEqual(config.apksigner, 'preserved.jar')
        self.assertTrue(config.status()['bundle']['ready'])

    def test_manual_override_is_retained_but_reset_restores_portability(self):
        custom = self.root / 'custom.jar'; custom.touch()
        config = ToolConfig(apktool_jar=str(custom))
        config.save()
        self.assertEqual(ToolConfig.load().apktool_jar, str(custom))
        self.assertFalse(ToolConfig.load().status()['bundle']['ready'])
        config.save(prefer_bundled=True)
        self.assertEqual(ToolConfig.load().apktool_jar, '')
        self.assertTrue(ToolConfig.load().status()['bundle']['ready'])

    def test_hash_verification_detects_changed_and_missing_files(self):
        self.assertTrue(verify(self.root)['ok'])
        (self.root / 'tools/apktool.jar').write_bytes(b'modified')
        (self.root / 'tools/java/bin/java.exe').unlink()
        result = verify(self.root)
        self.assertFalse(result['ok'])
        self.assertEqual(len(result['errors']), 2)
        self.assertFalse(ToolConfig().status()['bundle']['ready'])

    def test_manifest_rejects_escape_and_empty_hash_set(self):
        self.manifest.write_text(json.dumps({'schema':1,'files':{'../outside': 'bad'}}))
        self.assertIn('Unsafe', verify(self.root)['errors'][0])
        self.manifest.write_text(json.dumps({'schema':1,'files':{}}))
        self.assertFalse(verify(self.root)['ok'])
        self.manifest.write_text('[]')
        self.assertEqual(metadata(self.root), {})

    def test_build_extraction_rejects_traversal(self):
        builder = load_packaging_module('bundle_windows')
        archive = self.root / 'bad.zip'
        with zipfile.ZipFile(archive,'w') as stream:
            stream.writestr('../escape.txt','bad')
        with self.assertRaisesRegex(ValueError,'Unsafe'):
            builder.extract(archive, self.root / 'extracted')
        self.assertFalse((self.root / 'escape.txt').exists())

    def test_download_rejects_checksum_before_publishing(self):
        import io
        builder = load_packaging_module('bundle_windows')
        asset = {'url':'https://example.invalid/test', 'filename':'tool.jar', 'sha256':'0'*64}
        with patch.object(builder.urllib.request, 'urlopen', side_effect=lambda *a,**k: io.BytesIO(b'wrong')), patch.object(builder.time, 'sleep'):
            with self.assertRaisesRegex(ValueError,'SHA-256'):
                builder.download(asset, self.root)
        self.assertFalse((self.root / 'tool.jar').exists())
        self.assertFalse((self.root / 'tool.part').exists())
