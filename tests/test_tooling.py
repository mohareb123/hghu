import itertools
import sys
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from protohunter.analyzer import Analyzer
from protohunter.runtime import AnalysisCancelled, stop_decoder
from protohunter.tooling import ToolConfig


class ToolingTests(unittest.TestCase):
    def test_jar_java_paths_with_spaces_and_settings_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp, 'apk tool.jar'); jar.touch()
            java = Path(tmp, 'java executable.exe'); java.touch()
            config = ToolConfig(str(jar), str(java))
            self.assertEqual(config.command('apktool'), [str(java), '-jar', str(jar.resolve())])
            target = Path(tmp, 'settings.json'); config.save(target)
            self.assertEqual(ToolConfig.load(target), config)
            self.assertTrue(config.status()['apktool'])
            self.assertNotIn('java_path', config.status())
            self.assertEqual(config.status(private=True)['java_path'], str(java))

    def test_missing_java_jar_and_invalid_settings(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True), patch('protohunter.tooling.shutil.which', return_value=None), patch('protohunter.tooling.app_directory', return_value=Path(tmp)):
            jar = Path(tmp, 'apktool.jar'); jar.touch()
            config = ToolConfig(str(jar))
            self.assertFalse(config.status()['apktool'])
            with self.assertRaisesRegex(ValueError, 'needs Java'):
                config.command('apktool')
            with self.assertRaisesRegex(ValueError, 'not found'):
                ToolConfig(str(jar) + 'missing').command('apktool')
            with self.assertRaisesRegex(ValueError, 'existing .jar'):
                ToolConfig(str(jar) + 'missing').save(Path(tmp, 'settings.json'))
            broken = Path(tmp, 'broken.json'); broken.write_text('[]')
            self.assertEqual(ToolConfig.load(broken), ToolConfig())

    def test_adjacent_jar_and_portable_java_discovery(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True), patch('protohunter.tooling.shutil.which', return_value=None), patch('protohunter.tooling.app_directory', return_value=Path(tmp)):
            jar = Path(tmp, 'tools/apktool.jar'); jar.parent.mkdir(); jar.touch()
            java = Path(tmp, 'tools/java/bin/java.exe'); java.parent.mkdir(parents=True); java.touch()
            self.assertEqual(ToolConfig().command('apktool'), [str(java), '-jar', str(jar.resolve())])

    def test_probe_timeout_and_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp, 'apktool.jar'); jar.touch()
            java = Path(tmp, 'java.exe'); java.touch()
            config = ToolConfig(str(jar), str(java))
            with patch('protohunter.tooling.subprocess.run', side_effect=[subprocess.TimeoutExpired('java', 12), subprocess.CompletedProcess([], 1)]):
                results = config.probe()
            self.assertEqual([r['ok'] for r in results], [False, False])

    def test_decoder_uses_jar_command_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp, 'apktool.jar'); jar.touch()
            java = Path(tmp, 'java.exe'); java.touch()
            source = Path(tmp, 'game.apk'); source.touch()
            analyzer = Analyzer(tool_config=ToolConfig(str(jar), str(java)))
            with patch('protohunter.analyzer.subprocess.Popen') as popen:
                popen.return_value.poll.return_value = 2
                popen.return_value.returncode = 2
                analyzer.decode(source, 'apktool')
                self.assertEqual(popen.call_args.args[0][:3], [str(java), '-jar', str(jar.resolve())])
                self.assertFalse(popen.call_args.kwargs.get('shell', False))
            self.assertTrue(any('exited with code 2' in w for w in analyzer.report['warnings']))

    def test_decoder_cancel_stops_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            java = Path(tmp, 'java.exe'); java.touch()
            jar = Path(tmp, 'apktool.jar'); jar.touch()
            cancelled = [False]
            analyzer = Analyzer(tool_config=ToolConfig(str(jar), str(java)), cancel=lambda: cancelled[0])
            with patch('protohunter.analyzer.subprocess.Popen') as popen, patch('protohunter.analyzer.stop_decoder') as stop:
                def poll():
                    cancelled[0] = True
                    return None
                popen.return_value.poll.side_effect = poll
                with self.assertRaises(AnalysisCancelled):
                    analyzer.decode(Path(tmp, 'game.apk'), 'apktool')
                stop.assert_called()

    def test_process_stop_terminates_real_child(self):
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
            start_new_session=os.name != 'nt', creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
        try:
            stop_decoder(process)
            self.assertIsNotNone(process.poll())
        finally:
            if process.poll() is None:
                process.kill(); process.wait()

    def test_decoder_timeout_and_fast_resource_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            java = Path(tmp, 'java.exe'); java.touch()
            jar = Path(tmp, 'apktool.jar'); jar.touch()
            analyzer = Analyzer(scan_mode='fast', tool_config=ToolConfig(str(jar), str(java)))
            with patch('protohunter.analyzer.subprocess.Popen') as popen, patch('protohunter.analyzer.stop_decoder') as stop, patch('protohunter.analyzer.time.monotonic', side_effect=itertools.count(step=200)):
                popen.return_value.poll.return_value = None
                def stopped(process):
                    process.poll.return_value = 0
                    process.returncode = 0
                stop.side_effect = stopped
                analyzer.decode(Path(tmp, 'game.apk'), 'apktool')
                self.assertIn('-r', popen.call_args.args[0])
                stop.assert_called_once()
            self.assertTrue(any('180 seconds' in w for w in analyzer.report['warnings']))
