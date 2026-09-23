import hashlib
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from protohunter.runtime import AnalysisCancelled
from protohunter.tooling import ToolConfig
from protohunter.web import Server


class JobTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server(('127.0.0.1', 0), allow_decoders=True, desktop_tools=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def request(self, method, path, body=b'', headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        headers = {'Content-Type': 'application/octet-stream', **(headers or {})}
        conn.request(method, path, body, headers)
        response = conn.getresponse(); status, data = response.status, json.loads(response.read())
        conn.close()
        return status, data

    def desktop(self, path, body, headers=None):
        return self.request('POST', path, json.dumps(body).encode(), {
            'Content-Type': 'application/json', 'X-ProtoHunter-Config-Token': self.server.config_token, **(headers or {})})

    def await_job(self, accepted):
        job = self.server.get_job(accepted['job_id'])
        job.thread.join(timeout=5)
        self.assertFalse(job.thread.is_alive())
        return job

    def test_upload_async_progress_hash_and_result(self):
        content = b'https://login.example.invalid/\nTCP'
        status, accepted = self.request('POST', '/api/jobs?name=test.txt&scan_mode=fast', content)
        self.assertEqual(status, 202)
        job = self.await_job(accepted)
        self.assertEqual(job.status, 'completed')
        status, progress = self.request('GET', '/api/jobs/' + job.id)
        self.assertEqual(progress['status'], 'completed')
        status, result = self.request('GET', '/api/jobs/' + job.id + '/result')
        self.assertEqual(status, 200)
        self.assertEqual(result['input']['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(result['input']['scan_mode'], 'fast')

    def test_cancel_busy_progress_and_upload_cleanup(self):
        entered = threading.Event(); targets = []
        def analyze(target, **kwargs):
            targets.append(target)
            kwargs['progress']({'stage': 'scanning', 'file': 'a.txt', 'files_scanned': 7})
            entered.set()
            if not kwargs['cancel']():
                # Event.wait instead of busy-looping; the API supplies this bound method.
                kwargs['cancel'].__self__.wait(3)
            raise AnalysisCancelled()
        with patch('protohunter.web.analyze', side_effect=analyze):
            status, accepted = self.request('POST', '/api/jobs?name=a.txt', b'hello')
            self.assertEqual(status, 202)
            self.assertTrue(entered.wait(2))
            status, state = self.request('GET', '/api/jobs/' + accepted['job_id'])
            self.assertEqual(state['progress']['files_scanned'], 7)
            self.assertEqual(self.request('GET', '/api/jobs/' + accepted['job_id'] + '/result')[0], 409)
            self.assertEqual(self.request('POST', '/api/jobs?name=b.txt', b'a')[0], 429)
            self.assertEqual(self.request('POST', '/api/jobs/' + accepted['job_id'] + '/cancel')[0], 200)
            job = self.await_job(accepted)
        self.assertEqual(job.status, 'cancelled')
        self.assertFalse(targets[0].exists())
        self.assertTrue(self.server.analysis_lock.acquire(blocking=False))
        self.server.analysis_lock.release()

    def test_worker_error_releases_slot_and_cleans_temp(self):
        paths = []
        def fail(target, **kwargs):
            paths.append(target); raise ValueError('bad archive')
        with patch('protohunter.web.analyze', side_effect=fail):
            _, accepted = self.request('POST', '/api/jobs?name=a.apk', b'bad')
            job = self.await_job(accepted)
        self.assertEqual(job.status, 'failed')
        self.assertEqual(job.error, 'bad archive')
        self.assertFalse(paths[0].exists())
        self.assertTrue(self.server.analysis_lock.acquire(blocking=False))
        self.server.analysis_lock.release()

    def test_jobs_bounded_and_expired(self):
        for _ in range(4):
            _, accepted = self.request('POST', '/api/jobs?name=a.txt', b'hello')
            job = self.await_job(accepted)
        self.assertLessEqual(len(self.server.jobs), 2)
        job.finished -= 3601
        self.assertEqual(self.request('GET', '/api/jobs/' + job.id)[0], 404)

    def test_invalid_options_do_not_lock_server(self):
        self.assertEqual(self.request('POST', '/api/jobs?name=a.apk&scan_mode=nope', b'')[0], 400)
        self.assertTrue(self.server.analysis_lock.acquire(blocking=False)); self.server.analysis_lock.release()

    def test_token_and_host_security(self):
        _, state = self.request('GET', '/api/status')
        self.assertTrue(state['desktop_tools'])
        self.assertEqual(state['config_token'], self.server.config_token)
        _, public = self.request('GET', '/api/status', headers={'Host':'8765-preview.e2b.app'})
        self.assertFalse(public['desktop_tools']); self.assertIsNone(public['config_token'])
        self.assertNotIn('java_path', public['tools'])
        with patch('protohunter.web.choose_file') as picker, patch.object(ToolConfig, 'probe') as probe:
            self.assertEqual(self.desktop('/api/tools', {}, {'X-ProtoHunter-Config-Token':'wrong'})[0], 403)
            self.assertEqual(self.desktop('/api/local-file', {}, {'Host':'evil.example'})[0], 403)
            self.assertEqual(self.desktop('/api/choose-tool', {}, {'Origin':'https://evil.example'})[0], 403)
            picker.assert_not_called(); probe.assert_not_called()

    def test_desktop_cannot_bind_publicly(self):
        with self.assertRaisesRegex(ValueError, 'loopback'):
            Server(('0.0.0.0', 0), desktop_tools=True)

    def test_settings_validation_and_probe(self):
        with tempfile.TemporaryDirectory() as tmp, patch('protohunter.tooling.settings_path', return_value=Path(tmp, 'settings.json')), patch.object(ToolConfig, 'probe', return_value=[{'tool':'Java', 'ok':True, 'output':'test'}]):
            self.assertEqual(self.desktop('/api/tools', {'java':[]})[0], 400)
            status, value = self.desktop('/api/tools', {})
            self.assertEqual(status, 200)
            self.assertTrue(Path(tmp, 'settings.json').is_file())
            self.assertTrue(value['checks'][0]['ok'])

    def test_local_input_only_uses_native_selection_not_request_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'local.txt'); path.write_text('https://login.example.invalid')
            with patch('protohunter.web.choose_file', return_value=str(path)) as picker:
                status, accepted = self.desktop('/api/local-file?scan_mode=deep', {'path':'/not/accepted'})
                picker.assert_called_once_with('input')
            self.assertEqual(status, 202)
            self.assertTrue(accepted['local'])
            job = self.await_job(accepted)
            self.assertEqual(job.status, 'completed')
            self.assertTrue(path.exists())
            self.assertEqual(job.report['input']['name'], 'local.txt')

    def test_cancel_native_dialog_does_not_start_job(self):
        with patch('protohunter.web.choose_file', return_value=None):
            status, response = self.desktop('/api/local-file', {})
        self.assertEqual(status, 200); self.assertTrue(response['cancelled'])
        self.assertTrue(self.server.analysis_lock.acquire(blocking=False)); self.server.analysis_lock.release()

    @unittest.skipUnless(os.name == 'nt', 'Windows native structure')
    def test_native_dialog_structure_on_windows(self):
        import ctypes
        from protohunter.dialogs import choose_file
        with patch('ctypes.WinDLL') as library:
            library.return_value.GetOpenFileNameW.return_value = 0
            library.return_value.CommDlgExtendedError.return_value = 0
            self.assertIsNone(choose_file('apktool'))
            spec = library.return_value.GetOpenFileNameW.call_args.args[0]._obj
            self.assertEqual(spec.lStructSize, 152 if ctypes.sizeof(ctypes.c_void_p) == 8 else 88)
            self.assertEqual(spec.nMaxFile, 32768)
