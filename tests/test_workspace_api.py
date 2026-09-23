import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from protohunter.web import Server
from test_projects import FakeConfig, zip_bytes


class WorkspaceAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.source = cls.root / 'sample.apk'; cls.source.write_bytes(zip_bytes({'config.txt': 'https://example.invalid'}))
        cls.server = Server(('127.0.0.1', 0), allow_decoders=True, desktop_tools=True, projects_root=cls.root / 'projects')
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(); cls.temp.cleanup()

    def request(self, method, path, body=None, token=True, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        hdr = {'Content-Type': 'application/json' if path == '/api/workspace' else 'application/octet-stream'}
        if token:
            hdr['X-ProtoHunter-Config-Token'] = self.server.config_token
        hdr.update(headers or {})
        conn.request(method, path, json.dumps(body).encode() if body is not None else b'', hdr)
        response = conn.getresponse(); code = response.status; data = json.loads(response.read()); conn.close()
        return code, data

    def job(self, body):
        code, accepted = self.request('POST', '/api/workspace', body)
        self.assertEqual(code, 202, accepted)
        job = self.server.get_job(accepted['job_id']); job.thread.join(5)
        self.assertFalse(job.thread.is_alive())
        self.assertEqual(job.status, 'completed', job.error)
        return job

    def test_private_import_job_and_persistent_listing(self):
        with patch('protohunter.workspace_api.choose_file', return_value=str(self.source)):
            job = self.job({'action': 'create', 'path': '/must/not/be/used.apk'})
        self.assertTrue(job.private)
        self.assertEqual(self.request('GET', '/api/jobs/' + job.id, token=False)[0], 403)
        self.assertEqual(self.request('GET', '/api/jobs/' + job.id + '/result', token=False)[0], 403)
        self.assertEqual(self.request('POST', '/api/jobs/' + job.id + '/cancel', token=False)[0], 403)
        self.assertEqual(self.request('GET', '/api/jobs/' + job.id + '/result')[1]['name'], self.source.name)
        code, data = self.request('POST', '/api/workspace', {'action': 'list'})
        self.assertEqual(code, 200)
        self.assertIn(job.report['id'], [p['id'] for p in data['projects']])

    def test_token_host_origin_and_no_mutation_on_denial(self):
        with patch('protohunter.workspace_api.choose_file') as picker:
            for headers, token in [({}, False), ({'Host':'preview.e2b.app'}, True), ({'Origin':'https://evil.example'}, True)]:
                self.assertEqual(self.request('POST', '/api/workspace', {'action':'create'}, token=token, headers=headers)[0], 403)
            picker.assert_not_called()

    def test_workspace_decode_save_build_and_report(self):
        project = self.server.projects.create(self.source); project_id = project['id']
        with patch.object(self.server, 'tool_config', FakeConfig()):
            job = self.job({'action':'run', 'project':project_id, 'operation':'apktool', 'unit':'main'})
            path = job.report['decoded']['main'] + '/Example.smali'
            code, file = self.request('POST', '/api/workspace', {'action':'read', 'project':project_id, 'path':path})
            self.assertEqual(code, 200)
            code, edited = self.request('POST', '/api/workspace', {'action':'save', 'project':project_id, 'path':path,
                'text':file['text']+'# edited', 'sha256':file['sha256']})
            self.assertEqual(code, 200, edited)
            self.job({'action':'run', 'project':project_id, 'operation':'build', 'unit':'main'})
            self.job({'action':'run', 'project':project_id, 'operation':'inspect', 'unit':'main'})
        code, report = self.request('POST', '/api/workspace', {'action':'report', 'project':project_id, 'unit':'main'})
        self.assertEqual(code, 200)
        self.assertTrue(report['research'])

    def test_invalid_paths_and_busy(self):
        project = self.server.projects.create(self.source)
        for action in ('read', 'save'):
            code, _ = self.request('POST', '/api/workspace', {'action':action, 'project':project['id'], 'path':'runs/../../etc/passwd', 'text':'bad'})
            self.assertEqual(code, 400)
        self.server.analysis_lock.acquire()
        try:
            self.assertEqual(self.request('POST', '/api/workspace', {'action':'list'})[0], 429)
        finally:
            self.server.analysis_lock.release()

    def test_disable_decoders_prevents_project_tool_execution(self):
        project = self.server.projects.create(self.source)
        with patch.object(self.server, 'allow_decoders', False):
            self.assertEqual(self.request('POST', '/api/workspace', {'action':'run', 'project':project['id'], 'operation':'apktool'})[0], 400)
