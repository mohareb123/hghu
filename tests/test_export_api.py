import http.client
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
import zipfile

from protohunter.analyzer import analyze
from protohunter.web import Server
from test_projects import zip_bytes


class ExportAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.server = Server(('127.0.0.1', 0), allow_decoders=True, desktop_tools=True, projects_root=Path(cls.tmp.name, 'projects'))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()
        cls.report = analyze(Path(__file__).resolve().parents[1] / 'protohunter/demo.smali')

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(); cls.tmp.cleanup()

    def request(self, body, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        conn.request('POST', '/api/export-sections', json.dumps(body).encode(), {'Content-Type':'application/json', **(headers or {})})
        response = conn.getresponse(); code, data, headers = response.status, response.read(), dict(response.getheaders()); conn.close()
        return code, data, headers

    def check_zip(self, response):
        code, data, headers = response
        self.assertEqual(code, 200, data[:500]); self.assertEqual(headers['Content-Type'], 'application/zip')
        self.assertIn('attachment;', headers['Content-Disposition'])
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertIn('protocol.json', archive.namelist()); self.assertIn('server.txt', archive.namelist())
            return json.loads(archive.read('index.json'))

    def test_report_fallback_and_validation(self):
        index = self.check_zip(self.request({'report':self.report}))
        self.assertEqual(index['input'], self.report['input'])
        self.assertEqual(self.request({'report':[]})[0], 400)
        self.assertEqual(self.request({'report':self.report}, {'Origin':'https://evil.example'})[0], 403)
        self.assertEqual(self.request({'report':self.report}, {'Content-Type':'text/plain'})[0], 415)

    def test_existing_job_export_and_expired_job(self):
        file = Path(self.tmp.name, 'input.txt'); file.write_text('https://example.invalid')
        self.server.analysis_lock.acquire()
        job = self.server.start_job(file, file.name, {})
        job.thread.join(5)
        self.check_zip(self.request({'job':job.id}))
        job.private = True
        self.assertEqual(self.request({'job':job.id})[0], 403)
        self.check_zip(self.request({'job':job.id}, {'X-ProtoHunter-Config-Token':self.server.config_token}))
        job.status = 'running'
        self.assertEqual(self.request({'job':job.id}, {'X-ProtoHunter-Config-Token':self.server.config_token})[0], 409)
        job.status = 'completed'
        self.assertEqual(self.request({'job':'missing'})[0], 404)

    def test_private_project_and_exact_run_export(self):
        apk = Path(self.tmp.name, 'game.apk'); apk.write_bytes(zip_bytes({'config.txt':'https://original.example.invalid'}))
        store = self.server.projects; project = store.create(apk)
        data = store.run(project['id'], 'inspect'); run = data['runs'][-1]
        self.assertTrue(store.safe(project['id'], run['sections'] + '/server.json').is_file())
        body = {'project':project['id'], 'run':run['id']}
        self.assertEqual(self.request(body)[0], 403)
        headers = {'X-ProtoHunter-Config-Token':self.server.config_token}
        first = self.check_zip(self.request(body, headers))
        second = store.run(project['id'], 'inspect')['runs'][-1]
        report_path = store.safe(project['id'], second['path'] + '/report.json')
        newer = json.loads(report_path.read_text(encoding='utf-8'))
        newer['input']['name'] = 'different later report'
        report_path.write_text(json.dumps(newer), encoding='utf-8')
        self.assertEqual(self.check_zip(self.request(body, headers))['input'], first['input'])
        self.assertEqual(self.check_zip(self.request({**body, 'run':second['id']}, headers))['input']['name'], 'different later report')
        self.assertEqual(self.request(body, {**headers, 'Host':'preview.e2b.app'})[0], 403)
        self.assertEqual(self.request({**body, 'run':'../../escape'}, headers)[0], 400)

    def test_size_limit_releases_export_slot(self):
        from protohunter.export_api import MAX_REPORT
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        conn.request('POST', '/api/export-sections', '{}', {'Content-Type':'application/json', 'Content-Length':str(MAX_REPORT + 1)})
        response = conn.getresponse(); self.assertEqual(response.status, 400); response.read(); conn.close()
        self.check_zip(self.request({'report':self.report}))

    def test_busy_export_does_not_block_analysis_slot(self):
        self.server.export_lock.acquire()
        try:
            self.assertEqual(self.request({'report':self.report})[0], 429)
            self.assertTrue(self.server.analysis_lock.acquire(False)); self.server.analysis_lock.release()
        finally:
            self.server.export_lock.release()
