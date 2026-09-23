import http.client
import json
import threading
import unittest

from protohunter.web import Server


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server(('127.0.0.1', 0))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request(method, path, body, headers or {})
        response = conn.getresponse()
        status, data, headers = response.status, response.read(), dict(response.getheaders())
        conn.close()
        return status, data, headers

    def test_preview_host_accepted(self):
        status, data, headers = self.request('GET', '/', headers={'Host':'8765-sandbox.e2b.app'})
        self.assertEqual(status, 200)
        self.assertIn(b'ProtoHunter', data)
        self.assertNotIn('X-Frame-Options', headers)
        self.assertIn('Content-Security-Policy', headers)

    def test_status(self):
        status, data, _ = self.request('GET', '/api/status')
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(data)['allow_decoders'])

    def test_upload(self):
        status, data, _ = self.request('POST','/api/analyze?name=test.txt',b'https://example.com',{'Content-Type':'application/octet-stream'})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)['input']['name'],'test.txt')

    def test_demo(self):
        status, data, _ = self.request('POST','/api/demo',b'',{'Content-Type':'application/octet-stream'})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(data)['input']['demo'])

    def test_game_xapk_upload(self):
        from test_games import zip_bytes, sample_metadata
        data = zip_bytes({'config.apk': zip_bytes({'assets/global-metadata.dat': sample_metadata()})})
        status, body, _ = self.request('POST', '/api/analyze?name=game.xapk&profile=games', data, {'Content-Type': 'application/octet-stream'})
        self.assertEqual(status, 200)
        report = json.loads(body)
        self.assertEqual(report['input']['profile'], 'games')
        self.assertEqual(report['native'][0]['kind'], 'Unity metadata')

    def test_invalid_profile(self):
        status, _, _ = self.request('POST', '/api/analyze?name=x.xapk&profile=unlimited', b'', {'Content-Type': 'application/octet-stream'})
        self.assertEqual(status, 400)

    def test_game_input_limit(self):
        status, _, _ = self.request('POST', '/api/analyze?name=x.xapk&profile=games', b'', {'Content-Type': 'application/octet-stream', 'Content-Length': str(2 * 1024**3 + 1)})
        self.assertEqual(status, 413)





    def test_concurrent_request_is_busy(self):
        self.server.analysis_lock.acquire()
        try:
            status, _, _ = self.request('POST', '/api/demo', b'', {'Content-Type':'application/octet-stream'})
            self.assertEqual(status, 429)
        finally:
            self.server.analysis_lock.release()

    def test_no_cross_origin(self):
        status, _, _ = self.request('POST','/api/demo',b'',{'Content-Type':'application/octet-stream','Origin':'https://attacker.invalid'})
        self.assertEqual(status, 403)

    def test_no_simple_form_upload(self):
        status, _, _ = self.request('POST','/api/demo',b'',{'Content-Type':'text/plain'})
        self.assertEqual(status, 415)

    def test_no_external_decoders_by_default(self):
        status, _, _ = self.request('POST','/api/analyze?name=a.apk&decode=auto',b'',{'Content-Type':'application/octet-stream'})
        self.assertEqual(status, 400)

    def test_path_traversal(self):
        status, _, _ = self.request('GET','/../../pyproject.toml')
        self.assertEqual(status, 404)

    def test_empty_apk_invalid(self):
        status, _, _ = self.request('POST','/api/analyze?name=a.apk',b'',{'Content-Type':'application/octet-stream'})
        self.assertEqual(status, 400)

    def test_oversize(self):
        status, _, _ = self.request('POST','/api/analyze?name=a.apk',b'',{'Content-Type':'application/octet-stream','Content-Length':str(129*1024*1024)})
        self.assertEqual(status, 413)


if __name__ == '__main__':
    unittest.main()
