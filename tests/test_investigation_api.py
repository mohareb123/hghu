import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
import zipfile
from contextlib import redirect_stdout, redirect_stderr
import io
from protohunter.web import Server
from protohunter.cli import main
from test_investigation import LOGIN, BUILDER, TRANSPORT, dex_fixture


class InvestigationAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server = Server(('127.0.0.1', 0), projects_root=Path(self.tmp.name, 'projects'))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(); self.tmp.cleanup()

    def post(self, path, body, headers=None):
        conn=http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        conn.request('POST',path,body,headers or {'Content-Type':'application/octet-stream'})
        response=conn.getresponse(); status=response.status; data=json.loads(response.read()); conn.close()
        return status,data

    def test_mode_and_optional_compare(self):
        status,report=self.post('/api/analyze?name=login.smali&investigate=true', LOGIN.encode())
        self.assertEqual(status,200); self.assertTrue(report['protocol_report']['meta']['enabled'])
        request=json.dumps({'protocol_report':report['protocol_report'], 'files':[{'name':'old.py','text':'class LoginClient: pass'}]})
        headers={'Content-Type':'application/json'}
        status,result=self.post('/api/bot-compare',request,headers)
        self.assertEqual(status,200,result); self.assertEqual(result['bot_matches'][0]['name'],'LoginClient')
        self.assertEqual(self.post('/api/bot-compare',request,{**headers,'Origin':'https://evil.invalid'})[0],403)
        self.assertEqual(self.post('/api/bot-compare','{"protocol_report":{},"files":[]}',headers)[0],400)
        self.assertEqual(self.post('/api/analyze?name=login.smali&investigate=oops',LOGIN.encode())[0],400)
        self.server.export_lock.acquire()
        try: self.assertEqual(self.post('/api/bot-compare',request,headers)[0],429)
        finally: self.server.export_lock.release()
        self.assertEqual(self.post('/api/bot-compare',request,headers)[0],200)

    def test_cli_report_and_real_dex_bundle(self):
        root=Path(self.tmp.name); apk=root/'input.apk'
        with zipfile.ZipFile(apk,'w') as z:
            z.writestr('classes.dex',dex_fixture()); z.writestr('assets/config.json','{"url":"https://unused.example.invalid"}')
        bot=root/'old.py'; bot.write_text('class Client: pass')
        target=root/'report.json'
        with redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
            self.assertEqual(main(['analyze',str(apk),'--bot-project',str(bot),'-o',str(target)]),0)
        report=json.loads(target.read_text(encoding='utf-8'))
        protocol=json.loads((root/'report.sections/protocol_report.json').read_text(encoding='utf-8'))
        self.assertEqual(protocol,report['protocol_report']); self.assertTrue(protocol['meta']['enabled'])
        self.assertTrue(protocol['bot_matches']); self.assertTrue((root/'report.sections/dependency_graph.txt').exists())
        self.assertTrue(any(e['evidence']['format']=='dex' for e in report['dependency_graph']['edges']))
