"""Run the actual Windows executable: CLI, desktop startup, static assets and HTTP analysis."""
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import tempfile
import threading
from urllib.request import Request, urlopen


def main():
    executable = Path(sys.argv[1]).resolve()
    if os.name != 'nt' or executable.read_bytes()[:2] != b'MZ':
        raise RuntimeError('This smoke test requires an actual Windows PE executable on Windows')
    version = subprocess.run([str(executable), '--version'], capture_output=True, text=True, timeout=60, check=True)
    assert version.stdout.strip() == '0.4.0', version.stdout
    with tempfile.TemporaryDirectory(prefix='protohunter-exe-test-') as tmp:
        source = Path(tmp, 'sample.smali')
        source.write_text('.class public LN2/c;\n.method public login()V\n const-string v0, "CSMajorLoginReq"\n const-string v1, "https://login.example.invalid/"\n return-void\n.end method\n', encoding='utf-8')
        output = Path(tmp, 'report.json')
        subprocess.run([str(executable), 'analyze', str(source), '--profile', 'games', '-o', str(output)], check=True, timeout=60)
        report = json.loads(output.read_text(encoding='utf-8'))
        assert report['endpoints'][0]['host'] == 'login.example.invalid'
        assert any(x['target'] == 'CSMajorLoginReq' for x in report['research'])
        assert 'bot_comparison' not in report
    environment = {**os.environ, 'PROTOHUNTER_NO_BROWSER': '1', 'PROTOHUNTER_PORT': '0'}
    process = subprocess.Popen([str(executable)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding='utf-8', errors='replace', env=environment)
    lines = queue.Queue()
    def read_output():
        for line in process.stdout:
            lines.put(line)
        lines.put(None)
    threading.Thread(target=read_output, daemon=True).start()
    try:
        url = None
        for _ in range(30):
            line = lines.get(timeout=60)
            if line is None:
                raise AssertionError('Executable exited before desktop server startup')
            print(line.rstrip())
            match = re.search(r'Open: (http://127\.0\.0\.1:\d+/)', line)
            if match:
                url = match.group(1)
                break
        assert url, 'No local URL announced'
        with urlopen(url, timeout=15) as response:
            assert b'ProtoHunter' in response.read()
        with urlopen(url + 'app.js', timeout=15) as response:
            assert 'javascript' in response.headers['Content-Type']
            assert b'renderResearchOverview' in response.read()
        with urlopen(url + 'api/status', timeout=15) as response:
            assert json.load(response)['version'] == '0.4.0'
        request = Request(url + 'api/demo', data=b'', headers={'Content-Type': 'application/octet-stream'}, method='POST')
        with urlopen(request, timeout=30) as response:
            demo = json.load(response)
        assert demo['input']['demo'] is True
        assert demo['summary']['smali_classes'] == 1
        assert demo['coverage_summary']['semantic_completeness_guaranteed'] is False
        print('WINDOWS EXE SMOKE PASSED: PE, version, CLI extraction, desktop startup, bundled assets, API demo.')
    finally:
        subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, check=False)
        process.wait(timeout=20)
        if process.stdout:
            process.stdout.close()


if __name__ == '__main__':
    main()
