"""Run the actual Windows executable: CLI, desktop startup, static assets and HTTP analysis."""
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import tempfile
import time
import zipfile
import threading
from urllib.request import Request, urlopen


def smoke_java(executable):
    # A tiny trusted fixture tests java -jar wiring, not actual Apktool decompilation.
    java_bin = Path(os.environ['JAVA_HOME']) / 'bin'
    with tempfile.TemporaryDirectory(prefix='protohunter jar test ') as tmp:
        base = Path(tmp)
        source = base / 'FakeApktool.java'
        source.write_text(r'''import java.nio.file.*;
public class FakeApktool {
  public static void main(String[] args) throws Exception {
    if (args[0].equals("--version")) { System.out.println("fixture-1.0"); return; }
    for (int i=0; i<args.length-1; i++) if (args[i].equals("-o")) {
      Path out=Paths.get(args[i+1]); Files.createDirectories(out);
      Files.writeString(out.resolve("Example.smali"), ".class public LExample;\n.method public login()V\n const-string v0, \"CSMajorLoginResp\"\n return-void\n.end method\n");
      return;
    }
    throw new IllegalArgumentException("missing output directory");
  }
}''', encoding='utf-8')
        subprocess.run([str(java_bin / 'javac.exe'), '-d', str(base / 'classes'), str(source)], check=True, timeout=30)
        jar = base / 'apktool fixture.jar'
        subprocess.run([str(java_bin / 'jar.exe'), '--create', '--file', str(jar), '--main-class', 'FakeApktool', '-C', str(base / 'classes'), '.'], check=True, timeout=30)
        apk = base / 'input.apk'
        with zipfile.ZipFile(apk, 'w') as archive:
            archive.writestr('config.txt', 'https://login.example.invalid')
        projects = base / 'projects'
        created = subprocess.run([str(executable), 'workspace', '--root', str(projects), 'create', str(apk)],
                                 capture_output=True, text=True, check=True, timeout=60)
        project = json.loads(created.stdout)
        subprocess.run([str(executable), 'workspace', '--root', str(projects), 'run', project['id'], 'inspect'],
                       stdout=subprocess.DEVNULL, check=True, timeout=60)
        state = json.loads((projects / project['id'] / 'project.json').read_text(encoding='utf-8'))
        assert state['runs'][-1]['status'] == 'completed'
        output = base / 'jar-report.json'
        subprocess.run([str(executable), 'analyze', str(apk), '--scan-mode', 'fast', '--decode', 'apktool',
                        '--apktool-jar', str(jar), '--java', str(java_bin / 'java.exe'), '-o', str(output)], check=True, timeout=60)
        report = json.loads(output.read_text(encoding='utf-8'))
        assert report['input']['scan_mode'] == 'fast'
        assert any(r['target'] == 'CSMajorLoginResp' and r['source'].startswith('apktool/') for r in report['research'])


def main():
    executable = Path(sys.argv[1]).resolve()
    if os.name != 'nt' or executable.read_bytes()[:2] != b'MZ':
        raise RuntimeError('This smoke test requires an actual Windows PE executable on Windows')
    version = subprocess.run([str(executable), '--version'], capture_output=True, text=True, timeout=60, check=True)
    assert version.stdout.strip() == '0.7.0', version.stdout
    with tempfile.TemporaryDirectory(prefix='protohunter-exe-test-') as tmp:
        source = Path(tmp, 'sample.smali')
        source.write_text('.class public LN2/c;\n.method public login()V\n const-string v0, "CSMajorLoginReq"\n const-string v1, "https://login.example.invalid/"\n return-void\n.end method\n', encoding='utf-8')
        output = Path(tmp, 'report.json')
        subprocess.run([str(executable), 'analyze', str(source), '--profile', 'games', '-o', str(output)], check=True, timeout=60)
        report = json.loads(output.read_text(encoding='utf-8'))
        assert report['endpoints'][0]['host'] == 'login.example.invalid'
        assert any(x['target'] == 'CSMajorLoginReq' for x in report['research'])
        assert 'bot_comparison' not in report
    smoke_java(executable)
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
            status = json.load(response)
            assert status['version'] == '0.7.0'
            assert status['desktop_tools'] and status['native_picker'] and status['config_token']
            assert status['allow_decoders']
        with urlopen(url + 'workspace.js', timeout=15) as response:
            assert b'/api/workspace' in response.read()
        request = Request(url + 'api/workspace', data=b'{"action":"list"}',
                          headers={'Content-Type':'application/json', 'X-ProtoHunter-Config-Token':status['config_token']}, method='POST')
        with urlopen(request, timeout=15) as response:
            assert isinstance(json.load(response)['projects'], list)
        request = Request(url + 'api/demo', data=b'', headers={'Content-Type': 'application/octet-stream'}, method='POST')
        with urlopen(request, timeout=30) as response:
            demo = json.load(response)
        assert demo['input']['demo'] is True
        assert demo['summary']['smali_classes'] == 1
        assert demo['coverage_summary']['semantic_completeness_guaranteed'] is False
        request = Request(url + 'api/jobs?name=async.txt&scan_mode=fast', data=b'https://login.example.invalid',
                          headers={'Content-Type':'application/octet-stream'}, method='POST')
        with urlopen(request, timeout=15) as response:
            job = json.load(response)['job_id']
        deadline = time.monotonic() + 30
        while True:
            with urlopen(url + 'api/jobs/' + job, timeout=15) as response:
                state = json.load(response)
            if state['status'] == 'completed':
                break
            assert state['status'] not in {'failed', 'cancelled'}, state
            assert time.monotonic() < deadline, state
            time.sleep(0.2)
        with urlopen(url + 'api/jobs/' + job + '/result', timeout=15) as response:
            result = json.load(response)
        assert result['input']['scan_mode'] == 'fast'
        assert result['endpoints'][0]['host'] == 'login.example.invalid'
        print('WINDOWS EXE SMOKE PASSED: PE, version, CLI extraction, Java/JAR fixture, desktop capabilities, assets, demo, background jobs, persisted workspace CLI/API.')
    finally:
        subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, check=False)
        process.wait(timeout=20)
        if process.stdout:
            process.stdout.close()


if __name__ == '__main__':
    main()
