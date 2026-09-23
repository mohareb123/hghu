"""Exercise the actual bundled engines on Windows with no Java/dotnet on PATH.

Apktool/JADX use a real generated APK. Il2CppDumper startup and unsupported
metadata are tested; this is not a successful dump of a real Unity game.
"""
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile


def command(args, env, expected=0, timeout=180):
    result = subprocess.run([str(x) for x in args], env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding='utf-8', errors='replace', timeout=timeout)
    if result.returncode != expected:
        raise AssertionError(f'Command exited {result.returncode}, expected {expected}: {args[0]}\n{result.stdout[-2400:]}')
    return result.stdout


def main():
    bundle = Path(sys.argv[1]).resolve()
    if os.name != 'nt':
        raise RuntimeError('Requires the actual Windows bundle')
    with tempfile.TemporaryDirectory(prefix='protohunter offline bundle ') as temporary:
        temp = Path(temporary)
        # A relocation into a path containing spaces verifies no CI absolute paths leak.
        moved = temp / 'Complete app'
        shutil.copytree(bundle, moved)
        exe = moved / 'ProtoHunter.exe'; java = moved / 'tools/java/bin/java.exe'
        jar = moved / 'tools/apktool.jar'
        env = {k: v for k, v in os.environ.items() if not k.startswith(('JAVA', 'JDK', 'DOTNET', 'PROTOHUNTER', '_JAVA'))}
        env.update(PATH=str(Path(os.environ['SystemRoot']) / 'System32'), JAVA_HOME=str(temp / 'no-java'),
                   DOTNET_ROOT=str(temp / 'no-dotnet'), DOTNET_MULTILEVEL_LOOKUP='0',
                   APPDATA=str(temp / 'settings'), PROTOHUNTER_NO_BROWSER='1')
        stale = Path(env['APPDATA']) / 'ProtoHunter/tools.json'; stale.parent.mkdir(parents=True)
        stale.write_text(json.dumps({'java': 'Z:/old-machine/java.exe', 'apktool_jar':'Z:/old/apktool.jar',
                                     'jadx':'Z:/old/jadx', 'il2cpp':'Z:/old/dumper.exe'}))
        doctor = json.loads(command([exe, 'doctor', '--verify-bundle'], env))
        assert doctor['integrity']['ok'], doctor['integrity']
        assert doctor['optional_decoders']['bundle']['ready'], doctor
        assert all(doctor['optional_decoders'][key] for key in ('jadx', 'apktool', 'il2cpp', 'java'))
        assert Path(doctor['optional_decoders']['java_path']).resolve() == java.resolve()
        assert '21.0.12' in command([java, '-version'], env)
        assert '2.12.1' in command([java, '-jar', jar, '--version'], env)
        assert '1.5.3' in command([java, '-cp', moved / 'tools/jadx/lib/*', 'jadx.cli.JadxCLI', '--version'], env)
        help_text = command([moved / 'tools/il2cpp/Il2CppDumper.exe', '--help'], env)
        assert 'usage:' in help_text.lower(), help_text
        fixture = temp / 'apk source'
        (fixture / 'smali/com/protohunter/fixture').mkdir(parents=True)
        (fixture / 'res/values').mkdir(parents=True)
        (fixture / 'assets/UnityFixture').mkdir(parents=True)
        (fixture / 'apktool.yml').write_text('''version: 2.12.1
apkFileName: fixture.apk
usesFramework:
  ids:
  - 1
sdkInfo:
  minSdkVersion: 21
  targetSdkVersion: 28
packageInfo:
  forcedPackageId: 127
versionInfo:
  versionCode: 1
  versionName: '1.0'
resourcesAreCompressed: false
doNotCompress:
- resources.arsc
''', encoding='utf-8')
        (fixture / 'AndroidManifest.xml').write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.protohunter.fixture" android:versionCode="1" android:versionName="1.0"><uses-sdk android:minSdkVersion="21" android:targetSdkVersion="28"/><application android:label="@string/app_name" android:hasCode="true"/></manifest>''', encoding='utf-8')
        (fixture / 'res/values/strings.xml').write_text('<resources><string name="app_name">ProtoHunter offline fixture</string></resources>', encoding='utf-8')
        (fixture / 'smali/com/protohunter/fixture/Probe.smali').write_text('''.class public Lcom/protohunter/fixture/Probe;
.super Ljava/lang/Object;
.method public static endpoint()Ljava/lang/String;
    .locals 1
    const-string v0, "https://login.example.invalid/CSMajorLoginReq"
    return-object v0
.end method
.method public static login(Ljava/net/Socket;Ljava/net/SocketAddress;)V
    .locals 0
    invoke-virtual {p0, p1}, Ljava/net/Socket;->connect(Ljava/net/SocketAddress;)V
    return-void
.end method
''', encoding='utf-8')
        (fixture / 'assets/UnityFixture/libil2cpp.so').write_bytes(b'\x7fELF' + b'\0' * 60)
        (fixture / 'assets/UnityFixture/global-metadata.dat').write_bytes(struct.pack('<II', 0xFAB11BAF, 999) + b'\0' * 248)
        apk = temp / 'fixture.apk'
        command([java, '-jar', jar, 'b', fixture, '-p', temp / 'framework', '-o', apk], env)
        with zipfile.ZipFile(apk) as archive:
            assert {'classes.dex', 'AndroidManifest.xml'}.issubset(archive.namelist())
        bot = temp / 'old.py'; bot.write_text('class Probe:\n pass\n', encoding='utf-8')
        direct = json.loads(command([exe, 'analyze', apk, '--investigate', '--bot-project', bot], env))
        assert direct['protocol_report']['meta']['enabled']
        assert any(edge['kind'] == 'calls' and edge['evidence']['format'] == 'dex' for edge in direct['dependency_graph']['edges'])
        assert any(row['network'] for category in ('unknown', 'auth', 'transport') for row in direct['protocol_report'][category])
        assert direct['protocol_report']['bot_matches']
        projects = temp / 'projects'
        prefix = [exe, 'workspace', '--root', projects]
        project = json.loads(command(prefix + ['create', apk], env))
        project_id = project['id']
        for operation in ('jadx', 'apktool', 'inspect', 'build'):
            result = json.loads(command(prefix + ['run', project_id, operation] + (['--investigate'] if operation == 'inspect' else []), env, timeout=300))
            assert result['runs'][-1]['status'] == 'completed', result
        workspace = projects / project_id
        inspection = next(run for run in result['runs'] if run['operation'] == 'inspect')
        sections = workspace / inspection['sections']
        report = json.loads((workspace / inspection['path'] / 'report.json').read_text(encoding='utf-8'))
        for stem, key in (('server', 'servers'), ('protocol', 'protocols'), ('source', 'sources'), ('protocol_report', 'protocol_report'), ('dependency_graph', 'dependency_graph')):
            assert json.loads((sections / (stem + '.json')).read_text(encoding='utf-8')) == report[key]
            assert (sections / (stem + '.txt')).is_file()
        assert report['protocol_report']['meta']['enabled']
        assert (workspace / inspection['path'] / 'protocol_report.json').is_file()
        assert json.loads((sections / 'index.json').read_text(encoding='utf-8'))['format'] == 'protohunter-sections-v1'
        source = workspace / result['decoded']['main'] / 'smali/com/protohunter/fixture/Probe.smali'
        assert 'CSMajorLoginReq' in source.read_text(encoding='utf-8')
        java_sources = list(workspace.glob('runs/*/jadx/sources/com/protohunter/fixture/Probe.java'))
        assert java_sources and 'CSMajorLoginReq' in java_sources[0].read_text(encoding='utf-8')
        assert zipfile.is_zipfile(workspace / result['runs'][-1]['artifact'])
        command(prefix + ['run', project_id, 'il2cpp', '--binary-unit', 'main', '--metadata-unit', 'main',
                         '--binary-member', 'assets/UnityFixture/libil2cpp.so',
                         '--metadata-member', 'assets/UnityFixture/global-metadata.dat'], env, expected=2)
        final = json.loads((workspace / 'project.json').read_text(encoding='utf-8'))
        assert final['runs'][-1]['status'] == 'failed'
        log = (workspace / final['runs'][-1]['path'] / 'step-00.log').read_text(encoding='utf-8', errors='replace')
        assert 'metadata' in log.lower(), log
        # No tool/config changes during execution: the distributed checksums still match.
        assert json.loads(command([exe, 'doctor', '--verify-bundle'], env))['integrity']['ok']
    print('REAL BUNDLE SMOKE PASSED: relocation, old settings migration, SHA-256, bundled Java/JADX/Apktool, real APK round-trip, app-local Il2CppDumper launch and invalid metadata rejection; no host Java/.NET on PATH.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        if os.environ.get('GITHUB_ACTIONS'):
            print('::error::' + str(exc)[-3000:].replace('%','%25').replace('\r','%0D').replace('\n','%0A'))
        raise
