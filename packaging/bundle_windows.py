"""Assemble pinned real engines and runtimes; no third-party binaries go into Git.

Run on Windows after build-windows.ps1. Corresponding Temurin sources are uploaded
alongside the binary distribution, not downloaded on the user's first launch.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()


def download(asset, cache):
    destination = cache / asset['filename']
    if destination.is_file() and digest(destination) == asset['sha256']:
        return destination
    temporary = destination.with_suffix('.part')
    for attempt in range(3):
        try:
            request = urllib.request.Request(asset['url'], headers={'User-Agent': 'ProtoHunter-Bundle-Builder'})
            with urllib.request.urlopen(request, timeout=90) as response, temporary.open('wb') as out:
                shutil.copyfileobj(response, out, 1024**2)
            if digest(temporary) != asset['sha256']:
                raise ValueError('SHA-256 mismatch: ' + asset['filename'])
            temporary.replace(destination)
            return destination
        except (OSError, ValueError):
            temporary.unlink(missing_ok=True)
            if attempt == 2:
                raise
            time.sleep(2)


def extract(archive, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as z:
        members = z.infolist()
        if len(members) > 100000 or sum(i.file_size for i in members) > 3 * 1024**3:
            raise ValueError('Tool ZIP exceeds the assembly budget')
        for info in members:
            path = PurePosixPath(info.filename)
            if path.is_absolute() or '..' in path.parts or ':' in info.filename or '\\' in info.filename or (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Unsafe tool ZIP member: ' + info.filename)
        z.extractall(destination)


def run(command, cwd=ROOT):
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding='utf-8', errors='replace', timeout=600)
    print(result.stdout[-8000:], flush=True)
    if result.returncode:
        raise RuntimeError(f'Build command failed ({result.returncode}): {command[0]}')


def assemble():
    if os.name != 'nt':
        raise RuntimeError('This assembly is for Windows x64 only')
    lock = json.loads((ROOT / 'packaging/bundle.lock.json').read_text())
    cache = ROOT / 'build/bundle-downloads'; cache.mkdir(parents=True, exist_ok=True)
    unpacked = ROOT / 'build/bundle-unpacked'
    output = ROOT / 'dist/ProtoHunter-Complete'
    sources = ROOT / 'dist/ProtoHunter-Sources'
    for path in (unpacked, output, sources):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)
    assets = {key: download(value, cache) for key, value in lock['assets'].items()}
    tools = output / 'tools'; tools.mkdir()
    shutil.copy2(assets['apktool'], tools / 'apktool.jar')
    extract(assets['jadx'], tools / 'jadx')
    if not (tools / 'jadx/lib').is_dir():
        raise ValueError('JADX release layout changed; refusing an incomplete bundle')
    extract(assets['java'], unpacked / 'java')
    java = next((p for p in (unpacked / 'java').iterdir() if (p / 'bin/java.exe').is_file()), None)
    if not java:
        raise ValueError('JRE layout changed')
    shutil.copytree(java, tools / 'java')  # Includes original legal notices and runtime DLLs.
    extract(assets['il2cpp_source'], unpacked / 'il2cpp')
    source = next((unpacked / 'il2cpp').glob('Il2CppDumper-*'))
    (source / 'global.json').write_text(json.dumps({'sdk': {'version': lock['dotnet_sdk'], 'rollForward': 'disable'}}))
    il2cpp = tools / 'il2cpp'
    run(['dotnet', 'publish', str(source / 'Il2CppDumper/Il2CppDumper.csproj'), '-c', 'Release',
         '-f', 'net8.0', '-r', 'win-x64', '--self-contained', 'true', '-o', str(il2cpp),
         '-p:RuntimeFrameworkVersion=' + lock['dotnet_runtime'], '-p:PublishSingleFile=false',
         '-p:PublishTrimmed=false', '-p:TargetFrameworks=net8.0', '-p:RestorePackagesWithLockFile=true'], cwd=source)
    if not (il2cpp / 'coreclr.dll').is_file():
        raise ValueError('Il2CppDumper must contain its own .NET runtime')
    config = json.loads((il2cpp / 'config.json').read_text(encoding='utf-8-sig'))
    config['RequireAnyKey'] = False
    (il2cpp / 'config.json').write_text(json.dumps(config, indent=2), encoding='utf-8')
    for src, dest in [('dist/ProtoHunter.exe', 'ProtoHunter.exe'), ('packaging/README-Complete.md', 'README-FIRST.md'),
                      ('docs/workspaces.md', 'workspaces.md'), ('docs/section-exports.md', 'section-exports.md'), ('docs/protocol-investigation.md', 'protocol-investigation.md'), ('LICENSE', 'LICENSE-ProtoHunter.txt'),
                      ('packaging/bundle.lock.json', 'bundle-provenance.json')]:
        shutil.copy2(ROOT / src, output / dest)
    shutil.copytree(ROOT / 'packaging/licenses', output / 'licenses')
    shutil.copy2(source / 'LICENSE', output / 'licenses/Il2CppDumper-LICENSE.txt')
    notices = ROOT / 'packaging/THIRD-PARTY.md'
    shutil.copy2(notices, output / 'THIRD-PARTY.md')
    # Ship corresponding source alongside the binary release with equal availability.
    for key in ('java_source', 'il2cpp_source'):
        shutil.copy2(assets[key], sources / assets[key].name)
    shutil.copy2(ROOT / 'packaging/bundle.lock.json', sources / 'bundle-provenance.json')
    shutil.copy2(ROOT / 'packaging/THIRD-PARTY.md', sources / 'README-SOURCES.md')
    shutil.copy2(ROOT / 'packaging/bundle_windows.py', sources / 'bundle_windows.py')
    lockfile = source / 'Il2CppDumper/packages.lock.json'
    if lockfile.exists():
        shutil.copy2(lockfile, sources / 'Il2CppDumper-packages.lock.json')
    manifest = {'schema': 1, 'platform': 'windows-x64', 'versions': lock['versions'],
                'upstream': lock['assets'], 'files': {}}
    for path in sorted(output.rglob('*')):
        if path.is_file():
            manifest['files'][path.relative_to(output).as_posix()] = digest(path)
    (output / 'bundle-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    for folder in (output, sources):
        lines = [digest(p) + '  ' + p.relative_to(folder).as_posix() for p in sorted(folder.rglob('*')) if p.is_file()]
        (folder / 'SHA256SUMS.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('COMPLETE BUNDLE:', output, flush=True)
    return output


if __name__ == '__main__':
    try:
        assemble()
    except Exception as exc:
        message = str(exc).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        if os.environ.get('GITHUB_ACTIONS'):
            print('::error::' + message)
        raise
