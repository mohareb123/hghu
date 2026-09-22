"""Trusted local tool configuration. JARs are executed only when decoding is requested."""
from dataclasses import dataclass, asdict
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def app_directory():
    return Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent.parent


def settings_path():
    base = Path(os.environ.get('APPDATA', str(Path.home() / '.config')))
    return base / 'ProtoHunter' / 'tools.json'


@dataclass(frozen=True)
class ToolConfig:
    apktool_jar: str = ''
    java: str = ''
    jadx: str = ''
    il2cpp: str = ''
    dotnet: str = ''
    apksigner: str = ''
    zipalign: str = ''

    def resolve(self):
        base = app_directory()
        jar = self.apktool_jar or os.environ.get('PROTOHUNTER_APKTOOL_JAR', '')
        if not jar:
            jar = next((str(p) for p in (base / 'apktool.jar', base / 'tools' / 'apktool.jar') if p.is_file()), '')
        java = self.java or os.environ.get('PROTOHUNTER_JAVA', '')
        if not java:
            candidates = [base / 'tools' / 'java' / 'bin' / 'java.exe', base / 'tools' / 'jre' / 'bin' / 'java.exe']
            if os.environ.get('JAVA_HOME'):
                candidates.append(Path(os.environ['JAVA_HOME']) / 'bin' / ('java.exe' if os.name == 'nt' else 'java'))
            java = next((str(p) for p in candidates if p.is_file()), '') or shutil.which('java') or ''
        else:
            java = shutil.which(java) or java
        return ToolConfig(str(Path(jar).expanduser().resolve()) if jar else '', java,
                          **{key: getattr(self, key) or os.environ.get('PROTOHUNTER_' + key.upper(), '')
                             for key in ('jadx', 'il2cpp', 'dotnet', 'apksigner', 'zipalign')})

    def status(self, private=False):
        config = self.resolve()
        jar_found = bool(config.apktool_jar and Path(config.apktool_jar).is_file())
        java_found = bool(config.java and Path(config.java).is_file())
        wrapper = shutil.which('apktool')
        result = {'jadx': bool(shutil.which('jadx')), 'apktool': (jar_found and java_found) if config.apktool_jar else bool(wrapper),
                  'java': java_found, 'apktool_jar_found': jar_found,
                  'apktool_mode': 'jar' if config.apktool_jar else 'command',
                  'apktool_note': 'Java is required for apktool.jar' if jar_found and not java_found else ''}
        for tool in ('jadx', 'il2cpp', 'apksigner', 'zipalign'):
            try:
                result[tool] = bool(self.command(tool))
            except ValueError:
                result[tool] = False
        if private:
            result.update(apktool_jar=config.apktool_jar, java_path=config.java,
                          **{key + '_path': getattr(config, key) for key in ('jadx', 'il2cpp', 'dotnet', 'apksigner', 'zipalign')})
        return result

    def command(self, tool):
        config = self.resolve()
        if tool == 'apktool' and config.apktool_jar:
            if not Path(config.apktool_jar).is_file():
                raise ValueError('Configured apktool.jar was not found')
            if not config.java or not Path(config.java).is_file():
                raise ValueError('apktool.jar needs Java. Install Java or select java.exe in tool settings.')
            return [config.java, '-jar', config.apktool_jar]
        configured = getattr(config, tool, '')
        executable = shutil.which(configured) or configured if configured else shutil.which('Il2CppDumper' if tool == 'il2cpp' else tool)
        if not executable:
            return None
        path = Path(executable).expanduser().resolve()
        if tool == 'jadx':
            lib = path / 'lib' if path.is_dir() else path.parent.parent / 'lib'
            if lib.is_dir() and any(lib.glob('*.jar')):
                if not config.java or not Path(config.java).is_file():
                    raise ValueError('JADX requires Java; select java.exe')
                return [config.java, '-cp', str(lib / '*'), 'jadx.cli.JadxCLI']
        if not path.is_file():
            raise ValueError(f'{tool} executable was not found')
        if path.suffix.lower() == '.jar':
            if not config.java or not Path(config.java).is_file():
                raise ValueError(f'{tool} JAR requires Java')
            return [config.java, '-jar', str(path)]
        if tool == 'il2cpp' and path.suffix.lower() == '.dll':
            dotnet = shutil.which(config.dotnet or 'dotnet') or config.dotnet
            if not dotnet or not Path(dotnet).is_file():
                raise ValueError('Il2CppDumper.dll requires a compatible .NET runtime (dotnet)')
            return [dotnet, str(path)]
        return [str(path)]

    def save(self, path=None):
        # Called only by the explicit trusted desktop settings endpoint.
        resolved = self.resolve()
        if self.apktool_jar and (not Path(self.apktool_jar).is_file() or Path(self.apktool_jar).suffix.lower() != '.jar'):
            raise ValueError('Select an existing .jar file')
        if self.java and (not resolved.java or not Path(resolved.java).is_file()):
            raise ValueError('Select an existing Java executable')
        for tool in ('jadx', 'il2cpp', 'apksigner', 'zipalign'):
            if getattr(self, tool):
                self.command(tool)
        if self.dotnet and not (shutil.which(self.dotnet) or Path(self.dotnet).is_file()):
            raise ValueError('Select an existing dotnet executable')
        destination = path or settings_path()
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix('.tmp')
        temporary.write_text(json.dumps(asdict(self)), encoding='utf-8')
        temporary.replace(destination)

    @classmethod
    def load(cls, path=None):
        try:
            data = json.loads((path or settings_path()).read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                return cls()
            return cls(**{k: str(data.get(k, '')) for k in cls.__dataclass_fields__})
        except (OSError, ValueError, TypeError):
            return cls()

    def probe(self):
        results = []
        config = self.resolve()
        commands = []
        if config.java and Path(config.java).is_file():
            commands.append(('Java', [config.java, '-version']))
        if self.status()['apktool']:
            commands.append(('Apktool', self.command('apktool') + ['--version']))
        if self.status()['jadx']:
            commands.append(('JADX', self.command('jadx') + ['--version']))
        # Il2CppDumper has no version-only CLI: do not start its interactive workflow here.
        for label, command in commands:
            with tempfile.TemporaryFile() as log:
                try:
                    process = subprocess.run(command, stdout=log, stderr=log, timeout=12, check=False)
                    log.seek(0)
                    results.append({'tool': label, 'ok': process.returncode == 0, 'output': log.read(4096).decode('utf-8', 'replace')})
                except (OSError, subprocess.TimeoutExpired) as exc:
                    results.append({'tool': label, 'ok': False, 'output': str(exc)})
        return results
