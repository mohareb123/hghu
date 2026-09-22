"""Trusted local tool configuration. JARs are executed only when decoding is requested."""
from dataclasses import dataclass
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
        return ToolConfig(str(Path(jar).expanduser().resolve()) if jar else '', java)

    def status(self, private=False):
        config = self.resolve()
        jar_found = bool(config.apktool_jar and Path(config.apktool_jar).is_file())
        java_found = bool(config.java and Path(config.java).is_file())
        wrapper = shutil.which('apktool')
        result = {'jadx': bool(shutil.which('jadx')), 'apktool': (jar_found and java_found) if config.apktool_jar else bool(wrapper),
                  'java': java_found, 'apktool_jar_found': jar_found,
                  'apktool_mode': 'jar' if config.apktool_jar else 'command',
                  'apktool_note': 'Java is required for apktool.jar' if jar_found and not java_found else ''}
        if private:
            result.update(apktool_jar=config.apktool_jar, java_path=config.java)
        return result

    def command(self, tool):
        config = self.resolve()
        if tool == 'apktool' and config.apktool_jar:
            if not Path(config.apktool_jar).is_file():
                raise ValueError('Configured apktool.jar was not found')
            if not config.java or not Path(config.java).is_file():
                raise ValueError('apktool.jar needs Java. Install Java or select java.exe in tool settings.')
            return [config.java, '-jar', config.apktool_jar]
        executable = shutil.which(tool)
        return [executable] if executable else None

    def save(self, path=None):
        # Called only by the explicit trusted desktop settings endpoint.
        resolved = self.resolve()
        if self.apktool_jar and (not Path(self.apktool_jar).is_file() or Path(self.apktool_jar).suffix.lower() != '.jar'):
            raise ValueError('Select an existing .jar file')
        if self.java and (not resolved.java or not Path(resolved.java).is_file()):
            raise ValueError('Select an existing Java executable')
        destination = path or settings_path()
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix('.tmp')
        temporary.write_text(json.dumps({'apktool_jar': self.apktool_jar, 'java': self.java}), encoding='utf-8')
        temporary.replace(destination)

    @classmethod
    def load(cls, path=None):
        try:
            data = json.loads((path or settings_path()).read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                return cls()
            return cls(**{k: str(data.get(k, '')) for k in ('apktool_jar', 'java')})
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
        for label, command in commands:
            with tempfile.TemporaryFile() as log:
                try:
                    process = subprocess.run(command, stdout=log, stderr=log, timeout=12, check=False)
                    log.seek(0)
                    results.append({'tool': label, 'ok': process.returncode == 0, 'output': log.read(4096).decode('utf-8', 'replace')})
                except (OSError, subprocess.TimeoutExpired) as exc:
                    results.append({'tool': label, 'ok': False, 'output': str(exc)})
        return results
