"""Browser-only synthetic engine backend; never imported by production entrypoints."""
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from protohunter.web import Server
from protohunter.tooling import ToolConfig
from test_projects import FakeConfig, zip_bytes


class BrowserConfig(ToolConfig):
    def command(self, tool):
        return FakeConfig().command(tool)

    def status(self, private=False):
        return dict(jadx=True, apktool=True, java=True, il2cpp=True, apksigner=True, zipalign=True)


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp, 'synthetic.apk')
        path.write_bytes(zip_bytes({'config.txt': 'https://login.example.invalid',
                                   'lib/arm64-v8a/libil2cpp.so': b'ELF fixture',
                                   'assets/global-metadata.dat': b'metadata fixture'}))
        with Server(('127.0.0.1', 0), True, BrowserConfig(), True, Path(tmp, 'projects')) as server:
            server.projects.create(path)
            print('READY http://127.0.0.1:' + str(server.server_port), flush=True)
            server.serve_forever()
