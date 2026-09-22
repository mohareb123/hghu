# Build from the repository root: python -m PyInstaller --clean --noconfirm packaging/ProtoHunter.spec
from pathlib import Path

root = Path(SPECPATH).parent
analysis = Analysis(
    [str(root / 'packaging' / 'windows_entry.py')],
    pathex=[str(root)],
    binaries=[],
    datas=[
        (str(root / 'protohunter' / 'static'), 'protohunter/static'),
        (str(root / 'protohunter' / 'demo.smali'), 'protohunter'),
    ],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'unittest'],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name='ProtoHunter',
    debug=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    runtime_tmpdir=None,
    icon=str(root / 'packaging' / 'protohunter.ico'),
    version=str(root / 'packaging' / 'windows_version.txt'),
    uac_admin=False,
)
