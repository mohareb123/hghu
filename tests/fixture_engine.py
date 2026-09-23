"""Synthetic external-tool contract fixture, NOT a decompiler or signing implementation."""
from pathlib import Path
import shutil
import sys
import time
import zipfile


def main():
    tool, *args = sys.argv[1:]
    if tool == 'wait':
        print('waiting', flush=True); time.sleep(60); return
    if tool == 'fail':
        print('synthetic decoder failure', flush=True); raise SystemExit(7)
    if tool == 'apktool':
        output = Path(args[args.index('-o') + 1])
        if args[0] == 'd':
            output.mkdir(); (output / 'apktool.yml').write_text('version: fixture\n')
            (output / 'Example.smali').write_bytes(b'.class public LExample;\r\n.method public login()V\r\n const-string v0, "CSMajorLoginReq"\r\n return-void\r\n.end method\r\n')
            (output / 'AndroidManifest.xml').write_text('<manifest package="test.fixture"/>')
        else:
            with zipfile.ZipFile(output, 'w') as archive:
                archive.writestr('fixture-smali.txt', (Path(args[1]) / 'Example.smali').read_text())
    elif tool == 'jadx':
        output = Path(args[args.index('-d') + 1]); output.mkdir()
        (output / 'Example.java').write_text('class Example { String url="https://login.example.invalid/"; }')
    elif tool == 'il2cpp':
        output = Path(args[-1]); output.mkdir(exist_ok=True)
        (output / 'dump.cs').write_text('// Synthetic type definition only\nclass Player { public int accountId; }')
        (output / 'DummyDll').mkdir(); (output / 'DummyDll' / 'Assembly-CSharp.dll').write_bytes(b'fixture-not-real-DLL')
    elif tool == 'zipalign':
        if '-c' not in args:
            shutil.copyfile(args[-2], args[-1])
    elif tool == 'apksigner':
        if args[0] == 'sign':
            shutil.copyfile(args[-1], args[args.index('--out') + 1])
        print('synthetic signer contract; not a cryptographic verification')
    else:
        raise SystemExit(2)
    print(tool + ' fixture completed', flush=True)


if __name__ == '__main__':
    main()
