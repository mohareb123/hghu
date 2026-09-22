import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .analyzer import analyze
from .tooling import ToolConfig


def main(argv=None):
    parser = argparse.ArgumentParser(prog="protohunter", description="Local Android network / Protobuf / Smali static analysis")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("analyze", help="Analyze a file or decoded directory")
    scan.add_argument("input", type=Path)
    scan.add_argument("--scan-mode", choices=["fast", "deep"], default="deep", help="Fast skips media/fonts/textures; deep scans them")
    scan.add_argument("--profile", choices=["standard", "games"], default="standard", help="Games: 2 GiB inputs, 512 MiB members, native and split-package support")
    scan.add_argument("--decode", choices=["none", "auto", "jadx", "apktool", "both"], default="none")
    scan.add_argument("-o", "--output", type=Path, help="Write JSON report (otherwise stdout)")
    web = sub.add_parser("serve", help="Open the local web workbench")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8765)
    web.add_argument("--allow-decoders", action="store_true", help="Permit external JADX/Apktool on uploads")
    doctor = sub.add_parser("doctor", help="Check optional decoders")
    web.add_argument("--desktop-tools", action="store_true", help="Enable trusted loopback-only tool settings and Windows local picker")
    for command in (scan, web, doctor):
        command.add_argument("--apktool-jar", help="Path to a trusted apktool.jar (no wrapper required)")
        command.add_argument("--java", help="Path to java.exe or java")
    args = parser.parse_args(argv)
    try:
        saved = ToolConfig.load()
        config = ToolConfig(args.apktool_jar if args.apktool_jar is not None else saved.apktool_jar,
                            args.java if args.java is not None else saved.java)
        if args.command == "serve":
            from .web import serve
            serve(args.host, args.port, args.allow_decoders, tool_config=config, desktop_tools=args.desktop_tools)
        elif args.command == "doctor":
            print(json.dumps({"python": sys.version.split()[0], "optional_decoders": config.status(private=True)}, indent=2))
        else:
            result = analyze(args.input, args.decode, profile=args.profile, scan_mode=args.scan_mode, tool_config=config)
            encoded = json.dumps(result, ensure_ascii=True, indent=2)
            if args.output:
                if args.output.resolve() == args.input.resolve():
                    raise ValueError("Output must not overwrite the input")
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(encoded + "\n", encoding="utf-8")
                print(f"Report: {args.output} · {result['summary']['findings']} findings · {result['summary']['research_findings']} research hits", file=sys.stderr)
            else:
                print(encoded)
        return 0
    except (ValueError, OSError) as exc:
        print(f"protohunter: {exc}", file=sys.stderr)
        return 2
