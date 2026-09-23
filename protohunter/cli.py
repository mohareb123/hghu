import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .analyzer import analyze
from .tooling import ToolConfig, app_directory
from .bundle import verify as verify_bundle
from .projects import ProjectStore
from .exports import export_directory
import os


def main(argv=None):
    parser = argparse.ArgumentParser(prog="protohunter", description="Local Android network / Protobuf / Smali static analysis")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("analyze", help="Analyze a file or decoded directory")
    scan.add_argument("input", type=Path)
    scan.add_argument("--scan-mode", choices=["fast", "deep"], default="deep", help="Fast skips media/fonts/textures; deep scans them")
    scan.add_argument("--profile", choices=["standard", "games"], default="standard", help="Games: 2 GiB inputs, 512 MiB members, native and split-package support")
    scan.add_argument("--decode", choices=["none", "auto", "jadx", "apktool", "both"], default="none")
    scan.add_argument("--investigate", action="store_true", help="Explainable protocol scores and static dependency graph")
    scan.add_argument("--bot-project", type=Path, help="Optional bot source directory/ZIP for lexical cross-reference; implies --investigate")
    scan.add_argument("--sections-dir", type=Path, help="Write all sections as TXT+JSON to a NEW directory; automatic alongside -o")
    scan.add_argument("-o", "--output", type=Path, help="Write JSON report (otherwise stdout)")
    web = sub.add_parser("serve", help="Open the local web workbench")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8765)
    web.add_argument("--allow-decoders", action="store_true", help="Permit external JADX/Apktool on uploads")
    doctor = sub.add_parser("doctor", help="Check optional decoders")
    doctor.add_argument("--verify-bundle", action="store_true", help="Verify bundled tool hashes; can take several seconds")
    web.add_argument("--desktop-tools", action="store_true", help="Enable trusted loopback-only tool settings and Windows local picker")
    workspace = sub.add_parser("workspace", help="Persistent JADX / Apktool / IL2CPP projects")
    workspace.add_argument("--root", type=Path, help="Workspace directory; defaults to local app data")
    actions = workspace.add_subparsers(dest="action", required=True)
    create = actions.add_parser("create"); create.add_argument("input", type=Path)
    actions.add_parser("list")
    show = actions.add_parser("show"); show.add_argument("project")
    run = actions.add_parser("run"); run.add_argument("project")
    run.add_argument("operation", choices=["jadx", "apktool", "il2cpp", "inspect", "build", "sign"])
    run.add_argument("--investigate", action="store_true")
    run.add_argument("--unit", default="main")
    for flag in ("binary-unit", "binary-member", "metadata-unit", "metadata-member", "keystore", "alias"):
        run.add_argument("--" + flag)
    run.add_argument("--store-pass-env", default="PROTOHUNTER_SIGN_STORE_PASS")
    run.add_argument("--key-pass-env", default="PROTOHUNTER_SIGN_KEY_PASS")
    for command in (scan, web, doctor, workspace):
        command.add_argument("--apktool-jar", help="Path to a trusted apktool.jar (no wrapper required)")
        command.add_argument("--java", help="Path to java.exe or java")
        for tool in ("jadx", "il2cpp", "dotnet", "apksigner", "zipalign"):
            command.add_argument("--" + tool, help="Trusted local path for " + tool)
    args = parser.parse_args(argv)
    try:
        saved = ToolConfig.load()
        config = ToolConfig(**{key: getattr(args, key) if getattr(args, key) is not None else getattr(saved, key)
                               for key in ToolConfig.__dataclass_fields__})
        if args.command == "serve":
            from .web import serve
            serve(args.host, args.port, args.allow_decoders, tool_config=config, desktop_tools=args.desktop_tools)
        elif args.command == "doctor":
            result = {"python": sys.version.split()[0], "optional_decoders": config.status(private=True)}
            if args.verify_bundle:
                result['integrity'] = verify_bundle(app_directory())
            print(json.dumps(result, indent=2))
            if args.verify_bundle and not result['integrity']['ok']:
                return 2
        elif args.command == "workspace":
            store = ProjectStore(args.root)
            if args.action == "list":
                result = store.list()
            elif args.action == "create":
                result = store.create(args.input)
            elif args.action == "show":
                result = store.load(args.project)
            else:
                options = {"investigate": args.investigate} if args.operation == "inspect" else {}
                if args.operation == "il2cpp":
                    options = {key: {"unit": getattr(args, key + "_unit"), "member": getattr(args, key + "_member")}
                               for key in ("binary", "metadata")}
                elif args.operation == "sign":
                    options = dict(keystore=args.keystore or "", alias=args.alias or "",
                                   store_pass=os.environ.get(args.store_pass_env, ""), key_pass=os.environ.get(args.key_pass_env, ""))
                result = store.run(args.project, args.operation, args.unit, config=config, **options)
            print(json.dumps(result, ensure_ascii=True, indent=2))
        else:
            result = analyze(args.input, args.decode, profile=args.profile, scan_mode=args.scan_mode, tool_config=config, investigate=args.investigate or bool(args.bot_project))
            if args.bot_project:
                from .botmatch import read_project, compare
                bot_files, omitted = read_project(args.bot_project)
                result["protocol_report"].update(compare(result["protocol_report"], bot_files))
                result["protocol_report"]["bot_comparison"]["omitted_non_source_files"] = omitted
            encoded = json.dumps(result, ensure_ascii=True, indent=2)
            sections_dir = args.sections_dir
            if args.output and args.output.resolve() == args.input.resolve():
                raise ValueError("Output must not overwrite the input")
            if sections_dir is None and args.output:
                base = args.output.with_name(args.output.stem + '.sections')
                sections_dir = base
                number = 2
                while sections_dir.exists() or sections_dir.is_symlink():
                    sections_dir = base.with_name(base.name + '-' + str(number)); number += 1
            if sections_dir and args.output and (sections_dir.resolve() == args.output.resolve() or sections_dir.resolve() in args.output.resolve().parents):
                raise ValueError("JSON report must be outside the section output directory")
            if sections_dir:
                export_directory(result, sections_dir)
                print(f"Sections (TXT + JSON): {sections_dir}", file=sys.stderr)
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
