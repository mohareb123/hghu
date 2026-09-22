"""Portable entry point: no arguments opens the local UI; arguments use the CLI."""
import os
import sys
import threading
import webbrowser

from . import __version__
from .cli import main as cli_main
from .web import Server
from .tooling import ToolConfig


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        return cli_main(args)
    try:
        port = int(os.environ.get("PROTOHUNTER_PORT", "0"))
        if not 0 <= port <= 65535:
            raise ValueError("PROTOHUNTER_PORT must be between 0 and 65535")
        # A desktop executable must never open a public, unauthenticated listener.
        with Server(("127.0.0.1", port), allow_decoders=True, tool_config=ToolConfig.load(), desktop_tools=True) as server:
            url = f"http://127.0.0.1:{server.server_port}/"
            print(f"ProtoHunter {__version__} - local Android research", flush=True)
            print(f"Open: {url}", flush=True)
            print("Keep this window open while analyzing. Press Ctrl+C or close it to stop.", flush=True)
            print("JADX/Apktool are optional external tools, not bundled with this executable.", flush=True)
            timer = None
            if os.environ.get("PROTOHUNTER_NO_BROWSER") != "1":
                def open_browser():
                    try:
                        if not webbrowser.open(url):
                            print(f"Open your browser manually: {url}", flush=True)
                    except Exception:
                        print(f"Open your browser manually: {url}", flush=True)
                timer = threading.Timer(0.4, open_browser)
                timer.daemon = True
                timer.start()
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                print("\nProtoHunter stopped.", flush=True)
            finally:
                if timer:
                    timer.cancel()
        return 0
    except (ValueError, OSError) as exc:
        print(f"ProtoHunter could not start: {exc}", file=sys.stderr, flush=True)
        return 2
