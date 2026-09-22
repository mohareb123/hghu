"""Static evidence extraction; nothing from the target is executed or contacted."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import mmap
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import zipfile

from . import __version__
from .formats import dex_strings, descriptors, embedded_descriptors
from .native import elf_info, il2cpp_header, il2cpp_literals
from .research import Research, TARGETS
from .coverage import Coverage, sha256_buffer
from .android import resource_strings
from .tooling import ToolConfig
from .runtime import AnalysisCancelled, binary_strings, stop_decoder

MAX_INPUT = 128 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_FILES = 12000
MAX_FINDINGS = 15000
MAX_SOURCES = 4 * 1024 * 1024
ARCHIVE_EXT = {".apk", ".aab", ".zip", ".jar", ".xapk", ".apks", ".obb"}


def profile_limits(profile):
    if profile == "standard":
        return {"input": MAX_INPUT, "member": MAX_FILE, "total": MAX_TOTAL,
                "expanded": MAX_TOTAL * 2, "files": MAX_FILES, "depth": 3}
    if profile == "games":
        return {"input": 2 * 1024**3, "member": 512 * 1024**2, "total": 2 * 1024**3,
                "expanded": 4 * 1024**3, "files": 40000, "depth": 3}
    raise ValueError("Unknown analysis profile")


MEDIA_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp3", ".wav", ".ogg", ".mp4", ".webm", ".ttf", ".otf", ".woff", ".woff2", ".ktx", ".ktx2", ".astc"}
SHORT_MARKERS = tuple({x.lower().encode() for terms in TARGETS.values() for x in terms if len(x) < 6} | {b"grpc", b"quic"})
SMALL_MEMBER = 2 * 1024**2

TEXT_EXT = {".smali", ".java", ".kt", ".proto", ".xml", ".json", ".txt", ".yaml", ".yml",
            ".cs", ".h", ".c", ".cpp", ".properties", ".conf", ".cfg", ".ini", ".js", ".html", ".csv", ".gradle"}
SCHEMES = "https?|wss?|grpcs?|tcp|udp|mqtts?|amqps?|ftps?|ssh|tls|ssl|dns|rtsp|rtmp|redis|mongodb|postgres(?:ql)?"
URL_RE = re.compile(r"\b(?:" + SCHEMES + r")://[^\s\x00-\x20<>\"'`\\{}]+", re.I)
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\w.])")
DOMAIN_RE = re.compile(r"(?<![\w.@/])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|dev|app|co|ai|cloud|xyz|info|me|online|local|internal|invalid)(?::\d{1,5})?(?![\w./])", re.I)
RPC_RE = re.compile(r"(?<![\w.])(?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*/[A-Za-z_]\w*(?![\w/])")
PROTOCOLS = {
    "gRPC": r"io[./]grpc|grpc[./]|ManagedChannelBuilder|MethodDescriptor|application/grpc",
    "Protobuf": r"google(?:::|[./])protobuf|com[./]google[./]protobuf|Google\.Protobuf|protobuf_c_|GeneratedMessageLite|GeneratedMessageV3|CodedInputStream|application/(?:x-)?protobuf",
    "HTTP": r"okhttp3?[/\.]|retrofit2?[/\.]|HttpURLConnection|application/json|\bHTTP/[123]",
    "WebSocket": r"WebSocket|websocket|Sec-WebSocket",
    "MQTT": r"org[./]eclipse[./]paho|MqttClient|MqttConnectOptions",
    "TLS": r"SSL_connect|SSL_read|SSL_write|mbedtls_|SSLSocket|SSLContext|X509TrustManager|CertificatePinner|TLSv1",
    "QUIC": r"org[./]chromium[./]net|QuicEngine|quiche|\bQUIC\b",
    "TCP": r"Ljava/net/Socket;|java\.net\.Socket\b",
    "UDP": r"DatagramSocket|DatagramPacket|\b(?:sendto|recvfrom)\b",
    "KCP": r"\bikcp_(?:create|send|recv|input|output|update)\b",
    "ENet": r"\benet_(?:host|peer|packet)_\w+\b",
    "HTTP/cURL": r"\bcurl_(?:easy|multi|global)_\w+\b",
}
COMPILED_PROTOCOLS = {name: re.compile(pattern) for name, pattern in PROTOCOLS.items()}


def tools(config=None):
    return (config or ToolConfig()).status()


class Analyzer:
    def __init__(self, profile="standard", scan_mode="deep", tool_config=None, progress=None, cancel=None, input_digest=None):
        if scan_mode not in {"fast", "deep"}:
            raise ValueError("Unknown scan mode")
        self.scan_mode = scan_mode
        self.tool_config = tool_config or ToolConfig()
        self.progress = progress
        self.cancel = cancel
        self.input_digest = input_digest
        self.last_progress = 0
        self.current_stage = "starting"
        self.current_file = ""
        self.skipped_media = 0
        self.small_members = 0
        self.research = Research()
        self.coverage = Coverage()
        self.profile = profile
        self.limits = profile_limits(profile)
        self.expanded = 0
        self.entries_seen = 0
        self.decoder_runs = 0
        self.decode_mode = "none"
        self.started = time.monotonic()
        self.report = {"version": __version__, "generated_at": datetime.now(timezone.utc).isoformat(),
                       "input": {}, "endpoints": [], "protocols": [], "protobuf": [], "smali": [],
                       "sources": [], "native": [], "bundles": [], "servers": [], "warnings": [], "files": [], "summary": {},
                       "limitations": [
                           "The Free Fire research plan contains user-specified search targets, not a validated build-specific schema.",
                           "A full byte hash does not imply complete semantic analysis or decryption. Consult the coverage ledger.",
                           "ELF symbols, string co-location and server role hints do not establish runtime call relationships.",
                           "The built-in IL2CPP parser reads standard string tables only. External Il2CppDumper type layouts are not original C# method bodies.",
                           "Native embedded descriptors are bounded carving candidates; completeness is not guaranteed.",
                           "Static evidence is not proof that a server is active or a protocol is used at runtime.",
                           "Encrypted, obfuscated or dynamically assembled values may not be recoverable.",
                           "DEX mode reads strings only. Actual Smali disassembly requires Apktool.",
                           "Generated Protobuf class markers do not reconstruct a complete .proto schema.",
                           "Descriptors preserve field/service structure here, not all options, extensions or source comments.",
                           "Domain and bare-IP matches are candidates and may include non-network constants."]}
        self.seen = set()
        self.total = 0
        self.source_bytes = 0
        self.file_count = 0
        self.finding_count = 0
        self.truncated = False

    def check(self):
        if self.cancel and self.cancel():
            raise AnalysisCancelled("Analysis cancelled")

    def emit(self, stage=None, source=None, **extra):
        self.check()
        stage = stage or self.current_stage
        source = source if source is not None else self.current_file
        changed = (stage, source) != (self.current_stage, self.current_file)
        self.current_stage, self.current_file = stage, source
        now = time.monotonic()
        if self.progress and (changed or now - self.last_progress >= 0.2):
            self.last_progress = now
            self.progress({"stage": stage, "file": source, "files_scanned": self.file_count,
                           "bytes_scanned": self.total, "entries_seen": self.entries_seen,
                           "skipped_media": self.skipped_media, **extra})

    def skip_media(self, name, size):
        self.check()
        if self.scan_mode == "fast" and Path(name).suffix.lower() in MEDIA_EXT:
            self.skipped_media += 1
            self.coverage.add(name, size, "skipped", reason="Fast mode: media/font/texture extension filter; content not read")
            self.emit("enumerating", name)
            return True
        return False

    def warn(self, text):
        if text not in self.report["warnings"] and len(self.report["warnings"]) < 100:
            self.report["warnings"].append(text)

    def add(self, group, value, kind, location, confidence="medium", **extra):
        if group == "protobuf" and extra.get("descriptor"):
            # Scan parsed names independently of raw binary string boundaries.
            stack = [extra["descriptor"]]
            visited = 0
            while stack and visited < 50000 and not self.research.truncated:
                item = stack.pop()
                visited += 1
                if isinstance(item, dict):
                    stack.extend(item.values())
                elif isinstance(item, list):
                    stack.extend(item)
                elif isinstance(item, str):
                    self.research.scan(item, {**location, "line": None, "location_kind": "decoded_descriptor",
                                             "descriptor_name": extra["descriptor"]["name"]})
        key = (group, value, kind, location["source"], location.get("line"), location.get("offset"))
        if key in self.seen:
            return
        if self.finding_count >= MAX_FINDINGS:
            self.truncated = True
            self.warn("Finding limit reached; results are partial.")
            return
        self.seen.add(key)
        self.report[group].append({"value": value[:2048], "kind": kind, "confidence": confidence,
                                   **location, **extra})
        self.finding_count += 1

    def scan_line(self, text, source, line=None, offset=None, context=None):
        target_location = {"source": source, "line": line, "offset": offset, "evidence": text[:600], **(context or {})}
        self.research.scan(text, target_location)
        if self.truncated:
            return
        # Bound work per line while keeping all chunks of long text visible to the scanner.
        location = {"source": source, "line": line, "offset": offset, "evidence": text.strip()[:600], **(context or {})}
        urls = []
        for match in URL_RE.finditer(text):
            value = match.group().rstrip(".,);")
            if value.endswith("]") and value.count("]") > value.count("["):
                value = value[:-1]
            try:
                parsed = urlsplit(value)
                host, port = parsed.hostname, parsed.port
                if not host or len(host) > 253:
                    continue
            except ValueError:
                continue
            urls.append((match.start(), match.end()))
            self.add("endpoints", value, "url", location, "high", host=host, port=port, scheme=parsed.scheme)
            self.add("protocols", parsed.scheme.upper(), "URI scheme", location, "high")
        def in_url(match):
            return any(a <= match.start() < b for a, b in urls)
        for match in IP_RE.finditer(text):
            if in_url(match):
                continue
            value = match.group()
            host, _, port = value.partition(":")
            try:
                address = ipaddress.ip_address(host)
                if port and not 1 <= int(port) <= 65535:
                    continue
            except ValueError:
                continue
            self.add("endpoints", value, "ip", location, "medium" if port else "low", host=host,
                     port=int(port) if port else None, private=address.is_private)
        for match in DOMAIN_RE.finditer(text):
            if in_url(match):
                continue
            value = match.group()
            host, _, port = value.partition(":")
            if port and not 1 <= int(port) <= 65535:
                continue
            self.add("endpoints", value, "domain candidate", location, "low", host=host, port=int(port) if port else None)
        for name, pattern in COMPILED_PROTOCOLS.items():
            if pattern.search(text):
                self.add("protocols", name, "code marker", location)
        if COMPILED_PROTOCOLS["Protobuf"].search(text):
            self.add("protobuf", "Protobuf runtime / generated-code marker", "generated-code marker", location,
                     "medium", note="Indicator only; a full schema cannot be inferred from this marker.")
        for match in RPC_RE.finditer(text):
            if not in_url(match):
                self.add("protobuf", match.group(), "RPC path candidate", location, "low")
        # Generated Java/Smali often retains field numbers even with the lite runtime.
        for match in re.finditer(r"\b([A-Z][A-Z0-9_]*)_FIELD_NUMBER(?::I)?\s*=\s*(0x[0-9a-fA-F]{1,8}|[0-9]{1,10})\b", text):
            number = int(match.group(2), 16 if match.group(2).startswith("0x") else 10)
            if 0 < number <= 536870911:
                self.add("protobuf", match.group(1) + " = " + str(number), "field-number constant", location,
                         "medium", field_name=match.group(1), field_number=number,
                         note="Generated constant candidate. Field type and enclosing message are not inferred.")
        # Retrofit path annotations in Java/Kotlin or single-line Smali representations.
        for match in re.finditer(r'@(?:[\w.]*\.)?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"([^"\n]+)"', text):
            self.add("endpoints", match.group(2), "relative HTTP route", location, "high", method=match.group(1))

    def consume(self, name, data, digest=None):
        self.emit("scanning", name)
        if self.file_count >= self.limits["files"] or self.total + len(data) > self.limits["total"]:
            self.warn("File/expanded-byte budget reached; some files were skipped.")
            self.coverage.add(name, len(data), "skipped", reason="File/content-byte budget reached")
            return False
        self.file_count += 1
        self.total += len(data)
        suffix = Path(name).suffix.lower()
        self.report["files"].append({"path": name, "size": len(data)})
        row = self.coverage.add(name, len(data), bytes_hashed=len(data), sha256=digest or sha256_buffer(data, check=self.check))
        self.research.scan_path(name)
        if suffix in {".pb", ".desc", ".protoset", ".bin"} and len(data) <= 8 * 1024**2:
            row["methods"].append("descriptor_probe")
            try:
                for descriptor in descriptors(data):
                    self.add("protobuf", descriptor["name"], "descriptor", {"source": name, "line": None,
                             "offset": 0, "evidence": "Parsed protobuf file descriptor"}, "high", descriptor=descriptor)
            except (ValueError, TypeError, UnicodeError, AttributeError, IndexError) as exc:
                if suffix in {".desc", ".protoset"}:
                    row.update(status="partial", reason=f"Descriptor parser: {exc}")
                    self.warn(f"Could not parse descriptor {name}: {exc}")
        if suffix in {".desc", ".protoset"} and len(data) > 8 * 1024**2:
            row.update(status="partial", reason="Descriptor parser size limit; string carving only")
        if data[:4] == b"\x7fELF" or suffix == ".so":
            row["methods"].append("ELF_sections_symbols_and_descriptor_candidates")
            self.scan_native(name, data)
        if data[:4] == b"\xaf\x1b\xb1\xfa" or name.endswith("global-metadata.dat"):
            row["methods"].append("IL2CPP_standard_string_tables")
            self.scan_metadata(name, data)
        if len(data) >= 8 and data[:2] in (b"\x03\x00", b"\x02\x00") and suffix in {".xml", ".arsc"}:
            row["methods"].append("Android_binary_resource_string_pools")
            try:
                for offset, text in resource_strings(data):
                    self.scan_text(text, name, offset=offset)
            except ValueError as exc:
                row["status"], row["reason"] = "partial", str(exc)
                self.warn(f"Android resources {name}: {exc}")
        if data[:4] == b"dex\n" or suffix == ".dex":
            row["methods"].append("DEX_string_table_only_not_instructions")
            try:
                for offset, text in dex_strings(data):
                    self.scan_text(text, name, offset=offset)
                    if ".proto" in text and text.startswith("\n"):
                        try:
                            for descriptor in descriptors(text.encode("latin-1")):
                                self.add("protobuf", descriptor["name"], "embedded DEX descriptor",
                                         {"source": name, "line": None, "offset": offset,
                                          "evidence": "Parsed descriptor from a single DEX string"},
                                         "high", descriptor=descriptor)
                        except (ValueError, TypeError, UnicodeError, AttributeError, IndexError):
                            pass
            except (ValueError, UnicodeError) as exc:
                self.warn(f"DEX {name}: {exc}. Remaining strings not read.")
                row["status"], row["reason"] = "partial", str(exc)
            self.finish_file_coverage(row)
            return True
        is_text = suffix in TEXT_EXT and b"\0" not in data[:8192] and len(data) <= MAX_FILE
        if suffix in TEXT_EXT and len(data) > MAX_FILE:
            self.warn(f"Large text scanned as strings, without full source preview: {name}")
        if suffix == ".json" and len(data) < 2 * 1024**2:
            self.scan_bundle_manifest(name, data[:])
        if is_text:
            row["methods"].append("text_lines_and_research_markers")
            text = data[:].decode("utf-8-sig", errors="replace")
            self.save_source(name, suffix.lstrip("."), text)
            if suffix == ".smali":
                row["methods"].append("Smali_inventory_and_invoke_references")
                self.scan_smali(text, name)
            if suffix == ".proto":
                package = re.search(r"\bpackage\s+([\w.]+)\s*;", text)
                self.add("protobuf", name.rsplit("!", 1)[-1], "proto source", {"source": name, "line": 1,
                         "offset": None, "evidence": text[:600]}, "high",
                         package=package.group(1) if package else "",
                         declarations=re.findall(r"\b(message|enum|service|rpc)\s+(\w+)", text),
                         schema=text[:128000], schema_truncated=len(text) > 128000)
            context = {}
            for number, line in enumerate(text.splitlines(), 1):
                if suffix == ".smali":
                    class_match = re.match(r"\s*\.class\s+.*?(L[^;]+;)", line)
                    method_match = re.match(r"\s*\.method\s+(.+)", line)
                    if class_match:
                        context["class_name"] = class_match.group(1)
                    if method_match:
                        context["method_name"] = method_match.group(1)
                    if line.strip() == ".end method":
                        context.pop("method_name", None)
                self.scan_text(line, name, line=number, context=context)
        else:
            row["methods"].append("ASCII_UTF16LE_string_carving_not_full_binary_semantics")
            for utf16 in (False, True):
                for offset, raw in binary_strings(data, utf16=utf16, check=self.check):
                    if self.truncated and self.research.truncated:
                        break
                    ascii_raw = raw[::2] if utf16 else raw
                    # Preserve short research/protocol tokens and tiny domains, without
                    # running every extractor on arbitrary 3–5 byte machine-code fragments.
                    if len(ascii_raw) < 6 and b"." not in ascii_raw:
                        lower = ascii_raw.lower()
                        if not any(marker in lower for marker in SHORT_MARKERS):
                            continue
                    self.scan_text(ascii_raw.decode("ascii"), name, offset=offset)
        self.finish_file_coverage(row)
        return True

    def finish_file_coverage(self, row):
        if self.truncated or self.research.truncated or self.research.calls_truncated:
            row["status"] = "partial"
            row["reason"] = "Extraction finding limit reached; the full-file hash is independent of extraction."

    def scan_text(self, text, name, line=None, offset=None, context=None):
        self.emit()
        for start in range(0, len(text), 7900):
            self.scan_line(text[start:start + 8192].replace("\\/", "/"), name, line, offset, context)
            if self.truncated and self.research.truncated:
                break

    def save_source(self, path, language, text):
        content = text[:96000]
        size = len(content.encode("utf-8"))
        if self.source_bytes + size <= MAX_SOURCES and len(self.report["sources"]) < 500:
            self.report["sources"].append({"path": path, "language": language, "content": content,
                                            "truncated": len(content) < len(text)})
            self.source_bytes += size
        else:
            self.warn("Source preview budget reached; not all scanned files have previews.")

    def scan_smali(self, text, name):
        class_match = re.search(r"(?m)^\s*\.class\s+.*?(L[^;]+;)", text)
        class_name = class_match.group(1) if class_match else name
        methods = re.findall(r"(?m)^\s*\.method\s+(.+)", text)
        fields = re.findall(r"(?m)^\s*\.field\s+(.+)", text)
        invokes = []
        for number, line in enumerate(text.splitlines(), 1):
            match = re.search(r"^\s*invoke-[\w/-]+\s+.*?,\s*(L\S+;->\S+)", line)
            if match and len(invokes) < 500:
                invokes.append({"target": match.group(1), "line": number})
        location = {"source": name, "line": 1, "offset": None, "evidence": class_name}
        self.add("smali", class_name, "class", location, "high", methods=methods[:1000],
                 fields=fields[:1000], invokes=invokes, method_count=len(methods), field_count=len(fields))
        # Apktool emits Retrofit annotation values on a separate line.
        for match in re.finditer(r"\.annotation[^\n]*Lretrofit2?/http/(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS);(.*?)\.end annotation", text, re.S):
            value = re.search(r'\bvalue\s*=\s*"([^"\n]+)"', match.group(2))
            if value:
                self.add("endpoints", value.group(1), "relative HTTP route",
                         {"source": name, "line": text[:match.start()].count("\n") + 1,
                          "offset": None, "evidence": match.group()[:600]}, "high", method=match.group(1))

    def scan_native(self, name, data):
        location = {"source": name, "line": None, "offset": 0, "evidence": "ELF header and section tables"}
        try:
            info = elf_info(data)
            self.coverage.entries[-1]["notes"] = info["notes"]
            if any("No section table" in note or "Symbol scan capped" in note for note in info["notes"]):
                self.coverage.entries[-1].update(status="partial", reason="ELF symbols unavailable or scan capped; see notes")
            self.add("native", name.rsplit("/", 1)[-1], "ELF library", location, "high", elf=info)
            for symbol in info["network_symbols"]:
                self.scan_text(symbol["name"], name, offset=symbol["string_offset"])
                if symbol["name"] in {"socket", "connect", "getaddrinfo", "send", "recv"}:
                    self.add("protocols", "Socket API", "native symbol",
                             {"source": name, "line": None, "offset": symbol["string_offset"],
                              "evidence": symbol["name"] + " (" + symbol["role"] + ")"}, "medium",
                             note="Socket API presence does not determine TCP versus UDP or prove execution.")
            for offset, descriptor in embedded_descriptors(data):
                self.add("protobuf", descriptor["name"], "native descriptor candidate",
                         {"source": name, "line": None, "offset": offset,
                          "evidence": "Heuristically carved raw FileDescriptorProto; boundary may be incomplete"},
                         "medium", descriptor=descriptor)
        except (ValueError, TypeError) as exc:
            self.coverage.entries[-1].update(status="partial", reason=f"ELF parser: {exc}")
            self.warn(f"ELF {name}: {exc}")

    def scan_metadata(self, name, data):
        try:
            info = il2cpp_header(data)
            self.add("native", "IL2CPP metadata v" + str(info["version"]), "Unity metadata",
                     {"source": name, "line": None, "offset": 0, "evidence": "Validated metadata magic and string table ranges"},
                     "high", metadata=info)
            if info["literal_count"] > 100000:
                self.coverage.entries[-1].update(status="partial", reason="IL2CPP literal count limit")
                self.warn(f"IL2CPP literal scan capped at 100000: {name}")
            for offset, text in il2cpp_literals(data, info):
                self.scan_text(text, name, offset=offset)
                if self.truncated and self.research.truncated:
                    break
        except ValueError as exc:
            self.coverage.entries[-1].update(status="partial", reason=f"IL2CPP parser: {exc}")
            self.warn(f"IL2CPP {name}: {exc}. Encrypted/custom metadata is not decoded.")

    def scan_bundle_manifest(self, name, data):
        if name.rsplit("/", 1)[-1].rsplit("!", 1)[-1] not in {"manifest.json", "info.json"}:
            return
        try:
            manifest = json.loads(data)
            if not isinstance(manifest, dict) or not any(k in manifest for k in ("package_name", "split_apks", "xapk_version")):
                return
            details = {key: manifest[key] for key in ("package_name", "name", "version_name", "version_code", "xapk_version", "split_apks", "expansions") if key in manifest}
            self.add("bundles", str(manifest.get("package_name", "Bundle manifest")), "bundle manifest",
                     {"source": name, "line": None, "offset": 0, "evidence": "Declared bundle metadata (not a verified Android signature)"},
                     "high", manifest=details)
        except (ValueError, UnicodeError, RecursionError):
            self.warn(f"Invalid bundle JSON: {name}")

    def consume_path(self, name, path, digest=None):
        self.research.scan_path(name)
        size = path.stat().st_size
        if self.skip_media(name, size):
            return
        if size > self.limits["member"]:
            self.coverage.add(name, size, "skipped", reason="Individual file size limit")
            self.warn(f"Large file skipped: {name}")
            return
        if size == 0:
            self.consume(name, b"")
            return
        with path.open("rb") as stream:
            with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
                self.consume(name, data, digest=digest)

    def archive(self, path, prefix="", depth=0):
        self.emit("enumerating", prefix or path.name)
        if depth > self.limits["depth"]:
            self.coverage.add(prefix.rstrip("!"), path.stat().st_size, "unexpanded", "archive", "Archive depth limit")
            self.warn(f"Archive depth limit reached: {prefix}")
            return
        container_name = prefix.rstrip("!") or self.report["input"]["name"]
        archive_row = self.coverage.add(container_name, path.stat().st_size, "enumerated", "archive", methods=["ZIP_directory_and_bounded_members"])
        self.research.scan_path(container_name)
        self.add("bundles", prefix.rstrip("!") or self.report["input"]["name"], "archive",
                 {"source": prefix.rstrip("!") or self.report["input"]["name"], "line": None,
                  "offset": 0, "evidence": "ZIP container; member contents inspected without installation"}, "high",
                 depth=depth)
        with zipfile.ZipFile(path) as archive:
            # Sequential, disposable staging: never use a member name as a filesystem path.
            infos = archive.infolist()
            archive_row["declared_entries"] = len(infos)
            for entry_index, info in enumerate(infos):
                self.check()
                if self.entries_seen >= self.limits["files"]:
                    self.warn("Archive entry budget reached; results are partial.")
                    archive_row.update(status="inventory_incomplete", reason="Global entry budget", unlisted_direct_entries=len(infos) - entry_index)
                    self.coverage.inventory_complete = False
                    break
                self.entries_seen += 1
                if info.is_dir():
                    continue
                local_name = info.filename.replace("\\", "/")
                name = prefix + local_name
                self.research.scan_path(name)
                if (local_name.startswith("/") or ".." in PurePosixPath(local_name).parts
                        or re.match(r"^[A-Za-z]:", local_name) or "\0" in local_name
                        or ((info.external_attr >> 16) & 0o170000) == 0o120000):
                    self.coverage.add(name, info.file_size, "skipped", reason="Unsafe path or symlink; not read")
                    if Path(name).suffix.lower() in ARCHIVE_EXT:
                        self.coverage.inventory_complete = False
                    self.warn(f"Unsafe archive entry skipped: {name[:160]}")
                    continue
                if self.skip_media(name, info.file_size):
                    continue
                suffix = Path(local_name).suffix.lower()
                is_container = suffix in ARCHIVE_EXT
                limit = self.limits["input"] if is_container else self.limits["member"]
                if info.file_size > limit or info.file_size > max(info.compress_size, 1) * 250:
                    self.coverage.add(name, info.file_size, "unexpanded" if is_container else "skipped",
                                      "archive" if is_container else "file", "Member size or compression-ratio limit")
                    self.warn(f"Large/high-ratio archive entry skipped: {name[:160]}")
                    continue
                if self.expanded + info.file_size > self.limits["expanded"] or self.total >= self.limits["total"]:
                    self.warn("Archive analysis budget reached; results are partial.")
                    self.coverage.add(name, info.file_size, "unexpanded" if is_container else "skipped",
                                      "archive" if is_container else "file", "Shared expanded/content-byte budget")
                    continue
                try:
                    self.emit("expanding", name, completed_bytes=0, total_bytes=info.file_size)
                    if not is_container and info.file_size <= SMALL_MEMBER:
                        with archive.open(info) as stream:
                            data = stream.read(SMALL_MEMBER + 1)
                        self.expanded += len(data)
                        if len(data) > SMALL_MEMBER or self.expanded > self.limits["expanded"]:
                            raise ValueError("Small-member/expanded-byte limit reached")
                        self.small_members += 1
                        self.consume(name, data)
                        continue
                    with tempfile.TemporaryDirectory(prefix="protohunter-member-") as tmp:
                        staged = Path(tmp, "member" + suffix)
                        with archive.open(info) as stream, staged.open("wb") as output:
                            count = 0
                            staged_digest = hashlib.sha256()
                            while True:
                                self.emit("expanding", name, completed_bytes=count, total_bytes=info.file_size)
                                chunk = stream.read(min(1024**2, limit - count + 1))
                                if not chunk:
                                    break
                                count += len(chunk)
                                self.expanded += len(chunk)
                                if count > limit or self.expanded > self.limits["expanded"]:
                                    raise ValueError("Expanded-byte limit reached")
                                staged_digest.update(chunk)
                                output.write(chunk)
                        if is_container and zipfile.is_zipfile(staged):
                            self.archive(staged, name + "!", depth + 1)
                            if suffix == ".apk" and self.decode_mode != "none":
                                self.decode(staged, self.decode_mode, name + "!")
                        elif is_container and suffix != ".obb":
                            self.coverage.add(name, info.file_size, "unexpanded", "archive", "Invalid nested ZIP container")
                            self.warn(f"Invalid nested archive skipped: {name}")
                        else:
                            if suffix == ".obb":
                                self.warn(f"Non-ZIP OBB: strings only; Unity asset bundles are not unpacked: {name}")
                            self.consume_path(name, staged, digest=staged_digest.hexdigest())
                except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, EOFError) as exc:
                    self.coverage.add(name, info.file_size, "unexpanded" if is_container else "error",
                                      "archive" if is_container else "file", str(exc))
                    self.warn(f"Unreadable entry {name[:160]}: {exc}")

    def directory(self, path, prefix=""):
        for root, directories, names in os.walk(path, followlinks=False):
            for d in directories:
                if Path(root, d).is_symlink():
                    self.coverage.add(prefix + Path(root, d).relative_to(path).as_posix(), None, "unexpanded", "directory", "Symlink not followed")
            directories[:] = sorted(d for d in directories if not Path(root, d).is_symlink())
            for name in sorted(names):
                self.check()
                item = Path(root, name)
                if item.is_symlink() or not item.is_file():
                    self.coverage.add(prefix + item.relative_to(path).as_posix(), None, "skipped", reason="Symlink or non-regular file")
                    continue
                if self.file_count >= self.limits["files"] or self.total >= self.limits["total"]:
                    self.warn("Directory analysis budget reached; results are partial.")
                    self.coverage.add(prefix or path.name, None, "inventory_incomplete", "directory", "Directory traversal stopped at shared budget")
                    return
                relative = prefix + item.relative_to(path).as_posix()
                try:
                    if item.suffix.lower() in ARCHIVE_EXT and zipfile.is_zipfile(item):
                        if item.stat().st_size > self.limits["input"]:
                            self.coverage.add(relative, item.stat().st_size, "unexpanded", "archive", "Archive input size limit")
                            self.warn(f"Large archive skipped: {relative}")
                            continue
                        self.archive(item, relative + "!")
                        if item.suffix.lower() == ".apk" and self.decode_mode != "none" and not prefix:
                            self.decode(item, self.decode_mode, relative + "!")
                    else:
                        self.consume_path(relative, item)
                except (OSError, ValueError, zipfile.BadZipFile) as exc:
                    self.coverage.add(relative, None, "error", reason=str(exc))
                    self.warn(f"Unreadable file {relative}: {exc}")

    def decode(self, path, mode, prefix=""):
        if self.decoder_runs >= 8:
            self.warn("External decode limit reached (8 inputs); remaining splits use direct analysis only.")
            return
        self.decoder_runs += 1
        selected = ["jadx", "apktool"] if mode in {"auto", "both"} else [mode]
        for tool in selected:
            if tool == "apktool" and path.suffix.lower() != ".apk":
                self.warn("Apktool requires an APK; standalone DEX needs a separate disassembler such as baksmali.")
                continue
            try:
                executable = self.tool_config.command(tool)
            except ValueError as exc:
                self.warn(str(exc))
                continue
            if not executable:
                self.warn(f"{tool} not installed; external decoding skipped.")
                continue
            with tempfile.TemporaryDirectory(prefix="protohunter-decode-") as tmp:
                output = Path(tmp, "decoded")
                command = (executable + ["--no-res", "-d", str(output), str(path.resolve())] if tool == "jadx"
                           else executable + ["d", "-f", "-o", str(output), str(path.resolve())])
                if tool == "apktool" and self.scan_mode == "fast":
                    command.insert(len(executable) + 1, "-r")
                    self.warn("Fast mode: Apktool -r skips resource decoding; direct resource-string scanning is still attempted.")
                proc = None
                try:
                    with tempfile.TemporaryFile() as log:
                        self.emit("decoding", prefix or path.name, decoder=tool)
                        proc = subprocess.Popen(command, stdout=log, stderr=log,
                                                start_new_session=os.name != "nt",
                                                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
                        deadline = time.monotonic() + 180
                        while proc.poll() is None:
                            self.emit("decoding", prefix or path.name, decoder=tool)
                            if time.monotonic() >= deadline:
                                stop_decoder(proc)
                                self.warn(f"{tool} exceeded 180 seconds; output may be incomplete.")
                                break
                            try:
                                proc.wait(timeout=0.2)
                            except subprocess.TimeoutExpired:
                                pass
                        if proc.returncode:
                            log.seek(0)
                            detail = log.read(1800).decode("utf-8", "replace")
                            self.warn(f"{tool} exited with code {proc.returncode}: {detail}")
                    if output.is_dir():
                        self.directory(output, prefix=prefix + f"{tool}/")
                except AnalysisCancelled:
                    if proc:
                        stop_decoder(proc)
                    raise
                except OSError as exc:
                    self.warn(f"Could not start {tool}: {exc}")
                finally:
                    if proc and proc.poll() is None:
                        stop_decoder(proc)

    def correlate_servers(self):
        """Group direct host evidence, not a runtime call graph or data-flow inference."""
        hosts = {}
        for endpoint in self.report["endpoints"]:
            host = endpoint.get("host", "").lower().rstrip(".")
            if host:
                hosts.setdefault(host, []).append(endpoint)
        markers = {}
        for marker in self.report["protocols"]:
            markers.setdefault(marker["source"], set()).add(marker["value"])
        for host, evidence in hosts.items():
            files = sorted({e["source"] for e in evidence})
            hints = set()
            for e in evidence:
                for role, pattern in {"authentication": r"auth|login|oauth|token", "telemetry": r"telemetry|analytics|metrics|crash",
                                      "content/update": r"cdn|patch|update|asset|download", "realtime": r"realtime|socket|match|lobby"}.items():
                    if re.search(pattern, e["value"], re.I):
                        hints.add(role)
            self.report["servers"].append({"value": host, "kind": "host evidence group",
                "confidence": max((e["confidence"] for e in evidence), key={"low": 0, "medium": 1, "high": 2}.get),
                "source": files[0], "line": None, "offset": None,
                "evidence": "Grouped by identical normalized host, not by inferred network activity",
                "host": host, "ports": sorted({e["port"] for e in evidence if e.get("port") is not None}),
                "schemes": sorted({e["scheme"] for e in evidence if e.get("scheme")}),
                "sources": files, "occurrences": len(evidence),
                "role_hints": sorted(hints), "role_hint_confidence": "low",
                "colocated_protocol_markers": sorted(set().union(*(markers.get(f, set()) for f in files))),
                "locations": [{k: e.get(k) for k in ("value", "source", "line", "offset", "confidence", "class_name", "method_name")} for e in evidence[:200]],
                "locations_truncated": len(evidence) > 200,
                "note": "Role hints come from names only. Protocol markers merely share a source file; no call/data-flow relationship is proven."})

    def run(self, path, decode="none", display_name=None, extra_inputs=None):
        path = Path(path)
        if decode not in {"none", "auto", "jadx", "apktool", "both"}:
            raise ValueError("Unsupported decoder")
        if not path.exists():
            raise ValueError("Input does not exist")
        self.decode_mode = decode
        self.report["input"] = {"name": display_name or path.name, "decode": decode, "profile": self.profile, "scan_mode": self.scan_mode}
        if self.scan_mode == "fast":
            self.warn("Fast mode skips media/font/texture files by extension. Use deep mode to include them; see coverage.")
        self.report["limits"] = self.limits.copy()
        if path.is_dir():
            self.report["input"]["kind"] = "directory"
            self.directory(path)
        else:
            size = path.stat().st_size
            if size > self.limits["input"]:
                raise ValueError(f"Input exceeds {self.limits['input'] // 1024**2} MiB for this profile")
            digest_value = self.input_digest
            if not digest_value:
                digest = hashlib.sha256()
                completed = 0
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        completed += len(chunk)
                        self.emit("hashing", display_name or path.name, completed_bytes=completed, total_bytes=size)
                        digest.update(chunk)
                digest_value = digest.hexdigest()
            self.report["input"].update(size=size, sha256=digest_value, kind=path.suffix.lower().lstrip("."))
            if zipfile.is_zipfile(path):
                try:
                    self.archive(path)
                except zipfile.BadZipFile as exc:
                    raise ValueError(f"Invalid ZIP/APK archive: {exc}") from exc
            elif path.suffix.lower() in ARCHIVE_EXT - {".obb"}:
                raise ValueError("Invalid ZIP/APK archive")
            else:
                if path.suffix.lower() == ".obb":
                    self.warn("Non-ZIP OBB: strings only; Unity asset bundles are not unpacked.")
                self.consume_path(display_name or path.name, path, digest=digest_value)
            if decode != "none":
                if path.suffix.lower() in {".apk", ".dex"}:
                    self.decode(path, decode)
                elif path.suffix.lower() not in ARCHIVE_EXT:
                    self.warn("External decoders are only used for APK/DEX input or APK members of bundles.")
            elif path.suffix.lower() in {".apk", ".dex", ".aab", ".xapk", ".apks"}:
                self.warn("String/asset analysis only. Enable external decoding for Java/Smali output (APK/DEX).")
        if extra_inputs:
            self.report['input']['derived_views'] = []
            for label, directory in extra_inputs:
                self.check()
                self.directory(Path(directory), prefix=label + '/')
                self.report['input']['derived_views'].append(label)
            self.warn('Derived decompiler views share extraction budgets; their bytes are not unique original-package bytes.')
        self.emit("reporting", self.report["input"]["name"])
        self.correlate_servers()
        self.research.finish(self.report)
        if self.research.truncated:
            self.warn("Research finding limit reached (20000); target results are partial.")
        self.report["coverage"] = self.coverage.entries
        self.report["coverage_summary"] = self.coverage.summary()
        self.report["coverage_summary"]["input_sha256"] = self.report["input"].get("sha256")
        self.report["coverage_summary"]["root_input_bytes_hashed"] = self.report["input"].get("size", 0)
        endpoints = self.report["endpoints"]
        self.report["summary"] = {
            "files_scanned": self.file_count, "bytes_scanned": self.total,
            "skipped_media": self.skipped_media, "small_members_in_memory": self.small_members,
            "expanded_bytes": self.expanded, "archive_entries": self.entries_seen,
            "native_modules": len(self.report["native"]), "bundle_findings": len(self.report["bundles"]),
            "research_findings": len(self.report["research"]), "invoke_references": len(self.report["flow"]),
            "focused_endpoints": sum(e["research_relevance"]["focused"] for e in self.report["endpoints"]),
            "unique_endpoints": len({(x["kind"], x["value"]) for x in endpoints}),
            "unique_hosts": len(self.report["servers"]),
            "protocols": len({x["value"] for x in self.report["protocols"]}),
            "protobuf_findings": len(self.report["protobuf"]), "smali_classes": len(self.report["smali"]),
            "findings": self.finding_count, "elapsed_seconds": round(time.monotonic() - self.started, 3),
            "endpoint_types": dict(Counter(x["kind"] for x in endpoints))}
        return self.report


def analyze(path, decode="none", display_name=None, profile="standard", scan_mode="deep", tool_config=None,
            progress=None, cancel=None, input_digest=None, extra_inputs=None):
    return Analyzer(profile, scan_mode, tool_config, progress, cancel, input_digest).run(path, decode, display_name, extra_inputs=extra_inputs)
