"""User-specified research plan. References and co-location are not runtime proof."""
from collections import Counter, defaultdict
import re

PLAN_VERSION = "freefire-research-v1"
MAX_RESEARCH = 20000
FAMILIES = ("Player", "Team", "Chat", "Room", "Match", "Friend", "Guild", "Inventory")
# These are requested search targets, not facts about any particular build.
TARGETS = {
    "login": ["CSMajorLoginReq", "CSMajorLoginResp", "http.proto", "N2/c.smali", "LP2/c.smali", "VodkaConfig", "appKey", "appSecret", "serverId", "login", "authentication"],
    "session": ["token", "accountId", "region", "serverTimestamp", "GetLoginData"],
    "transport": ["prototcp", "account.proto", "signalingservice.proto", "socket", "connect", "host", "port", "send", "recv"],
    "messages": list(FAMILIES),
    "security": ["encryption", "Cipher", "AES", "RSA", "HMAC", "SSL", "TLS"],
    "serialization": ["protobuf", "serialization", "SerializeToString", "ParseFromString", "toByteArray", "CodedInputStream"],
    "discovery": ["API", "URL", "domain", "HTTP", "HTTPS", "TCP", "UDP", "WebSocket", "server"],
}
EXACT = {"CSMajorLoginReq", "CSMajorLoginResp", "VodkaConfig", "GetLoginData"}
FILES = {"http.proto", "account.proto", "signalingservice.proto", "N2/c.smali", "LP2/c.smali"}
FIELDS = {"appKey", "appSecret", "serverId", "token", "accountId", "region", "serverTimestamp", "host", "port"}
WORDS = re.compile(r"[A-Za-z_][A-Za-z0-9_.$]{1,179}")


def normalized(value):
    return re.sub(r"[_-]", "", value).casefold()


def spelling(term):
    # CamelCase identifiers can also occur as protobuf snake_case names.
    return re.sub(r"([a-z0-9])([A-Z])", r"\1[_-]?\2", re.escape(term))


GATE = re.compile("|".join([spelling(t) for targets in TARGETS.values() for t in targets] + [re.escape("L" + t[:-6] + ";") for t in FILES if t.endswith(".smali")]), re.I)

RULES = []
for stage, terms in TARGETS.items():
    for term in terms:
        if term in FILES:
            # Support actual paths, class descriptors and quoted source references.
            alternatives = [re.escape(term)]
            if term.endswith(".smali"):
                alternatives.append(re.escape("L" + term[:-6] + ";"))
            pattern = re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(alternatives) + r")(?![A-Za-z0-9_])", re.I)
        elif stage == "security" and term in {"AES", "RSA", "HMAC", "SSL", "TLS"}:
            pattern = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(term) + r"(?:[_/-][A-Za-z0-9_/-]+)?(?![A-Za-z0-9_])", re.I)
        elif term in FAMILIES:
            continue  # Family matching below retains the full candidate name.
        else:
            prefix = r"(?:get|set|has|clear)?" if term in FIELDS else ""
            pattern = re.compile(r"(?<![A-Za-z0-9_])" + prefix + spelling(term) + r"(?![A-Za-z0-9_])", re.I)
        RULES.append((stage, term, pattern))


class Research:
    def __init__(self):
        self.hits = []
        self.seen = set()
        self.truncated = False
        self.scopes = defaultdict(set)
        self.file_stages = defaultdict(set)
        self.calls = []
        self.call_keys = set()
        self.calls_truncated = False
        self.counts = Counter()

    def add(self, stage, target, value, location, kind="identifier reference", confidence="medium", **extra):
        key = (stage, target, value, location["source"], location.get("line"), location.get("offset"))
        if key in self.seen:
            return
        if len(self.hits) >= MAX_RESEARCH:
            self.truncated = True
            return
        self.seen.add(key)
        hit = {"value": value[:256], "stage": stage, "target": target, "kind": kind,
               "confidence": confidence, **location, **extra}
        self.hits.append(hit)
        self.counts[target] += 1
        self.file_stages[location["source"]].add(stage)
        if location.get("method_name"):
            self.scopes[(location["source"], location.get("class_name"), location["method_name"])].add(stage)

    def scan(self, text, location):
        if self.truncated or not GATE.search(text):
            return
        for stage, term, pattern in RULES:
            match = pattern.search(text)
            if match:
                evidence = text[max(0, match.start() - 120):match.end() + 240]
                confidence = "high" if term in EXACT or term in FILES else "medium"
                kind = "named target reference" if term in EXACT or term in FILES else "field reference" if term in FIELDS else "keyword marker"
                literal = {}
                if term in {"port", "region"} and not location["source"].endswith(".proto") and location.get("location_kind") != "decoded_descriptor":
                    tail = text[match.end():]
                    if term == "port":
                        assignment = re.match(r'(?::I)?["\']?\s*[:=]\s*(0x[0-9a-fA-F]{1,8}|[0-9]{1,5})\b', tail)
                        if assignment:
                            value = int(assignment.group(1), 16 if assignment.group(1).startswith("0x") else 10)
                            if 1 <= value <= 65535:
                                literal = {"port_literal_candidate": value, "bound_to_endpoint": False}
                    else:
                        assignment = re.match(r'(?::Ljava/lang/String;)?["\']?\s*[:=]\s*["\']([A-Za-z][A-Za-z0-9_-]{1,15})["\']', tail)
                        if assignment:
                            literal = {"region_literal_candidate": assignment.group(1), "bound_to_endpoint": False}
                self.add(stage, term, match.group(), {**location, "evidence": evidence}, kind, confidence,
                         note="Static reference only. Literals, if present, are unbound candidates; data flow and runtime use are not inferred.", **literal)
        for match in WORDS.finditer(text):
            identifier = match.group()
            identifier_parts = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", identifier)
            tokens = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", identifier_parts).replace("_", " ").replace(".", " ").replace("$", " ").split()
            tokens = {t.casefold() for t in tokens}
            for family in FAMILIES:
                if family.casefold() in tokens or family.casefold() + "s" in tokens:
                    self.add("messages", family, identifier, {**location, "evidence": text[max(0, match.start()-80):match.end()+160]},
                             "message-family candidate", "low",
                             note="Name-family match only; this identifier is not necessarily a serialized network message.")
        # A literal Smali invoke is an observed reference, not a proved login/session transition.
        if location.get("method_name"):
            match = re.search(r"^\s*invoke-[\w/-]+\s+.*?,\s*(L[^;]+;->[^\s]+)", text)
            if match and re.search(r"Login|GetLoginData|connect|socket|send|recv", match.group(1), re.I):
                call_key = (location["source"], location.get("line"), match.group(1))
                if call_key in self.call_keys:
                    return
                if len(self.calls) >= 10000:
                    self.calls_truncated = True
                    return
                self.call_keys.add(call_key)
                self.calls.append({"value": match.group(1), "kind": "Smali invoke reference", "confidence": "high",
                                   **location, "caller": location.get("class_name", "") + "->" + location["method_name"],
                                   "callee": match.group(1), "runtime_transition_proven": False})

    def scan_path(self, path):
        self.scan(path, {"source": path, "line": None, "offset": None, "evidence": path, "location_kind": "path"})

    def finish(self, report):
        for endpoint in report["endpoints"]:
            scope = (endpoint["source"], endpoint.get("class_name"), endpoint.get("method_name"))
            method_stages = self.scopes.get(scope, set()) if endpoint.get("method_name") else set()
            file_stages = self.file_stages.get(endpoint["source"], set())
            stages = method_stages or file_stages
            reasons = []
            if method_stages & {"login", "session", "transport"}:
                reasons.append("same_smali_method_as_research_reference")
            elif file_stages & {"login", "session", "transport"}:
                reasons.append("same_file_as_research_reference")
            if re.search(r"login|auth|session|game|match|lobby|socket", endpoint["value"], re.I):
                reasons.append("endpoint_name_hint")
            if endpoint.get("scheme", "").lower() in {"tcp", "udp", "ws", "wss"}:
                reasons.append("explicit_transport_scheme")
            endpoint["research_relevance"] = {
                "focused": any(r != "same_file_as_research_reference" for r in reasons),
                "stages": sorted(stages), "reasons": reasons,
                "strength": "same_method" if method_stages else "same_file" if file_stages else "name_only" if reasons else "unranked",
                "runtime_use_proven": False,
            }
        by_host = defaultdict(list)
        for endpoint in report["endpoints"]:
            by_host[endpoint.get("host", "").casefold().rstrip(".")].append(endpoint)
        for server in report["servers"]:
            evidence = by_host[server["host"]]
            server["research_relevance"] = {"focused": any(e["research_relevance"]["focused"] for e in evidence),
                "reasons": sorted({r for e in evidence for r in e["research_relevance"]["reasons"]}), "runtime_use_proven": False}
        report["research"] = self.hits
        report["flow"] = self.calls
        report["research_plan"] = {
            "id": PLAN_VERSION, "origin": "User-provided targets, not a verified game schema",
            "targets": [{"stage": stage, "target": target, "status": "observed" if self.counts[target] else "not_observed_in_scanned_content",
                         "occurrences": self.counts[target]} for stage, targets in TARGETS.items() for target in targets],
            "truncated": self.truncated, "invoke_references_truncated": self.calls_truncated,
            "transition_note": "Smali invokes are direct syntactic references. Co-located fields/endpoints do not establish value propagation, login ordering, or runtime transitions.",
            "missing_note": "Not observed is not proof of absence. Check coverage, obfuscation, native stripping and decoder availability.",
        }
