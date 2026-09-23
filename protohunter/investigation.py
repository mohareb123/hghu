"""Explainable protocol triage. Scores rank investigation, not bot compatibility."""
from collections import Counter, defaultdict, deque
import hashlib
import ipaddress
from urllib.parse import urlsplit
import re
from .bytecode import smali_events, dex_events

CATEGORIES = ('AUTH', 'SESSION', 'SERVER_DISCOVERY', 'TRANSPORT', 'PACKET_CODEC', 'GAME', 'ROOM', 'MATCH', 'PLAYER', 'TEAM', 'FRIEND', 'GUILD', 'CHAT', 'VOICE', 'ANALYTICS', 'TELEMETRY', 'UNKNOWN')
RULES = {'login_session_call': 10, 'proto_executable_reference': 8, 'transport_path': 8,
         'token_access': 7, 'server_region_account': 7, 'caller_callee': 6,
         'packet_codec': 5, 'address_reference': 4, 'crypto_on_network_path': 3,
         'no_executable_reference': -10, 'resource_only': -8, 'unused_proto_definition': -5}
LIMITS = {'nodes': 20000, 'edges': 40000, 'candidates': 10000, 'path_depth': 24, 'evidence_per_item': 40}
NOTE = 'Investigation priority only, not bot compatibility. HIGH means a static call path to a recognized transport API, not runtime use or packet data flow. Maximum raw positive score is 58; REQUIRED and CRITICAL are unreachable under these weights.'
TRANSPORT = re.compile(r'^L(?:java/net/(?:Socket|DatagramSocket|HttpURLConnection|URLConnection);->(?:connect|send|receive|getInputStream|getOutputStream)|javax/net/ssl/SSLSocket;->(?:connect|startHandshake)|okhttp3/(?:Call|RealCall|WebSocket|OkHttpClient);->(?:execute|enqueue|send|newWebSocket)|org/java_websocket/[^;]+;->(?:connect|send)|io/grpc/[^;]+;->(?:start|sendMessage))\(')
CODEC = re.compile(r'->(?:toByteArray|writeTo|parseFrom|mergeFrom|encode|decode|serialize|deserialize|SerializeToString|ParseFromString)\(', re.I)
CRYPTO = re.compile(r'^L(?:javax/crypto/(?:Cipher|Mac)|java/security/(?:MessageDigest|Signature));->')
TOKEN = re.compile(r'->(?:get|set|put|read|write)?(?:access|refresh|session)?[_]?token(?=[:(])', re.I)
IDENTITY = re.compile(r'->(?:get|set|put|read|write)?(?:serverId|server|region|accountId|account)(?=[:(])', re.I)
ADDRESS = re.compile(r'(?:https?|wss?|tcp|udp)://[^\s"<>]+|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|\b(?:[\w-]+\.)+(?:com|net|org|io|invalid|app|dev)\b(?::\d{1,5})?|\[[0-9a-fA-F:]+\](?::\d+)?')


def addresses(text):
    seen = set()
    ipv6 = re.compile(r'(?<![\w:])[0-9a-fA-F]*:[0-9a-fA-F:]*:[0-9a-fA-F:]*(?![\w:])')
    candidates = [m.group().rstrip('.,);') for m in ADDRESS.finditer(text[:32768])]
    candidates += [m.group() for m in ipv6.finditer(text[:32768]) if '[' not in text[max(0,m.start()-1):m.start()]]
    for value in candidates[:60]:
        try:
            if '://' in value:
                parsed = urlsplit(value)
                if not parsed.hostname or (parsed.port is not None and not 1 <= parsed.port <= 65535): continue
            elif value.startswith('['):
                host, _, tail = value[1:].partition(']'); ipaddress.IPv6Address(host)
                if tail and not 1 <= int(tail[1:]) <= 65535: continue
            elif value.count(':') >= 2: ipaddress.IPv6Address(value)
            else:
                host, _, port = value.partition(':')
                if host[0].isdigit() and re.fullmatch(r'[0-9.]+',host): ipaddress.IPv4Address(host)
                if port and not 1 <= int(port) <= 65535: continue
        except ValueError: continue
        if value not in seen: seen.add(value); yield value


def classify(name):
    words = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', name).lower()
    for category, pattern in [('ANALYTICS', r'analytic|tracking|advertis'), ('TELEMETRY', r'telemetry|metric|crash'), ('AUTH', r'login|authentic|\bauth\b'), ('SESSION', r'session|token|logout'), ('SERVER_DISCOVERY', r'server.?list|discover|region|server.?address'), ('PACKET_CODEC', r'codec|serializ|encode|decode'), ('TRANSPORT', r'transport|socket|\btcp\b|\budp\b|\bhttp\b'), *[(x, x.lower()) for x in ('VOICE', 'ROOM', 'MATCH', 'PLAYER', 'TEAM', 'FRIEND', 'GUILD', 'CHAT', 'GAME')]]:
        if re.search(pattern, words): return category
    return 'UNKNOWN'


def priority(score):
    return next(label for floor, label in [(80, 'CRITICAL'), (60, 'REQUIRED'), (40, 'RELATED'), (20, 'POSSIBLE'), (0, 'UNKNOWN'), (-10**9, 'IGNORE')] if score >= floor)


def empty_report():
    return {**{k.lower(): [] for k in CATEGORIES}, 'bot_matches': [], 'missing_from_new_version': [],
            'meta': {'enabled': False, 'note': NOTE, 'score_rules': RULES, 'maximum_positive_score': sum(v for v in RULES.values() if v > 0)}}


def identity(kind, value):
    return kind + ':' + hashlib.sha256(value.encode('utf-8', errors='backslashreplace')).hexdigest()[:24]


def message_owner(owner):
    return owner.replace('$Builder;', ';')


def proto_definitions(text, package=''):
    # Structural subset, not a replacement for protoc; strings/comments cannot create fields.
    text = re.sub(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"', ' ', text)
    token = re.compile(r'\b(message|enum|service|oneof)\s+(\w+)\s*\{|([{}])|\b([A-Za-z_]\w*)\s*=\s*\d+\s*(?:\[|;)')
    stack = []; result = []
    for match in token.finditer(text):
        kind, name, brace, field = match.groups()
        if kind:
            parents = [x[1] for x in stack if x[0] == 'message']
            row = {'name': '.'.join(([package] if package else []) + parents + [name]), 'fields': []} if kind == 'message' else None
            if row: result.append(row)
            stack.append((kind, name, row))
        elif brace == '{': stack.append(('other', '', None))
        elif brace == '}':
            if stack: stack.pop()
        elif field and stack and stack[-1][0] in {'message', 'oneof'}:
            owner = next((x[2] for x in reversed(stack) if x[0] == 'message'), None)
            if owner is not None: owner['fields'].append(field)
    return [(row['name'], row['fields']) for row in result]


class Investigation:
    def __init__(self, check=lambda: None):
        self.check = check
        self.nodes = {}; self.edges = []; self.edge_keys = set(); self.items = {}
        self.calls = defaultdict(set); self.reverse = defaultdict(set)
        self.method_features = defaultdict(lambda: defaultdict(list))
        self.item_methods = defaultdict(set); self.definitions = defaultdict(set)
        self.warnings = []; self.partial = False; self.file_count = 0

    def warn(self, message):
        self.partial = True
        if len(self.warnings) < 100: self.warnings.append(message)

    def node(self, kind, value):
        key = identity(kind, value)
        if key not in self.nodes:
            if len(self.nodes) >= LIMITS['nodes']:
                self.partial = True; return None
            self.nodes[key] = {'id': key, 'kind': kind, 'name': value}
        return key

    def edge(self, source, target, kind, location):
        if not source or not target: return
        key = (source, target, kind, location['source'], location.get('line'), location.get('offset'))
        if key in self.edge_keys: return
        if len(self.edges) >= LIMITS['edges']:
            self.partial = True; return
        self.edge_keys.add(key)
        self.edges.append({'id': 'e' + str(len(self.edges)), 'source': source, 'target': target, 'kind': kind,
                           'evidence': location, 'runtime_proven': False})

    def candidate(self, name, kind, location, proto=False):
        key = identity('entity', name)
        if key not in self.items:
            if len(self.items) >= LIMITS['candidates']: self.partial = True; return None
            node = self.node('entity', name)
            if not node: return None
            self.items[key] = {'id': key, 'name': name, 'kind': kind, 'proto': proto, 'evidence': [], 'fields': set(), 'methods': set(), 'features': set(), 'opcodes': set(), 'constants': {}, 'resource_only': True, 'evidence_truncated': False}
        row = self.items[key]; row['proto'] |= proto
        row['resource_only'] &= bool(re.search(r'(?:^|[/!])(?:res|assets|unknown)/|AndroidManifest\.xml', location.get('source') or ''))
        if location not in row['evidence'] and len(row['evidence']) >= LIMITS['evidence_per_item']: row['evidence_truncated'] = True
        if location not in row['evidence'] and len(row['evidence']) < LIMITS['evidence_per_item']: row['evidence'].append(location)
        return key

    def ingest(self, events):
        for index, (kind, caller, value, loc) in enumerate(events):
            if index % 256 == 0: self.check()
            if len(self.edges) >= LIMITS['edges'] or len(self.nodes) >= LIMITS['nodes']:
                self.warn('Graph node/edge budget reached; remaining executable references omitted'); break
            if kind == 'unresolved': self.warn(loc['source'] + ': ' + value); continue
            owner = message_owner(caller.split('->')[0])
            entity = self.candidate(owner, 'class', loc, proto=False)
            if kind == 'class':
                if entity and 'protobuf' in value.lower(): self.items[entity]['proto'] = True
                continue
            if kind == 'named_constant':
                if entity:
                    name, _, raw = value.partition('=')
                    number = int(raw, 16 if '0x' in raw.lower() else 10)
                    self.items[entity]['constants'][name] = number
                    if re.fullmatch(r'(?:opcode|packet_?id|command_?id)', name, re.I): self.items[entity]['opcodes'].add(str(number))
                continue
            if kind == 'field_definition':
                if entity: self.items[entity]['fields'].add(value.split('->')[-1].split(':')[0])
                continue
            mid = self.node('method', caller)
            if not mid: continue
            if kind == 'method':
                self.definitions[mid].add(loc['source'])
                self.edge(entity, mid, 'declares', loc)
                if entity: self.items[entity]['methods'].add(mid)
                continue
            if not mid: continue
            if kind == 'calls':
                target = self.node('method', value)
                self.edge(mid, target, 'calls', loc)
                if target:
                    self.calls[mid].add(target); self.reverse[target].add(mid)
                target_owner = message_owner(value.split('->')[0])
                item = self.candidate(target_owner, 'class', loc, proto=False)
                if item:
                    if owner != target_owner: self.item_methods[item].add(mid)
                    self.edge(mid, item, 'references_type', loc)
                for key, pattern in [('transport', TRANSPORT), ('codec', CODEC), ('crypto', CRYPTO), ('token', TOKEN), ('identity', IDENTITY)]:
                    if pattern.search(value): self.method_features[mid][key].append({'reference': value, **loc})
                if item:
                    field = re.search(r'->(?:get|set|has|clear)([A-Z][\w$]*)\(', value)
                    if field: self.items[item]['fields'].add(field.group(1)[0].lower() + field.group(1)[1:])
            elif kind in ('type_use', 'field_access'):
                target_owner = message_owner(value.split('->')[0])
                item = self.candidate(target_owner, 'class', loc)
                if item and owner != target_owner: self.item_methods[item].add(mid)
                target = self.node('field', value) if kind == 'field_access' else item
                self.edge(mid, target, kind, loc)
                if kind == 'field_access':
                    if item: self.items[item]['fields'].add(value.split('->')[-1].split(':')[0])
                    for key, pattern in [('token', TOKEN), ('identity', IDENTITY)]:
                        if pattern.search(value): self.method_features[mid][key].append({'reference': value, **loc})
            elif kind == 'literal':
                for address in addresses(value):
                    item = self.candidate(address, 'address', loc)
                    if item: self.item_methods[item].add(mid); self.edge(mid, item, 'loads_literal', loc)
                    self.method_features[mid]['address'].append({'reference': address, **loc})

    def scan(self, data, source, dex=False):
        self.file_count += 1
        try: self.ingest(dex_events(data, source, self.check) if dex else smali_events(data, source, self.check))
        except (ValueError, IndexError, UnicodeError) as exc: self.warn(f'{source}: {exc}')

    def paths(self, seeds, links):
        previous = {x: None for x in seeds}; depth = {x: 0 for x in seeds}; todo = deque(seeds)
        while todo:
            current = todo.popleft()
            if depth[current] >= LIMITS['path_depth']:
                if any(x not in previous for x in links.get(current, ())): self.partial = True
                continue
            for target in sorted(links.get(current, ())):
                if target not in previous:
                    previous[target] = current; depth[target] = depth[current] + 1; todo.append(target)
            if len(previous) % 256 == 0: self.check()
        return previous

    def finish(self, report):
        # Declarations and string/resource findings do not manufacture executable edges.
        for group in ('endpoints', 'protocols', 'research'):
            for row in report[group]:
                self.check()
                if group == 'research' and row['kind'] not in ('message-family candidate', 'named target reference') and row.get('stage') != 'security' and row.get('target') != 'port': continue
                self.candidate(row['value'], 'address' if group == 'endpoints' else 'marker',
                               {k: row.get(k) for k in ('source', 'line', 'offset')})
        for row in report['protobuf']:
            declarations = proto_definitions(row.get('schema', ''), row.get('package', ''))
            def walk(messages, prefix=''):
                for message in messages:
                    name = prefix + message['name']; declarations.append((name, [f['name'] for f in message.get('fields', [])])); walk(message.get('messages', []), name + '.')
            descriptor = row.get('descriptor', {})
            walk(descriptor.get('messages', []), descriptor.get('package', '') + '.' if descriptor.get('package') else '')
            for name, fields in declarations:
                key = self.candidate(name, 'proto_definition', {k: row.get(k) for k in ('source', 'line', 'offset')}, True)
                if key:
                    self.items[key]['fields'].update(fields)
                    for field in fields:
                        self.edge(key, self.node('field', name + '.' + field), 'declares_field', {k: row.get(k) for k in ('source', 'line', 'offset')})
        # Only exact qualified descriptors can resolve declarations to classes.
        for key, item in list(self.items.items()):
            if item['kind'] != 'proto_definition': continue
            qualified = 'L' + item['name'].replace('.', '/') + ';'
            peer = identity('entity', qualified)
            if peer in self.items:
                self.items[peer]['proto'] = True; item['fields'].update(self.items[peer]['fields'])
                self.item_methods[key].update(self.item_methods[peer])
        transports = {mid for mid, features in self.method_features.items() if features['transport']}
        network_paths = self.paths(sorted(transports), self.reverse)
        login_seeds = sorted(mid for mid in self.definitions if re.search(r'(?:login|session|authenticate)', self.nodes[mid]['name'].split('->')[-1].split('(')[0], re.I))
        login_paths = self.paths(login_seeds, self.calls)
        result = empty_report(); all_items = []
        for key, item in self.items.items():
            self.check()
            methods = self.item_methods[key] | item['methods']
            executable = bool(self.item_methods[key]) if item['proto'] else bool(self.item_methods[key] or any(self.reverse.get(x) or self.calls.get(x) for x in item['methods']))
            reachable = sorted(methods & network_paths.keys())
            path = []
            if reachable:
                at = reachable[0]
                while at is not None: path.append(at); at = network_paths[at]
                terminal = self.method_features[path[-1]]['transport'][0]['reference']
                terminal_id = identity('method', terminal)
                if terminal_id in self.nodes: path.append(terminal_id)
            features = defaultdict(list)
            # Evidence local to referenced methods and their demonstrated transport chain only.
            for mid in sorted(methods | set(path)):
                for feature, hits in self.method_features.get(mid, {}).items(): features[feature].extend(hits[:10])
            tests = {'login_session_call': executable and bool(methods & login_paths.keys()),
                     'proto_executable_reference': item['proto'] and executable,
                     'transport_path': bool(path), 'token_access': bool(features['token']),
                     'server_region_account': bool(features['identity']),
                     'caller_callee': any(self.calls.get(m) or self.reverse.get(m) for m in methods),
                     'packet_codec': bool(features['codec']), 'address_reference': bool(features['address']),
                     'crypto_on_network_path': bool(path) and any(self.method_features[m]['crypto'] for m in path),
                     'no_executable_reference': not executable,
                     'resource_only': not executable and item['resource_only'],
                     'unused_proto_definition': item['proto'] and not executable}
            evidence_fields = {'login_session_call':'login_path', 'proto_executable_reference':'proto_candidate + method_node_ids', 'transport_path':'network_path', 'token_access':'feature_evidence.token', 'server_region_account':'feature_evidence.identity', 'caller_callee':'method_node_ids + dependency_graph.calls', 'packet_codec':'feature_evidence.codec', 'address_reference':'feature_evidence.address', 'crypto_on_network_path':'network_path + feature_evidence.crypto', 'no_executable_reference':'executable_reference (bounded absence, not proof)', 'resource_only':'references', 'unused_proto_definition':'proto_candidate + executable_reference (bounded absence)'}
            reasons = [{'rule': rule, 'points': points, 'evidence_field': evidence_fields[rule]} for rule, points in RULES.items() if tests[rule]]
            score = sum(r['points'] for r in reasons)
            ambiguous = any(len(self.definitions[m]) > 1 for m in path)
            confidence = 'HIGH' if path and not ambiguous and not self.partial else 'MEDIUM' if executable else 'LOW'
            login_path = []
            roots = sorted(methods & login_paths.keys())
            if roots:
                at = roots[0]
                while at is not None: login_path.append(self.nodes[at]['name']); at = login_paths[at]
                login_path.reverse()
            name = item['name']; category = classify(name)
            all_items.append({'id': key, 'name': name, 'type': category, 'classification_basis': 'name heuristic; review evidence',
                'kind': item['kind'], 'score': score, 'priority': priority(score), 'confidence': confidence,
                'score_reasons': reasons, 'confidence_basis': 'observed_static_transport_path' if confidence == 'HIGH' else 'partial_or_ambiguous_path' if path else 'static_references_only',
                'external_type_reference': bool(self.item_methods[key]), 'references': sorted({e['source'] for e in item['evidence'] if e['source']}),
                'evidence': item['evidence'], 'evidence_truncated': item['evidence_truncated'],
                'method_node_ids': sorted(methods)[:40], 'method_references_truncated': len(methods)>40,
                'fields': sorted(item['fields'])[:200], 'fields_truncated': len(item['fields'])>200,
                'opcodes': sorted(item['opcodes']), 'named_constants': item['constants'],
                'constant_note': 'Named Smali constants only; packet IDs/ports are candidates, not register-bound or runtime-verified.',
                'login_path': login_path, 'network': bool(path), 'network_path': [self.nodes[m]['name'] for m in path],
                'network_path_node_ids': path, 'transport_evidence': features['transport'][:10],
                'feature_evidence': {k: v[:20] for k, v in features.items() if v},
                'executable_reference': executable, 'proto_candidate': item['proto'],
                'ambiguous_definitions': ambiguous, 'runtime_use_proven': False, 'data_flow_proven': False})
        for item in sorted(all_items, key=lambda x: (-x['score'], x['name'])): result[item['type'].lower()].append(item)
        result['meta'].update(enabled=True, format='protohunter-protocol-report-v1', limits=LIMITS,
            truncated=self.partial, warnings=self.warnings, executable_files=self.file_count,
            counts={category: len(result[category.lower()]) for category in CATEGORIES},
            proto_message_counts=dict(Counter(i['type'] for i in all_items if i['proto_candidate'])),
            inventory_note='The original coverage/files sections inventory APK splits, DEX, SO, Manifest, assets, res and unknown; graph completeness is separate.',
            limitations=['No native instruction graph, Java AST, reflection, dynamic dispatch resolution, register/packet data flow or runtime verification.',
                         'Library API recognition is an allowlist; arbitrary send/connect names are not network proof.',
                         'Proto definitions without exact qualified class resolution remain unlinked; no invented Builder/response chain.',
                         'Duplicate method definitions across files are ambiguous; original and modified views may differ.',
                         'Positive rules count once each (maximum 58). Counts include candidates, not confirmed on-wire messages.'])
        return result, {'format': 'protohunter-dependency-graph-v1', 'nodes': list(self.nodes.values()), 'edges': self.edges,
                        'truncated': self.partial, 'limits': LIMITS, 'note': 'Only calls edges participate in reachability; field/type/literal edges are not data-flow edges.'}
