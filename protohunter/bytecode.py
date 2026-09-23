"""Bounded structural readers. Direct static references, never runtime/data-flow proof."""
import re
import struct
from .formats import dex_strings, varint

METHOD = re.compile(r'(L[^;\s]+;->[^\s(]+\([^\s]*\)[^\s,}]+)')
FIELD = re.compile(r'(L[^;\s]+;->[^\s:]+:[^\s,}]+)')


def smali_events(text, source, check=lambda: None):
    owner = None; method = None; payload = False; annotation = 0
    for number, raw in enumerate(text.splitlines(), 1):
        if number % 256 == 0: check()
        line = raw.strip()
        if len(line) > 8192:
            yield 'unresolved', method or '<unknown>', 'Smali line exceeds graph parser limit (8192)', {'source':source, 'line':number, 'offset':None, 'format':'smali'}
            continue
        # Comments and quoted literals cannot manufacture instructions.
        if line.startswith('.annotation') or line.startswith('.subannotation'): annotation += 1
        if annotation:
            if line.startswith(('.end annotation', '.end subannotation')): annotation -= 1
            continue
        line = line.split('#', 1)[0].strip() if '"' not in line else line
        location = {'source': source, 'line': number, 'offset': None, 'format': 'smali'}
        if line.startswith('.class '):
            value = line.split()[-1]
            owner = value if re.fullmatch(r'L[^;\s]+;', value) else None
        elif line.startswith('.super ') and owner:
            yield 'class', owner, line.split()[-1], location
        elif line.startswith('.field ') and owner:
            declaration = line.split('=', 1)[0].split()[-1]
            field = re.fullmatch(r'([^\s:]+:[^\s=]+)', declaration)
            if field:
                yield 'field_definition', owner, owner + '->' + field.group(1), location
                constant = re.search(r'=\s*(-?0x[0-9a-fA-F]{1,8}|-?[0-9]{1,10})\b', line)
                if constant: yield 'named_constant', owner, field.group(1).split(':')[0] + '=' + constant.group(1), location
        elif line.startswith('.method ') and owner:
            signature = line.split()[-1]
            method = owner + '->' + signature if '(' in signature else None
            if method: yield 'method', method, owner, location
        elif line.startswith('.end method'): method = None
        elif method:
            if line.startswith(('.packed-switch', '.sparse-switch', '.array-data')): payload = True
            if line.startswith(('.end packed-switch', '.end sparse-switch', '.end array-data')): payload = False
            if payload: continue
            if re.match(r'^invoke-[\w/-]+\s+\{[^}]*\},\s*L', line):
                m = METHOD.match(line.split('},', 1)[-1].strip())
                if m: yield 'calls', method, m.group(1), location
            elif re.match(r'^(?:iget|iput|sget|sput)(?:-[\w]+)?\s+', line):
                m = FIELD.match(line.rsplit(',', 1)[-1].strip())
                if m: yield 'field_access', method, m.group(1), location
            elif re.match(r'^(?:new-instance|check-cast|const-class)\s+', line):
                m = re.search(r',\s*(L[^;\s]+;)', line)
                if m: yield 'type_use', method, m.group(1), location
            elif re.match(r'^const-string(?:/jumbo)?\s+', line):
                m = re.search(r',\s*"((?:\\.|[^"\\])*)"', line)
                if m: yield 'literal', method, m.group(1), location


# Dalvik widths in 16-bit code units. Unassigned/optimized opcodes stop the method.
WIDTH = {}
for op in [0, 1, 4, 7, *range(0x0a, 0x13), 0x1d, 0x1e, 0x21, 0x27, 0x28, *range(0x7b, 0x90), *range(0xb0, 0xd0)]: WIDTH[op] = 1
for op in [2, 5, 8, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23, 0x29, *range(0x2d, 0x3e), *range(0x44, 0x6e), *range(0x90, 0xb0), *range(0xd0, 0xe3), 0xfe, 0xff]: WIDTH[op] = 2
for op in [3, 6, 9, 0x14, 0x17, 0x1b, *range(0x24, 0x27), *range(0x2a, 0x2d), *range(0x6e, 0x73), *range(0x74, 0x79), 0xfc, 0xfd]: WIDTH[op] = 3
WIDTH[0x18] = 5
WIDTH[0xfa] = WIDTH[0xfb] = 4


def dex_events(data, source, check=lambda: None, max_instructions=2_000_000):
    """Standard DEX 035–040 only; bounded tables, class_data and code_item walks."""
    if len(data) < 112 or data[4:7] not in {b'035', b'037', b'038', b'039', b'040'}:
        raise ValueError('Unsupported DEX version (standard 035–040 only)')
    def unpack(fmt, pos):
        size = struct.calcsize('<' + fmt)
        if pos < 0 or pos + size > len(data): raise ValueError('DEX range outside file')
        return struct.unpack_from('<' + fmt, data, pos)
    strings = []; string_bytes = 0
    for i, (_, text) in enumerate(dex_strings(data)):
        if i % 1024 == 0: check()
        if i >= 200000: raise ValueError('DEX graph string-table limit (200000)')
        string_bytes += len(text)
        if string_bytes > 32 * 1024**2: raise ValueError('DEX graph decoded string budget (32 MiB characters)')
        strings.append(text)
    def table(header, width, cap=65536):
        count, start = unpack('II', header)
        if count > cap or (count and start < 112) or start + count * width > len(data): raise ValueError('Invalid/oversized DEX table')
        return range(start, start + count * width, width)
    def get(values, index):
        if index >= len(values): raise ValueError('Invalid DEX index')
        return values[index]
    types = [get(strings, unpack('I', pos)[0]) for pos in table(64, 4)]
    if any(len(t) > 1024 for t in types): raise ValueError('DEX type descriptor length limit (1024)')
    reference_chars = 0
    def reference(value):
        nonlocal reference_chars
        reference_chars += len(value)
        if len(value) > 8192 or reference_chars > 32 * 1024**2: raise ValueError('DEX constructed-reference budget exceeded')
        return value
    protos = []; parameter_budget = 0
    for pos in table(72, 12):
        check()
        _, ret, params = unpack('III', pos); args = []
        if params:
            count = unpack('I', params)[0]
            parameter_budget += count
            if count > 4096 or parameter_budget > 1000000: raise ValueError('DEX parameter budget exceeded')
            args = [get(types, unpack('H', params + 4 + i * 2)[0]) for i in range(count)]
        protos.append(reference('(' + ''.join(args) + ')' + get(types, ret)))
    fields = []
    for pos in table(80, 8):
        owner, kind, name = unpack('HHI', pos)
        fields.append(reference(get(types, owner) + '->' + get(strings, name) + ':' + get(types, kind)))
    methods = []
    for pos in table(88, 8):
        owner, proto, name = unpack('HHI', pos)
        methods.append(reference(get(types, owner) + '->' + get(strings, name) + get(protos, proto)))
    budget = 0; member_budget = 0
    for pos in table(96, 32, 20000):
        check()
        class_idx = unpack('I', pos)[0]; owner = get(types, class_idx)
        super_idx = unpack('I', pos + 8)[0]
        if super_idx != 0xffffffff:
            yield 'class', owner, get(types, super_idx), {'source':source, 'line':None, 'offset':pos, 'format':'dex'}
        cursor = unpack('I', pos + 24)[0]
        if not cursor: continue
        counts = []
        for _ in range(4):
            count, cursor = varint(data, cursor); counts.append(count)
        member_budget += sum(counts)
        if member_budget > 200000: raise ValueError('DEX class_data member budget (200000)')
        for count in counts[:2]:
            idx = 0
            for _ in range(count):
                diff, cursor = varint(data, cursor); idx += diff
                _, cursor = varint(data, cursor)
                yield 'field_definition', owner, get(fields, idx), {'source':source, 'line':None, 'offset':cursor, 'format':'dex'}
        for count in counts[2:]:
            idx = 0
            for _ in range(count):
                diff, cursor = varint(data, cursor); idx += diff
                _, cursor = varint(data, cursor); code, cursor = varint(data, cursor)
                caller = get(methods, idx)
                if caller.split('->')[0] != owner: raise ValueError('DEX method/class mismatch')
                loc = {'source': source, 'line': None, 'offset': code, 'format': 'dex'}
                yield 'method', caller, owner, loc
                if not code: continue
                units = unpack('I', code + 12)[0]; start = code + 16
                if start + units * 2 > len(data): raise ValueError('Truncated DEX instructions')
                pc = 0
                while pc < units:
                    budget += 1
                    if budget % 1024 == 0: check()
                    if budget > max_instructions: raise ValueError('DEX instruction budget exceeded')
                    at = start + pc * 2; word = unpack('H', at)[0]; op = word & 255
                    if word in (0x100, 0x200, 0x300):
                        if pc + 2 > units: raise ValueError('Truncated DEX payload')
                        size = unpack('H', at + 2)[0]
                        if word == 0x100: width = 4 + size * 2
                        elif word == 0x200: width = 2 + size * 4
                        else:
                            if pc + 4 > units: raise ValueError('Truncated DEX array payload')
                            width = 4 + (size * unpack('I', at + 4)[0] + 1) // 2
                    else:
                        width = WIDTH.get(op)
                        if width is None: raise ValueError(f'Unsupported DEX opcode 0x{op:02x}; remaining file references incomplete')
                    if pc + width > units: raise ValueError('Truncated DEX instruction/payload')
                    location = {**loc, 'offset': at}
                    if 0x6e <= op <= 0x72 or 0x74 <= op <= 0x78 or op in (0xfa, 0xfb):
                        yield 'calls', caller, get(methods, unpack('H', at + 2)[0]), location
                    elif 0x52 <= op <= 0x6d:
                        yield 'field_access', caller, get(fields, unpack('H', at + 2)[0]), location
                    elif op in (0x1c, 0x1f, 0x20, 0x22, 0x23):
                        yield 'type_use', caller, get(types, unpack('H', at + 2)[0]), location
                    elif op in (0x1a, 0x1b):
                        yield 'literal', caller, get(strings, unpack('I' if op == 0x1b else 'H', at + 2)[0]), location
                    elif op in (0xfc, 0xfd):
                        yield 'unresolved', caller, 'invoke-custom: call-site resolution not implemented', location
                    pc += width
