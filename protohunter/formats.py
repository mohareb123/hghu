"""Bounded readers for DEX strings and protobuf descriptors. No code execution."""
import struct


def varint(data, offset):
    value = 0
    for i in range(10):
        if offset >= len(data):
            raise ValueError("Truncated varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << (7 * i)
        if not byte & 128:
            return value, offset
    raise ValueError("Oversized varint")


def dex_strings(data):
    """Return (file offset, string) from a standard little-endian DEX string table."""
    if len(data) < 112 or data[:4] != b"dex\n" or data[7] != 0:
        raise ValueError("Invalid DEX header")
    if struct.unpack_from("<I", data, 40)[0] != 0x12345678:
        raise ValueError("Unsupported DEX endian tag")
    count, table = struct.unpack_from("<II", data, 56)
    if count == 0:
        return
    if count > 1_000_000 or table < 112 or table + count * 4 > len(data):
        raise ValueError("Invalid DEX string table")
    for i in range(count):
        offset = struct.unpack_from("<I", data, table + i * 4)[0]
        if offset < 112 or offset >= len(data):
            raise ValueError("Invalid DEX string offset")
        _, start = varint(data, offset)
        end = data.find(b"\0", start, min(len(data), start + 1_048_576))
        if end < 0:
            raise ValueError("Unterminated DEX string")
        # DEX MUTF-8 represents NUL as C0 80 and supplementary codepoints as surrogates.
        raw = data[start:end].replace(b"\xc0\x80", b"\0")
        text = raw.decode("utf-8", errors="surrogatepass")
        text = text.encode("utf-16", errors="surrogatepass").decode("utf-16", errors="replace")
        yield offset, text


def wire(data):
    """Read a bounded protobuf wire message (descriptors don't use legacy groups)."""
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("Descriptor exceeds 8 MiB")
    result = {}
    offset = 0
    fields = 0
    while offset < len(data):
        key, offset = varint(data, offset)
        number, kind = key >> 3, key & 7
        if not number or number > 536870911:
            raise ValueError("Invalid protobuf field number")
        if kind == 0:
            value, offset = varint(data, offset)
        elif kind in (1, 5):
            size = 8 if kind == 1 else 4
            if offset + size > len(data):
                raise ValueError("Truncated fixed-width field")
            value, offset = data[offset:offset + size], offset + size
        elif kind == 2:
            size, offset = varint(data, offset)
            if offset + size > len(data):
                raise ValueError("Truncated length-delimited field")
            value, offset = data[offset:offset + size], offset + size
        else:
            raise ValueError("Unsupported wire type")
        result.setdefault(number, []).append(value)
        fields += 1
        if fields > 100_000:
            raise ValueError("Too many descriptor fields")
    return result


def text_field(fields, key, default=""):
    value = fields.get(key, [default])[0]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="strict")
    if isinstance(value, str):
        return value
    raise ValueError("Invalid descriptor string")


def int_field(fields, key, default=0):
    value = fields.get(key, [default])[0]
    if not isinstance(value, int):
        raise ValueError("Invalid descriptor number")
    return value


TYPES = {1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32", 6: "fixed64",
         7: "fixed32", 8: "bool", 9: "string", 10: "group", 11: "message", 12: "bytes",
         13: "uint32", 14: "enum", 15: "sfixed32", 16: "sfixed64", 17: "sint32", 18: "sint64"}


def descriptor_message(raw, depth=0):
    if depth > 32:
        raise ValueError("Descriptor nesting exceeds 32 levels")
    fields = wire(raw)
    name = text_field(fields, 1)
    if not name or not name.isidentifier():
        raise ValueError("Invalid message name")
    result = {"name": name, "fields": [], "messages": [], "enums": []}
    for item in fields.get(2, []):
        f = wire(item)
        field_name, number, kind = text_field(f, 1), int_field(f, 3), int_field(f, 5)
        if not field_name.isidentifier() or number < 1 or kind not in TYPES:
            raise ValueError("Invalid field descriptor")
        result["fields"].append({"name": field_name, "number": number,
            "type": text_field(f, 6) or TYPES[kind],
            "label": {1: "optional", 2: "required", 3: "repeated"}.get(int_field(f, 4), ""),
            "oneof_index": int_field(f, 9, -1)})
    result["messages"] = [descriptor_message(x, depth + 1) for x in fields.get(3, [])]
    result["enums"] = [descriptor_enum(x) for x in fields.get(4, [])]
    result["oneofs"] = [text_field(wire(x), 1) for x in fields.get(8, [])]
    return result


def descriptor_enum(raw):
    fields = wire(raw)
    values = []
    for item in fields.get(2, []):
        f = wire(item)
        number = int_field(f, 2)
        if number >= 1 << 63:
            number -= 1 << 64
        values.append({"name": text_field(f, 1), "number": number})
    return {"name": text_field(fields, 1), "values": values}


def descriptor_file(raw):
    fields = wire(raw)
    name = text_field(fields, 1)
    if not name.endswith(".proto") or any(ord(c) < 32 for c in name):
        raise ValueError("Not a FileDescriptorProto")
    result = {"name": name, "package": text_field(fields, 2),
              "syntax": text_field(fields, 12) or "proto2", "messages": [], "enums": [], "services": []}
    result["messages"] = [descriptor_message(x) for x in fields.get(4, [])]
    result["enums"] = [descriptor_enum(x) for x in fields.get(5, [])]
    result["dependencies"] = [x.decode("utf-8") for x in fields.get(3, [])]
    for item in fields.get(6, []):
        service = wire(item)
        methods = []
        for method in service.get(2, []):
            m = wire(method)
            methods.append({"name": text_field(m, 1), "input": text_field(m, 2),
                            "output": text_field(m, 3), "client_streaming": bool(int_field(m, 5)),
                            "server_streaming": bool(int_field(m, 6))})
        result["services"].append({"name": text_field(service, 1), "methods": methods})
    return result


def descriptors(data):
    """Accept FileDescriptorSet or standalone FileDescriptorProto; never guess a schema."""
    try:
        return [descriptor_file(data)]
    except (ValueError, UnicodeError, TypeError):
        fields = wire(data)
        if set(fields) != {1} or not fields[1]:
            raise ValueError("Not a FileDescriptorSet")
        return [descriptor_file(raw) for raw in fields[1]]


def embedded_descriptors(data):
    """Heuristic bounded native descriptor carving; returns candidates, never full-schema claims.

    A raw descriptor has no universal length prefix. Only accept a plausible named
    file with message/enum/service structure, and stop at top-level field boundaries.
    """
    import re
    pattern = re.compile(rb"\x0a([\x01-\x7f])([A-Za-z0-9_./-]{1,121}\.proto)")
    for index, match in enumerate(pattern.finditer(data)):
        if index >= 64:
            break
        if match.group(1)[0] != len(match.group(2)):
            continue
        start, cursor, end = match.start(), match.start(), match.start()
        seen = set()
        try:
            for _ in range(4096):
                if cursor >= min(len(data), start + 131072):
                    break
                key, after_key = varint(data, cursor)
                number, kind = key >> 3, key & 7
                if number not in range(1, 15) or kind not in (0, 2):
                    break
                if number in (1, 2, 8, 9, 12, 14) and number in seen:
                    break
                size_or_value, after_value = varint(data, after_key)
                next_cursor = after_value + size_or_value if kind == 2 else after_value
                if next_cursor > min(len(data), start + 131072):
                    break
                seen.add(number)
                end = cursor = next_cursor
            if not {4, 5, 6}.intersection(seen):
                continue
            descriptor = descriptor_file(data[start:end])
            if descriptor["messages"] or descriptor["enums"] or descriptor["services"]:
                yield start, descriptor
        except (ValueError, TypeError, UnicodeError, AttributeError, IndexError):
            continue
