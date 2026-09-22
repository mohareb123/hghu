"""Bounded ELF and IL2CPP metadata readers. These never load native code."""
import re
import struct

ARCHITECTURES = {3: "x86", 8: "MIPS", 40: "ARM", 62: "x86_64", 183: "AArch64", 243: "RISC-V"}
NETWORK_SYMBOL = re.compile(r"protobuf|grpc|ByteSizeLong|ParseFrom|SerializeTo|SSL_|TLS_|mbedtls|curl_|websocket|mqtt|enet_|ikcp_|^(?:connect|socket|send|recv|sendto|recvfrom|getaddrinfo|gethostbyname)$", re.I)


def checked_range(data, offset, size):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError("Binary range is outside the file")


def cstring(data, start, end, cap=2048):
    checked_range(data, start, max(0, end - start))
    if start >= end:
        return ""
    stop = data.find(b"\0", start, min(end, start + cap))
    if stop < 0:
        stop = min(end, start + cap)
    return data[start:stop].decode("utf-8", errors="replace")


def elf_info(data):
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ValueError("Invalid ELF magic")
    bits, byte_order = data[4], data[5]
    if bits not in (1, 2) or byte_order not in (1, 2):
        raise ValueError("Unsupported ELF class or byte order")
    endian = "<" if byte_order == 1 else ">"
    header_format = endian + ("HHIIIIIHHHHHH" if bits == 1 else "HHIQQQIHHHHHH")
    header_size = 16 + struct.calcsize(header_format)
    checked_range(data, 0, header_size)
    header = struct.unpack_from(header_format, data, 16)
    machine, section_offset, entry_size, section_count, names_index = header[1], header[5], header[10], header[11], header[12]
    result = {"bits": 32 if bits == 1 else 64, "endianness": "little" if byte_order == 1 else "big",
              "architecture": ARCHITECTURES.get(machine, f"machine-{machine}"), "sections": [],
              "needed_libraries": [], "symbols": [], "network_symbols": [], "symbol_count": 0,
              "notes": []}
    if not section_offset:
        result["notes"].append("No section table; symbols and dependencies were not recovered from program headers.")
        return result
    section_format = endian + ("IIIIIIIIII" if bits == 1 else "IIQQQQIIQQ")
    minimum = struct.calcsize(section_format)
    if entry_size < minimum:
        raise ValueError("Invalid ELF section entry size")
    checked_range(data, section_offset, entry_size)
    section_zero = struct.unpack_from(section_format, data, section_offset)
    if section_count == 0:
        section_count = section_zero[5]
    if names_index == 0xffff:
        names_index = section_zero[6]
    if section_count > 4096:
        raise ValueError("ELF section count exceeds 4096")
    checked_range(data, section_offset, entry_size * section_count)
    sections = [struct.unpack_from(section_format, data, section_offset + i * entry_size) for i in range(section_count)]
    for section in sections:
        if section[1] != 8:  # SHT_NOBITS has no file contents.
            checked_range(data, section[4], section[5])
    def get_string(index, table):
        if not 0 <= index < table[5]:
            return ""
        return cstring(data, table[4] + index, table[4] + table[5])
    names = sections[names_index] if 0 < names_index < len(sections) else None
    for section in sections:
        name = get_string(section[0], names) if names else ""
        if len(result["sections"]) < 512:
            result["sections"].append({"name": name, "offset": section[4], "size": section[5], "type": section[1]})
        if section[1] not in (2, 6, 11):
            continue
        link = section[6]
        if link >= len(sections) or sections[link][1] != 3:
            result["notes"].append(f"Invalid string-table link in section {name}")
            continue
        strings = sections[link]
        if section[1] == 6:  # SHT_DYNAMIC
            fmt = endian + ("iI" if bits == 1 else "qQ")
            size = struct.calcsize(fmt)
            step = section[9] or size
            if step < size:
                raise ValueError("Invalid dynamic entry size")
            for i in range(min(section[5] // step, 10000)):
                tag, value = struct.unpack_from(fmt, data, section[4] + i * step)
                if tag == 0:
                    break
                if tag == 1:
                    library = get_string(value, strings)
                    if library and library not in result["needed_libraries"]:
                        result["needed_libraries"].append(library)
            continue
        fmt = endian + ("IIIBBH" if bits == 1 else "IBBHQQ")
        size = struct.calcsize(fmt)
        step = section[9] or size
        if step < size:
            raise ValueError("Invalid ELF symbol size")
        count = section[5] // step
        remaining = max(0, 100000 - result["symbol_count"])
        if count > remaining:
            result["notes"].append("Symbol scan capped at 100000 entries.")
        for i in range(min(count, remaining)):
            entry_offset = section[4] + i * step
            values = struct.unpack_from(fmt, data, entry_offset)
            if bits == 1:
                string_index, address, _, info, visibility, section_index = values
            else:
                string_index, info, visibility, section_index, address, _ = values
            result["symbol_count"] += 1
            name = get_string(string_index, strings)
            if not name or (info >> 4) not in (1, 2):
                continue
            symbol = {"name": name, "role": "import" if section_index == 0 else "defined",
                      "address": address, "offset": entry_offset,
                      "string_offset": strings[4] + string_index, "visibility": visibility & 3}
            if len(result["symbols"]) < 1000:
                result["symbols"].append(symbol)
            if NETWORK_SYMBOL.search(name) and len(result["network_symbols"]) < 2000:
                result["network_symbols"].append(symbol)
    if len(sections) > 512:
        result["notes"].append("Section preview capped at 512.")
    result["notes"].append("Symbol preview capped at 1000; network-symbol preview at 2000. Imported symbols do not prove runtime use.")
    return result


def il2cpp_header(data):
    if len(data) < 32 or data[:4] != b"\xaf\x1b\xb1\xfa":
        raise ValueError("Missing standard IL2CPP metadata magic/header")
    version = struct.unpack_from("<I", data, 4)[0]
    if not 24 <= version <= 31:
        raise ValueError(f"Unsupported IL2CPP metadata version {version}; only standard v24–31 string tables are read")
    tables = {}
    for name, position in (("literal_table", 8), ("literal_data", 16), ("identifier_strings", 24)):
        offset, size = struct.unpack_from("<II", data, position)
        checked_range(data, offset, size)
        if size and offset < 32:
            raise ValueError("IL2CPP string table overlaps the header")
        tables[name] = {"offset": offset, "size": size}
    if tables["literal_table"]["size"] % 8:
        raise ValueError("Invalid IL2CPP literal table size")
    return {"version": version, "tables": tables,
            "literal_count": tables["literal_table"]["size"] // 8,
            "note": "String tables only, not reconstructed C# types or a complete metadata dump. Custom/encrypted layouts are unsupported."}


def il2cpp_literals(data, header):
    table = header["tables"]["literal_table"]
    pool = header["tables"]["literal_data"]
    for index in range(min(header["literal_count"], 100000)):
        length, position = struct.unpack_from("<II", data, table["offset"] + index * 8)
        if position > pool["size"] or length > pool["size"] - position:
            raise ValueError("IL2CPP literal points outside string data")
        offset = pool["offset"] + position
        if 0 < length <= 16384:
            yield offset, data[offset:offset + length].decode("utf-8", errors="replace")
