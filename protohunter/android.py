"""Android binary XML/resources string pools, not a full resource or manifest decompiler."""
import struct


def resource_strings(data):
    if len(data) < 8:
        raise ValueError("Truncated Android resource header")
    root_type, root_header, root_size = struct.unpack_from('<HHI', data, 0)
    if root_type not in (2, 3) or root_header < 8 or root_size > len(data) or root_size < root_header:
        raise ValueError("Invalid Android resource container")
    budget = [200000]

    def chunks(start, end, depth=0):
        if depth > 4:
            raise ValueError("Resource nesting limit reached")
        cursor = start
        while cursor < end:
            if cursor + 8 > end:
                raise ValueError("Truncated resource chunk")
            kind, header, size = struct.unpack_from('<HHI', data, cursor)
            if header < 8 or size < header or cursor + size > end:
                raise ValueError("Invalid resource chunk range")
            if kind == 1:
                if header < 28:
                    raise ValueError("Invalid string pool header")
                count, styles, flags, string_start, style_start = struct.unpack_from('<IIIII', data, cursor + 8)
                if header + 4 * (count + styles) > size or string_start < header + 4 * (count + styles) or string_start > size:
                    raise ValueError("Invalid string pool offsets")
                pool_end = cursor + (style_start or size)
                if pool_end > cursor + size or pool_end < cursor + string_start:
                    raise ValueError("Invalid string pool data range")
                def length8(position):
                    if position >= pool_end:
                        raise ValueError("Truncated UTF-8 length")
                    first = data[position]
                    if first & 128:
                        if position + 1 >= pool_end:
                            raise ValueError("Truncated UTF-8 length")
                        return ((first & 127) << 8) | data[position + 1], position + 2
                    return first, position + 1
                def length16(position):
                    if position + 2 > pool_end:
                        raise ValueError("Truncated UTF-16 length")
                    first = struct.unpack_from('<H', data, position)[0]
                    if first & 0x8000:
                        if position + 4 > pool_end:
                            raise ValueError("Truncated UTF-16 length")
                        return ((first & 0x7fff) << 16) | struct.unpack_from('<H', data, position + 2)[0], position + 4
                    return first, position + 2
                for i in range(count):
                    if budget[0] <= 0:
                        raise ValueError("Android string pool limit reached (200000)")
                    budget[0] -= 1
                    relative = struct.unpack_from('<I', data, cursor + header + i * 4)[0]
                    position = cursor + string_start + relative
                    if position >= pool_end:
                        raise ValueError("String points outside Android string pool")
                    if flags & 256:
                        _, position = length8(position)
                        length, position = length8(position)
                        byte_length, encoding = length, 'utf-8'
                    else:
                        length, position = length16(position)
                        byte_length, encoding = length * 2, 'utf-16le'
                    if position + byte_length > pool_end:
                        raise ValueError("String exceeds Android pool bounds")
                    if byte_length > 32768:
                        raise ValueError("Android string length limit reached (32768 bytes)")
                    yield position, data[position:position + byte_length].decode(encoding, errors='replace')
            elif kind == 0x200:  # RES_TABLE_PACKAGE
                yield from chunks(cursor + header, cursor + size, depth + 1)
            cursor += size
    yield from chunks(root_header, root_size)
