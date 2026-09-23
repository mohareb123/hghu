"""Generate the small P app icon using only the Python standard library."""
from pathlib import Path
import struct


def image(size):
    rows = ('11110', '11011', '11011', '11110', '11000', '11000', '11000')
    pixels = bytearray()
    for y in reversed(range(size)):
        for x in range(size):
            u, v = (x + 0.5) / size, (y + 0.5) / size
            dx, dy = max(0.22 - u, 0, u - 0.78), max(0.22 - v, 0, v - 0.78)
            visible = dx * dx + dy * dy <= 0.22**2
            gx, gy = int((u - 0.29) / 0.085), int((v - 0.20) / 0.085)
            letter = u >= 0.29 and v >= 0.20 and 0 <= gx < 5 and 0 <= gy < 7 and rows[gy][gx] == '1'
            red, green, blue = (16, 24, 16) if letter else (189, 252, 121)
            pixels.extend((blue, green, red, 255 if visible else 0))
    mask_stride = ((size + 31) // 32) * 4
    header = struct.pack('<IIIHHIIIIII', 40, size, size * 2, 1, 32, 0, len(pixels), 0, 0, 0, 0)
    return header + pixels + b'\0' * (mask_stride * size)


def main():
    sizes = (16, 32, 48, 64, 128)
    images = [image(size) for size in sizes]
    offset = 6 + 16 * len(sizes)
    directory = bytearray(struct.pack('<HHH', 0, 1, len(sizes)))
    for size, bitmap in zip(sizes, images):
        directory.extend(struct.pack('<BBBBHHII', size, size, 0, 0, 1, 32, len(bitmap), offset))
        offset += len(bitmap)
    Path(__file__).with_name('protohunter.ico').write_bytes(directory + b''.join(images))


if __name__ == '__main__':
    main()
