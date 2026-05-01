#!/usr/bin/env python3
"""безликий"""

import struct
import sys
from pathlib import Path

KEY = 0xA3B7C1D9E5F20486
KEY_BYTES = struct.pack("<Q", KEY)


def encrypt(data: bytes) -> bytes:
    return bytes(b ^ KEY_BYTES[i % 8] for i, b in enumerate(data))


def main():
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <input.sys> <output.h> <array_name>")
        sys.exit(1)

    src, dst, name = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    raw = src.read_bytes()
    enc = encrypt(raw)

    with open(dst, "w", encoding="utf-8") as f:
        f.write(f"/* безликий — generated do not edit */\n")
        f.write("#pragma once\n\n")
        f.write("#include <stdint.h>\n")
        f.write("#include <stddef.h>\n\n")
        f.write(f"const uint8_t {name}_data[] = {{\n")

        for i in range(0, len(enc), 16):
            chunk = enc[i : i + 16]
            f.write("    " + ", ".join(f"0x{b:02X}" for b in chunk) + ",\n")

        f.write("};\n\n")
        f.write(f"const size_t {name}_size = {len(raw)};\n")

    print(f"{src.name} -> {dst.name} ({len(raw)} bytes, XOR 0x{KEY:016X})")


if __name__ == "__main__":
    main()
