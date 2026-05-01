#!/usr/bin/env python3
import sys


def fnv1a(s):
    h = 0x811C9DC5
    for c in s.encode():
        h ^= c
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def fnv1a_wide_lower(s):
    h = 0x811C9DC5
    for c in s:
        c = c.lower()
        lo = ord(c) & 0xFF
        hi = (ord(c) >> 8) & 0xFF
        h ^= lo
        h = (h * 0x01000193) & 0xFFFFFFFF
        h ^= hi
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


if "--wide" in sys.argv:
    sys.argv.remove("--wide")
    for name in sys.argv[1:]:
        print(f"#define H_{name.replace('.', '_'):40s} 0x{fnv1a_wide_lower(name):08X}u")
else:
    for name in sys.argv[1:]:
        print(f"#define H_{name:40s} 0x{fnv1a(name):08X}u")
