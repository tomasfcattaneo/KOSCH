#!/usr/bin/env python3
import sys

KEY = 0x4B

def xor_encrypt(s):
    return ', '.join(f'0x{(ord(c) ^ KEY):02X}' for c in s)

if '--wide' in sys.argv:
    sys.argv.remove('--wide')
    for s in sys.argv[1:]:
        safe = s.replace('.', '_').replace('\\', '_')
        enc_bytes = []
        for c in s:
            lo = ord(c) & 0xFF
            hi = (ord(c) >> 8) & 0xFF
            enc_bytes.append(f'0x{(lo ^ KEY):02X}')
            enc_bytes.append(f'0x{(hi ^ KEY):02X}')
        print(f'/* L"{s}" */ static const uint8_t xw_{safe}[] = {{{", ".join(enc_bytes)}}};')
        print(f'#define XW_{safe}_LEN {len(s)}')
else:
    for s in sys.argv[1:]:
        safe = s.replace('.', '_').replace('\\', '_')
        print(f'/* "{s}" */ static const char xs_{safe}[] = {{{xor_encrypt(s)}}};')
        print(f'#define XS_{safe}_LEN {len(s)}')
