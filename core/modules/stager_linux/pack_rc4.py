#!/usr/bin/env python3
"""RC4 packer for the self-unpacker stub.

Usage: pack_rc4.py <stub.bin> <stub.elf> <stager.bin> <out.bin>
"""

import os
from pack_common import parse_args, patch_and_write_packed


def rc4(data, key):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def main():
    stub_path, elf_path, payload_path, out_path = parse_args()
    payload = open(payload_path, "rb").read()
    key = os.urandom(16)
    packed = rc4(payload, key)
    patch_and_write_packed(
        stub_path, elf_path, payload, packed, out_path, key=key, algo_name="rc4"
    )


if __name__ == "__main__":
    main()
