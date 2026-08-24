#!/usr/bin/env python3
"""RC4 packer for the self-unpacker stub.

Usage: pack_rc4.py <stub.bin> <stub.elf> <stager.bin> <out.bin>

Encrypts stager.bin with a random 16-byte RC4 key, patches the 24-byte header
(unpacked_size, packed_size, key) in the stub at the correct .data vaddr offset
(read from the ELF), and appends the encrypted payload.

The header offset is determined by reading the .data section vaddr directly
from the ELF rather than computing it from accumulated section sizes.  This is
necessary because the linker may insert alignment padding between sections
(e.g. when .rodata is absent, .data is aligned to 16 bytes relative to .text),
which objcopy -O binary preserves but a naive size-sum would miss.
"""

import os
import struct
import subprocess
import sys

HEADER_SIZE = 24


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


def get_data_vaddr(elf_path):
    """Return the vaddr of the .data section from the ELF, or raise on failure."""
    result = subprocess.run(
        ['readelf', '-S', '--wide', elf_path],
        capture_output=True, text=True, check=True,
    )
    for line in result.stdout.splitlines():
        parts = line.split()
        # readelf -S --wide line format (one section per line):
        #   [ Nr] Name  Type  Addr  Off  Size  ES  Flg  Lk  Inf  Al
        # The Name field may have a leading '[' index; find '.data' token.
        if '.data' in parts:
            idx = parts.index('.data')
            # The address field follows the type field (two after '.data').
            vaddr_hex = parts[idx + 2]
            return int(vaddr_hex, 16)
    raise ValueError(f"No .data section found in {elf_path}")


def main():
    stub_path, elf_path, payload_path, out_path = (
        sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    )

    payload = open(payload_path, 'rb').read()
    key = os.urandom(16)
    packed = rc4(payload, key)

    hdr_off = get_data_vaddr(elf_path)

    stub = bytearray(open(stub_path, 'rb').read())
    stub[hdr_off:hdr_off + 8] = struct.pack('<II', len(payload), len(packed))
    stub[hdr_off + 8:hdr_off + HEADER_SIZE] = key

    open(out_path, 'wb').write(bytes(stub) + packed)
    print(f"packed(rc4): {len(stub) + len(packed)} bytes "
          f"(stub={len(stub)} packed={len(packed)} unpacked={len(payload)})")


if __name__ == '__main__':
    main()
