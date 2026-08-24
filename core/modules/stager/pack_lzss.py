#!/usr/bin/env python3
"""LZSS packer for the self-unpacker stub.

Usage: pack_lzss.py <stub.bin> <stub.elf> <stager.bin> <out.bin>

Compresses stager.bin with a greedy LZSS, patches the header (unpacked_size,
packed_size; key stays zero) in the stub at the correct .data vaddr offset
(read from the ELF), and appends the compressed payload.

The header offset is determined by reading the .data section vaddr directly
from the ELF rather than computing it from accumulated section sizes.  This is
necessary because the linker may insert alignment padding between sections
(e.g. when .rodata is absent, .data is aligned to 16 bytes relative to .text),
which objcopy -O binary preserves but a naive size-sum would miss.
"""

import struct
import subprocess
import sys

MIN_MATCH = 3
MAX_MATCH = 18
WINDOW = 4096


def lzss_compress(data):
    n = len(data)
    out = bytearray()
    pos = 0
    heads = {}  # 4-byte hash -> recent positions (oldest first)

    def h4(p):
        return (data[p] | (data[p + 1] << 8) | (data[p + 2] << 16) |
                (data[p + 3] << 24)) & 0xFFFFFFFF

    while pos < n:
        flagpos = len(out)
        out.append(0)
        flags = 0
        for bit in range(8):
            if pos >= n:
                break
            best_off = 0
            best_len = 0
            maxlen = min(MAX_MATCH, n - pos)
            if maxlen >= MIN_MATCH and pos + 4 <= n:
                h = h4(pos)
                cands = heads.get(h)
                if cands:
                    for cand in reversed(cands[-8:]):
                        off = pos - cand
                        if off <= 0 or off > WINDOW:
                            continue
                        if data[cand] != data[pos]:
                            continue
                        l = 0
                        while l < maxlen and data[cand + l] == data[pos + l]:
                            l += 1
                        if l > best_len:
                            best_len = l
                            best_off = off
                            if l == maxlen:
                                break
                heads.setdefault(h, []).append(pos)
                if len(heads[h]) > 8:
                    heads[h].pop(0)

            if best_len >= MIN_MATCH:
                flags |= (1 << bit)
                off = best_off - 1
                lenc = best_len - MIN_MATCH
                out.append(off & 0xFF)
                out.append(((off >> 8) & 0x0F) | (lenc << 4))
                pos += best_len
            else:
                out.append(data[pos])
                pos += 1
        out[flagpos] = flags
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
    packed = lzss_compress(payload)

    hdr_off = get_data_vaddr(elf_path)

    stub = bytearray(open(stub_path, 'rb').read())
    stub[hdr_off:hdr_off + 8] = struct.pack('<II', len(payload), len(packed))

    open(out_path, 'wb').write(bytes(stub) + packed)
    print(f"packed(lzss): {len(stub) + len(packed)} bytes "
          f"(stub={len(stub)} packed={len(packed)} unpacked={len(payload)})")


if __name__ == '__main__':
    main()
