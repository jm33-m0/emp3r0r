#!/usr/bin/env python3
"""LZSS packer for the self-unpacker stub.

Usage: pack_lzss.py <stub.bin> <stub.elf> <stager.bin> <out.bin>
"""

from pack_common import parse_args, patch_and_write_packed

MIN_MATCH = 3
MAX_MATCH = 18
WINDOW = 4096


def lzss_compress(data):
    n = len(data)
    out = bytearray()
    pos = 0
    heads = {}  # 4-byte hash -> recent positions (oldest first)

    def h4(p):
        return (
            data[p] | (data[p + 1] << 8) | (data[p + 2] << 16) | (data[p + 3] << 24)
        ) & 0xFFFFFFFF

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
                flags |= 1 << bit
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


def main():
    stub_path, elf_path, payload_path, out_path = parse_args()
    payload = open(payload_path, "rb").read()
    packed = lzss_compress(payload)
    patch_and_write_packed(
        stub_path, elf_path, payload, packed, out_path, algo_name="lzss"
    )


if __name__ == "__main__":
    main()
