#!/usr/bin/env python3
"""Shared helper module for stager packer scripts."""

import struct
import subprocess
import sys

HEADER_SIZE = 24


def get_data_vaddr(elf_path):
    """Return the vaddr of the .data section from the ELF, or raise on failure."""
    result = subprocess.run(
        ["readelf", "-S", "--wide", elf_path],
        capture_output=True,
        text=True,
        check=True,
    )
    for line in result.stdout.splitlines():
        parts = line.split()
        # readelf -S --wide line format (one section per line):
        #   [ Nr] Name  Type  Addr  Off  Size  ES  Flg  Lk  Inf  Al
        # The Name field may have a leading '[' index; find '.data' token.
        if ".data" in parts:
            idx = parts.index(".data")
            # The address field follows the type field (two after '.data').
            vaddr_hex = parts[idx + 2]
            return int(vaddr_hex, 16)
    raise ValueError(f"No .data section found in {elf_path}")


def parse_args():
    """Parse common 4-argument command line for packer scripts."""
    if len(sys.argv) < 5:
        print(
            f"Usage: {sys.argv[0]} <stub.bin> <stub.elf> <stager.bin> <out.bin>",
            file=sys.stderr,
        )
        sys.exit(1)
    return sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]


def patch_and_write_packed(
    stub_path, elf_path, payload, packed_payload, out_path, key=b"", algo_name="packer"
):
    """Patch the unpack header in the stub and output the final packed stager."""
    hdr_off = get_data_vaddr(elf_path)
    stub = bytearray(open(stub_path, "rb").read())
    stub[hdr_off : hdr_off + 8] = struct.pack("<II", len(payload), len(packed_payload))
    if key:
        stub[hdr_off + 8 : hdr_off + HEADER_SIZE] = key[:16]

    final_blob = bytes(stub) + packed_payload
    open(out_path, "wb").write(final_blob)
    print(
        f"packed({algo_name}): {len(final_blob)} bytes "
        f"(stub={len(stub)} packed={len(packed_payload)} unpacked={len(payload)})"
    )
