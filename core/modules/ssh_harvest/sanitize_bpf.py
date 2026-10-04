#!/usr/bin/env python3
"""Remove identifying debug metadata from the shipped BPF object.

`clang -g` is required to make the `.BTF`/`.BTF.ext` sections libbpf needs for
BTF-defined maps, but it also emits the build directory, the file name and the
full source text of every probed line into the object. The object is uploaded
to the agent, so none of that belongs in it.

The rewrite is in place and only touches debug metadata:

  * `.debug_*`/`.rel.debug_*`/`.llvm_addrsig` are emptied,
  * every `.BTF` string referenced by a `.BTF.ext` line-info record is
    replaced by "?", keeping the string offsets and every BTF type intact.

libbpf only requires `.BTF.ext` to be structurally valid; it never interprets
the line-info text. The script aborts without modifying the file if the object
does not match the ELF64/BTF layout it expects, so a compiler change cannot
silently produce an unsanitised artifact.
"""

import struct
import sys

ELF_MAGIC = b"\x7fELF"
BTF_MAGIC = 0xEB9F


def fail(msg):
    raise SystemExit("sanitize_bpf: " + msg)


def parse_sections(data):
    """Return (e_shoff, e_shentsize, [(header_offset, name, shdr)])."""
    if data[:4] != ELF_MAGIC or data[4] != 2 or data[5] != 1:
        fail("not a little-endian ELF64 object")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    if e_shoff == 0 or e_shnum == 0:
        fail("object has no section table")

    sections = []
    for i in range(e_shnum):
        hdr = e_shoff + i * e_shentsize
        sh = struct.unpack_from("<IIQQQQIIQQ", data, hdr)
        sections.append((hdr, sh))
    if e_shstrndx >= len(sections):
        fail("invalid section name table index")

    _, shstr = sections[e_shstrndx]
    strtab = data[shstr[4]:shstr[4] + shstr[5]]

    def name_of(sh):
        off = sh[0]
        if off >= len(strtab):
            return ""
        end = strtab.find(b"\0", off)
        return strtab[off:end].decode("ascii", "replace")

    named = [(hdr, name_of(sh), sh) for hdr, sh in sections]
    return e_shoff, e_shentsize, named


def empty_section(data, hdr, sh):
    """Zero a section's bytes and mark it NULL so tools skip it."""
    data[sh[4]:sh[4] + sh[5]] = b"\0" * sh[5]
    struct.pack_into("<I", data, hdr + 4, 0)   # sh_type = SHT_NULL
    struct.pack_into("<Q", data, hdr + 32, 0)  # sh_size = 0


def line_string_offsets(data, ext_off, ext_size):
    """Collect the `.BTF` string offsets used by `.BTF.ext` line info."""
    ext = bytes(data[ext_off:ext_off + ext_size])
    if len(ext) < 32:
        fail(".BTF.ext is too short")
    magic, version, flags, hdr_len, func_off, func_len, line_off, line_len = \
        struct.unpack_from("<HBBIIIII", ext, 0)
    if magic != BTF_MAGIC or version != 1 or flags != 0:
        fail("unsupported .BTF.ext header")
    if line_len == 0:
        return set()  # no line info to sanitise
    if hdr_len + line_off + line_len > len(ext):
        fail(".BTF.ext line info is out of bounds")

    blob = ext[hdr_len + line_off:hdr_len + line_off + line_len]
    if len(blob) < 12:
        fail(".BTF.ext line info is truncated")
    rec_size = struct.unpack_from("<I", blob, 0)[0]
    if rec_size < 16:
        fail("unexpected .BTF.ext line record size %d" % rec_size)

    refs = set()
    off = 4
    while off + 8 <= len(blob):
        _, num_info = struct.unpack_from("<II", blob, off)
        off += 8
        if off + num_info * rec_size > len(blob):
            fail(".BTF.ext line info section is out of bounds")
        for i in range(num_info):
            # struct bpf_line_info: insn_off, file_name_off, line_off, line_col.
            # Both strings are rewritten, so the source file path goes too.
            rec = off + i * rec_size
            refs.add(struct.unpack_from("<I", blob, rec + 4)[0])
            refs.add(struct.unpack_from("<I", blob, rec + 8)[0])
        off += num_info * rec_size
    return refs


def scrub_btf_strings(data, btf_off, btf_size, refs):
    btf = bytes(data[btf_off:btf_off + btf_size])
    magic, version, flags, hdr_len, _, _, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", btf, 0)
    if magic != BTF_MAGIC or version != 1 or flags != 0:
        fail("unsupported .BTF header")
    if hdr_len + str_off + str_len > btf_size:
        fail(".BTF string table is out of bounds")

    base = btf_off + hdr_len + str_off
    for ref in refs:
        if ref == 0:
            continue  # offset 0 is the empty string, leave it
        if ref >= str_len:
            fail(".BTF.ext references an out-of-range string")
        end = btf.find(b"\0", hdr_len + str_off + ref)
        if end < 0:
            fail("unterminated .BTF string")
        data[base + ref] = ord("?")
        zero_from = base + ref + 1
        zero_to = btf_off + end
        if zero_to > zero_from:
            data[zero_from:zero_to] = b"\0" * (zero_to - zero_from)


def main(path):
    data = bytearray(open(path, "rb").read())
    _, _, sections = parse_sections(data)

    ext = btf = None
    for hdr, name, sh in sections:
        if sh[5] == 0:
            continue
        if name == ".BTF.ext":
            ext = sh
        elif name == ".BTF":
            btf = sh
        elif name.startswith(".debug_") or name.startswith(".rel.debug_") or \
                name == ".llvm_addrsig":
            empty_section(data, hdr, sh)

    if btf is None:
        fail("no .BTF section")
    if ext is None:
        # No line info means no source text to scrub; the compile flag still
        # keeps the build directory out of the remaining file records.
        open(path, "wb").write(data)
        return

    scrub_btf_strings(data, btf[4], btf[5], line_string_offsets(data, ext[4], ext[5]))
    open(path, "wb").write(data)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: sanitize_bpf.py <object>")
    main(sys.argv[1])
