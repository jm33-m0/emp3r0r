// unpack_stub_lzss.c — LZSS self-unpacker stub.
//
// Decompresses the packed payload into a fresh RW mapping, which is then
// flipped to RX, and jumps to it.
// See unpack.h for the stub/packer contract.

#include "lzss.h"
#include "unpack.h"

/* Header is emitted into the read-only .unpack_header section; pack_lzss.py
 * patches unpacked_size/packed_size (key unused). */
UNPACK_HEADER();

static void do_unpack_lzss(const uint8_t *src, const struct unpack_header *h,
                           uint8_t *dst) {
  if (stager_lzss_decompress(src, h->packed_size, dst, h->unpacked_size) != 0)
    __builtin_trap();
}

__attribute__((noreturn, used)) void unpack_and_run(void) {
  unpack_run_stub(&unpack_header, do_unpack_lzss);
}

UNPACK_ENTRY();
