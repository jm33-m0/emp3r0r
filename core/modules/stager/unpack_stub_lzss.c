// unpack_stub_lzss.c — LZSS self-unpacker stub.
//
// Decompresses the packed payload into a fresh RWX mapping and jumps to it.
// See unpack.h for the stub/packer contract.

#include "unpack.h"

/* In .data; pack_lzss.py patches unpacked_size/packed_size (key unused). */
static struct unpack_header hdr = {1, 1, {0}};

/* LZSS: 8 flag bits per byte (LSB first). 0 = literal byte, 1 = match.
 * Match = 2 bytes: offset-1 (12 bits: low 8 in b0, high 4 in b1[0..3]) and
 * length-3 (4 bits, b1[4..7]). */
static void lzss_decompress(const uint8_t *src, size_t src_len, uint8_t *dst,
                            size_t dst_len) {
  size_t ip = 0, op = 0;
  while (op < dst_len && ip < src_len) {
    uint8_t flags = src[ip++];
    for (int i = 0; i < 8 && op < dst_len; i++, flags >>= 1) {
      if (flags & 1) {
        uint8_t b0 = src[ip++];
        uint8_t b1 = src[ip++];
        size_t off = b0 | ((b1 & 0x0F) << 8);
        off += 1;
        size_t len = (b1 >> 4) + 3;
        for (size_t j = 0; j < len && op < dst_len; j++, op++)
          dst[op] = dst[op - off];
      } else {
        dst[op++] = src[ip++];
      }
    }
  }
}

__attribute__((noreturn, used)) void unpack_and_run(void) {
  const uint8_t *src = (const uint8_t *)(&hdr + 1);
  long addr = unpack_mmap(0, hdr.unpacked_size, 7 /* RWX */,
                          0x22 /* MAP_PRIVATE|MAP_ANONYMOUS */, -1, 0);
  if (addr < 0)
    __builtin_trap();

  lzss_decompress(src, hdr.packed_size, (uint8_t *)addr, hdr.unpacked_size);

  ((void (*)(void))addr)(); /* original stager _start */
  __builtin_trap();
}

UNPACK_ENTRY();
