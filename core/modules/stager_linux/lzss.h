#ifndef STAGER_LZSS_H
#define STAGER_LZSS_H

#include <stddef.h>
#include <stdint.h>

/*
 * LZSS decoder shared by the self-unpacker stub and the fuzz/unit tests.
 *
 * Format (see pack_lzss.py): one flag byte per group of up to eight tokens,
 * LSB first. A clear flag is a literal byte; a set flag is a two-byte match:
 * offset-1 (12 bits, low byte first) followed by length-3 in the high nibble.
 *
 * The packed blob is build output, but the decoder is still a memory-safety
 * boundary: a truncated token or a match that reaches before the start of the
 * output must fail instead of reading outside the source or destination.
 * Returns 0 only after producing exactly dst_len bytes.
 */
static inline int stager_lzss_decompress(const uint8_t *src, size_t src_len,
                                         uint8_t *dst, size_t dst_len) {
  size_t ip = 0, op = 0;
  while (op < dst_len) {
    if (ip >= src_len)
      return -1;
    uint8_t flags = src[ip++];
    for (int i = 0; i < 8 && op < dst_len; i++, flags >>= 1) {
      if (flags & 1) {
        if (src_len - ip < 2)
          return -1;
        uint8_t b0 = src[ip++];
        uint8_t b1 = src[ip++];
        size_t off = (size_t)(b0 | ((b1 & 0x0F) << 8)) + 1;
        size_t len = (size_t)(b1 >> 4) + 3;
        if (off > op)
          return -1;
        for (size_t j = 0; j < len && op < dst_len; j++, op++)
          dst[op] = dst[op - off];
      } else {
        if (ip >= src_len)
          return -1;
        dst[op++] = src[ip++];
      }
    }
  }
  return 0;
}

#endif /* STAGER_LZSS_H */
