/*
 * fuzz_lzss.c — the stager's self-unpacker decoder on hostile packed input.
 *
 * The first four bytes select the destination length (little-endian, capped);
 * the rest is treated as the LZSS stream. A decoder bug must show up as an
 * ASan/UBSan failure, never as an out-of-bounds read or an underflowing match.
 */

#include "fuzz_common.h"
#include "lzss.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DST (64u * 1024u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4)
    return 0;

  uint32_t raw_len = 0;
  memcpy(&raw_len, data, sizeof(raw_len));
  size_t dst_len = (size_t)(raw_len % (MAX_DST + 1u));
  if (dst_len == 0)
    return 0;

  uint8_t *dst = malloc(dst_len);
  if (dst == NULL)
    return 0;
  (void)stager_lzss_decompress(data + 4, size - 4, dst, dst_len);
  free(dst);
  return 0;
}
