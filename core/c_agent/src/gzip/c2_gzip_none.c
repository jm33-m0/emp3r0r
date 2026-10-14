/*
 * c2_gzip_none.c — stub gzip provider for builds that do not need compression.
 *
 * Selected with `GZIP=none`. The FTP upload and gzipped module download then
 * fail cleanly with C2_ERR_UNSUPPORTED instead of pulling a compression
 * dependency into the agent; everything else works unchanged.
 */

#include "c2_gzip.h"

size_t c2_gzip_bound(size_t in_len) {
  (void)in_len;
  return 0;
}

c2_status c2_gzip_compress(const uint8_t *in, size_t in_len, uint8_t *out,
                           size_t out_cap, size_t *out_len) {
  (void)in;
  (void)in_len;
  (void)out;
  (void)out_cap;
  (void)out_len;
  return C2_ERR_UNSUPPORTED;
}

c2_status c2_gzip_decompress(const uint8_t *in, size_t in_len, uint8_t *out,
                             size_t out_cap, size_t *out_len) {
  (void)in;
  (void)in_len;
  (void)out;
  (void)out_cap;
  (void)out_len;
  return C2_ERR_UNSUPPORTED;
}
