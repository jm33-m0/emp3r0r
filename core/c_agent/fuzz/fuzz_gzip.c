#include "c2_gzip.h"

#include "fuzz_common.h"

#include <stdlib.h>
#include <string.h>

/* Drive both gzip directions with arbitrary bytes. Decompression parses a
 * gzip header and runs miniz on untrusted input (a downloaded module is
 * attacker-adjacent), so the property under test is memory safety and a
 * correct round-trip, not acceptance. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t out[8192];
  size_t out_len = 0;
  (void)c2_gzip_decompress(data, size, out, sizeof(out), &out_len);

  /* Round-trip: compress then decompress must reproduce the input. */
  size_t bound = c2_gzip_bound(size);
  uint8_t *gz = malloc(bound);
  if (gz == NULL)
    return 0;
  size_t gz_len = 0;
  if (c2_gzip_compress(data, size, gz, bound, &gz_len) == C2_OK) {
    uint8_t *back = malloc(size ? size : 1);
    if (back != NULL) {
      size_t back_len = 0;
      if (c2_gzip_decompress(gz, gz_len, back, size ? size : 1, &back_len) !=
          C2_OK)
        c2_fuzz_fail("gzip round trip failed to decompress");
      if (back_len != size || (size && memcmp(back, data, size) != 0))
        c2_fuzz_fail("gzip round trip mismatch");
      free(back);
    }
  }
  free(gz);
  return 0;
}
