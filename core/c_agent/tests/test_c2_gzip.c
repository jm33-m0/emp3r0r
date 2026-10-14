/*
 * test_c2_gzip.c — gzip writer/reader tests.
 *
 * The FTP upload path requires a valid gzip stream, so the critical property
 * is that c2_gzip_decompress (zlib) can inflate exactly what c2_gzip_compress
 * (stored blocks) produces, across block boundaries and for the empty input.
 * The reader must also reject malformed streams instead of over-reading.
 */

#include "c2_gzip.h"

#include "test.h"

#include <stdlib.h>
#include <string.h>

static void roundtrip(const uint8_t *in, size_t len) {
  uint8_t *gz = malloc(c2_gzip_bound(len) + 16);
  size_t gz_len = 0;
  CHECK_EQ_LONG(c2_gzip_compress(in, len, gz, c2_gzip_bound(len) + 16,
                                 &gz_len),
                0);
  CHECK(gz_len > 8);
  CHECK(gz[0] == 0x1f && gz[1] == 0x8b); /* gzip magic */

  /* miniz always supplies the inflater, so a well-formed stream must round
   * trip; a corrupt one must be rejected. */
  uint8_t *back = malloc(len ? len : 1);
  size_t back_len = 0;
  c2_status st = c2_gzip_decompress(gz, gz_len, back, len ? len : 1, &back_len);
  CHECK_EQ_LONG(st, C2_OK);
  CHECK_EQ_LONG(back_len, len);
  CHECK(len == 0 || memcmp(back, in, len) == 0);
  free(back);
  free(gz);
}

int main(void) {
  /* Empty, small, exactly one stored block, and crossing several blocks. */
  roundtrip((const uint8_t *)"", 0);
  roundtrip((const uint8_t *)"hello gzip", 10);
  uint8_t *big = malloc(200000);
  for (size_t i = 0; i < 200000; i++)
    big[i] = (uint8_t)(i * 31u + 7u);
  roundtrip(big, 65535);  /* one full stored block */
  roundtrip(big, 65536);  /* exactly over one block */
  roundtrip(big, 200000); /* several blocks */
  free(big);

  /* A truncated/corrupt gzip stream must fail, not read out of bounds. */
  uint8_t bad[64];
  memset(bad, 0, sizeof(bad));
  bad[0] = 0x1f;
  bad[1] = 0x8b;
  uint8_t out[256];
  size_t out_len = 0;
  c2_status st = c2_gzip_decompress(bad, sizeof(bad), out, sizeof(out),
                                    &out_len);
  CHECK(st != C2_OK);

  TEST_DONE();
}
