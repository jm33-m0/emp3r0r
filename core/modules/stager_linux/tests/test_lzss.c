/*
 * test_lzss.c — decoder boundary tests for the self-unpacker.
 *
 * The packed stage is generated at build time, but the decoder still must not
 * read before the output buffer or past the compressed input when the header
 * is truncated or corrupted.
 */

#include "test.h"

#include "lzss.h"

#include <stdint.h>
#include <string.h>

static void test_literals(void) {
  const uint8_t src[] = {0x00, 'A', 'B', 'C'};
  uint8_t dst[3] = {0};
  CHECK_EQ_LONG(stager_lzss_decompress(src, sizeof(src), dst, sizeof(dst)), 0);
  CHECK_BYTES(dst, "ABC", 3);
}

static void test_backreference(void) {
  /* flags 0b00001000: three literals, then offset=2 (distance 3), length=3 */
  const uint8_t src[] = {0x08, 'A', 'B', 'C', 0x02, 0x00};
  uint8_t dst[6] = {0};
  CHECK_EQ_LONG(stager_lzss_decompress(src, sizeof(src), dst, sizeof(dst)), 0);
  CHECK_BYTES(dst, "ABCABC", 6);
}

static void test_truncated_token(void) {
  const uint8_t literal[] = {0x00};
  uint8_t dst[1] = {0};
  CHECK_EQ_LONG(stager_lzss_decompress(literal, sizeof(literal), dst, 1), -1);

  const uint8_t match[] = {0x01, 0x00};
  uint8_t match_dst[3] = {0};
  CHECK_EQ_LONG(stager_lzss_decompress(match, sizeof(match), match_dst, 3), -1);
}

static void test_backreference_before_output(void) {
  const uint8_t src[] = {0x01, 0x00, 0x00};
  uint8_t dst[3] = {0};
  CHECK_EQ_LONG(stager_lzss_decompress(src, sizeof(src), dst, sizeof(dst)), -1);
}

static void test_empty_output(void) {
  const uint8_t src[] = {0x00};
  uint8_t dst[1] = {0};
  CHECK_EQ_LONG(stager_lzss_decompress(src, sizeof(src), dst, 0), 0);
}

int main(void) {
  test_literals();
  test_backreference();
  test_truncated_token();
  test_backreference_before_output();
  test_empty_output();
  TEST_DONE();
}
