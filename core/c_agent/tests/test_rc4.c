#include "util/rc4.h"

#include "test.h"

#include <stdlib.h>
#include <string.h>

int main(void) {
  /* RFC 6229 test vector: 40-bit key 01 02 03 04 05, first 32 keystream bytes.
   * The reference values were produced with Go's crypto/rc4 (see the protocol
   * tests); rc4_crypt XORs zero plaintext, so the output is the keystream. */
  static const uint8_t key5[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
  static const uint8_t keystream[32] = {
      0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27, 0xcc, 0xc3, 0x52,
      0x4a, 0x0a, 0x11, 0x18, 0xa8, 0x69, 0x82, 0x94, 0x4f, 0x18, 0xfc,
      0x82, 0xd5, 0x89, 0xc4, 0x03, 0xa4, 0x7a, 0x0d, 0x09, 0x19};
  uint8_t buf[32] = {0};
  rc4_ctx ctx;

  rc4_init(&ctx, key5, sizeof(key5));
  rc4_crypt(&ctx, buf, sizeof(buf));
  CHECK_BYTES(buf, keystream, sizeof(keystream));

  /* Symmetric: encrypt then decrypt restores the plaintext. */
  const uint8_t plain[7] = {'s', 'e', 'c', 'r', 'e', 't', '!'};
  uint8_t data[7];
  rc4_ctx enc, dec;
  memcpy(data, plain, sizeof(data));
  rc4_init(&enc, key5, sizeof(key5));
  rc4_crypt(&enc, data, sizeof(data));
  CHECK(memcmp(data, plain, sizeof(data)) != 0);
  rc4_init(&dec, key5, sizeof(key5));
  rc4_crypt(&dec, data, sizeof(data));
  CHECK_BYTES(data, plain, sizeof(data));

  /* An empty/NULL key is treated as a single zero byte, never a divide-by-zero. */
  uint8_t z1[8] = {0}, z2[8] = {0};
  rc4_ctx zc1, zc2;
  rc4_init(&zc1, NULL, 0);
  rc4_crypt(&zc1, z1, sizeof(z1));
  rc4_init(&zc2, NULL, 0);
  rc4_crypt(&zc2, z2, sizeof(z2));
  CHECK_BYTES(z1, z2, sizeof(z1));

  /* decrypt_alloc rejects invalid input and reports it via out params. */
  uint8_t *out = (uint8_t *)0x1;
  size_t out_len = 123;
  CHECK_EQ_LONG(rc4_decrypt_alloc(NULL, 4, key5, 5, &out, &out_len), -1);
  CHECK(out == NULL && out_len == 0);
  CHECK_EQ_LONG(rc4_decrypt_alloc((const uint8_t *)"abcd", 4, key5, 5, &out,
                                  &out_len),
                0);
  CHECK(out != NULL && out_len == 4);
  free(out);

  TEST_DONE();
}
