#include "util/packer.h"

#include "test.h"

#include <string.h>

int main(void) {
  /* Known answers produced with the Go mirror, deriveKeyFromString in
   * core/lib/listener/staged_blob.go. Keeping the vector pinned detects a
   * divergence between the C and Go key derivation. */
  static const struct {
    const char *pass;
    uint8_t key[DERIVED_KEY_LEN];
  } vectors[] = {
      {"secret",
       {0x73, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00,
        0x72, 0x00, 0x00, 0x00}},
      {"password",
       {0x70, 0x77, 0x00, 0x00, 0x61, 0x6f, 0x00, 0x00, 0x73, 0x72, 0x00, 0x00,
        0x73, 0x64, 0x00, 0x00}},
      {"1234567890abcdef",
       {0x31, 0x35, 0x39, 0x63, 0x32, 0x36, 0x30, 0x64, 0x33, 0x37, 0x61, 0x65,
        0x34, 0x38, 0x62, 0x66}},
  };

  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    uint8_t key[DERIVED_KEY_LEN];
    derive_key_from_string(vectors[i].pass, key);
    CHECK_BYTES(key, vectors[i].key, DERIVED_KEY_LEN);
  }

  /* decode_config_string reverses the build-time XOR and stops at a NUL. */
  const char *config = "hello-world";
  unsigned char encoded[32];
  char decoded[32];
  for (size_t i = 0; config[i]; i++)
    encoded[i] = (unsigned char)config[i] ^ (unsigned char)CONFIG_XOR_KEY;
  encoded[strlen(config)] = 0x00;
  memset(decoded, 0xAA, sizeof(decoded));
  decode_config_string(decoded, encoded, sizeof(decoded));
  CHECK(strcmp(decoded, config) == 0);

  /* A zero byte terminates the output even when capacity is larger. */
  {
    unsigned char e2[8] = {
        'A' ^ CONFIG_XOR_KEY, 0x00, 'B', 'B', 'B', 'B', 'B', 'B'};
    char d2[8];
    memset(d2, 0x55, sizeof(d2));
    decode_config_string(d2, e2, sizeof(d2));
    CHECK(d2[0] == 'A' && d2[1] == '\0');

    /* max_len == 0 must be a no-op and never underflow or write to dest. */
    memset(d2, 0x55, sizeof(d2));
    decode_config_string(d2, e2, 0);
    CHECK((unsigned char)d2[0] == 0x55);
  }

  /* High-bit (>= 0x80) bytes must zero-extend, matching Go's uint32(str[i]). */
  {
    const char high_pass[] = "\x80\x81\x82\x83";
    uint8_t high_key[DERIVED_KEY_LEN];
    const uint8_t expected[DERIVED_KEY_LEN] = {
        0x80, 0x00, 0x00, 0x00, 0x81, 0x00, 0x00, 0x00,
        0x82, 0x00, 0x00, 0x00, 0x83, 0x00, 0x00, 0x00};
    derive_key_from_string(high_pass, high_key);
    CHECK_BYTES(high_key, expected, DERIVED_KEY_LEN);
  }

  TEST_DONE();
}
