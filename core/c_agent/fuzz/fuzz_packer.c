#include "packer.h"

#include "fuzz_common.h"

/* Drives derive_key_from_string (passphrase -> fixed 16-byte key) and
 * decode_config_string (XOR-encoded string -> NUL-terminated output) with
 * arbitrary, unsanitised input. The bounds check in decode_config_string is
 * the property under test. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char pass[128];
  size_t n = size < sizeof(pass) - 1 ? size : sizeof(pass) - 1;
  memcpy(pass, data, n);
  pass[n] = '\0';

  uint8_t key[DERIVED_KEY_LEN];
  derive_key_from_string(pass, key);

  unsigned char enc[128];
  size_t m = size < sizeof(enc) ? size : sizeof(enc);
  memcpy(enc, data, m);

  char out[128];
  size_t dest_cap = 1 + (size ? (size_t)data[0] % sizeof(out) : 0);
  decode_config_string(out, enc, dest_cap);

  (void)key;
  return 0;
}
