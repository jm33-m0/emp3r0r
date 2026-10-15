#include "util/rc4.h"

#include "fuzz_common.h"

#include <string.h>

/* Property: RC4 is an involution on the keystream, so encrypting twice with
 * the same key restores the input. Any state/keystream bug fails here. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0)
    return 0;

  size_t key_len = (size_t)data[0] + 1; /* 1..256 */
  if (key_len > size)
    key_len = size;

  const uint8_t *key = data;
  size_t n = size - key_len;
  uint8_t buf[1024];
  if (n > sizeof(buf))
    n = sizeof(buf);
  if (n)
    memcpy(buf, data + key_len, n);
  uint8_t original[1024];
  if (n)
    memcpy(original, buf, n);

  rc4_ctx a, b;
  rc4_init(&a, key, key_len);
  rc4_init(&b, key, key_len);
  rc4_crypt(&a, buf, n);
  rc4_crypt(&b, buf, n);

  if (n && memcmp(buf, original, n) != 0)
    c2_fuzz_fail("rc4 is not an involution");
  return 0;
}
