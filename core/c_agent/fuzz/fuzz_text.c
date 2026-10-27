#include "common.h"
#include "messages.h"

#include "fuzz_common.h"

/* Exercises the pure text codecs and the canonical auth string with arbitrary
 * bytes and lengths/capacities. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t out[512];
  char b64[1024];
  size_t olen = 0;

  /* hex decode: full length and a truncation that can leave an odd nibble. */
  size_t hn = size < sizeof(out) * 2 ? size : sizeof(out) * 2;
  (void)c2_hex_decode((const char *)data, hn, out, sizeof(out));
  if (hn > 0)
    (void)c2_hex_decode((const char *)data, hn - 1, out, sizeof(out));

  /* base64url decode: the exact length and a 4-aligned prefix, with a
   * destination capacity derived from the input. */
  size_t cap = size ? size % (sizeof(out) + 1) : 0;
  (void)c2_base64url_decode((const char *)data, size, out, cap, &olen);
  size_t n4 = size & ~(size_t)3;
  if (n4 >= 4)
    (void)c2_base64url_decode((const char *)data, n4, out, size % sizeof(out),
                              &olen);

  /* base64url encode then decode round-trip. */
  size_t n = c2_base64url_encode(data, size, b64, sizeof(b64));
  if (n > 0) {
    size_t dl = 0;
    (void)c2_base64url_decode(b64, n, out, sizeof(out), &dl);
  }

  /* hex encode into a correctly sized buffer (the caller owns the capacity). */
  {
    size_t hn = size < sizeof(out) / 2 ? size : sizeof(out) / 2;
    char hex[sizeof(out) + 1];
    c2_hex_encode(data, hn, hex);
  }

  /* canonical auth string; the route is a single text field. */
  {
    char canon[1024];
    (void)c2_auth_canonical(
        c2_str_of("uuid", 4), (int64_t)size, c2_str_lit("n"),
        c2_str_of((const char *)data, size), canon, sizeof(canon), NULL);
  }

  return 0;
}
