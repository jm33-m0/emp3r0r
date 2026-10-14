#include "c2_common.h"
#include "c2_messages.h"

#include "fuzz_common.h"

#include <string.h>

static int fake_sign(void *ctx, const uint8_t priv[C2_P256_PRIV_BYTES],
                     const uint8_t *msg, size_t msg_len, uint8_t *sig,
                     size_t sig_cap, size_t *sig_len) {
  (void)ctx;
  (void)priv;
  if (sig_cap == 0) {
    *sig_len = 0;
    return 0;
  }
  size_t n = msg_len % sig_cap;
  for (size_t i = 0; i < n; i++) {
    uint8_t byte = (msg && msg_len) ? msg[i % msg_len] : 0;
    sig[i] = (uint8_t)(byte ^ (uint8_t)i);
  }
  *sig_len = n;
  return 0;
}

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

  /* canonical auth string with newline-separated capabilities. */
  c2_str caps[C2_MAX_CAPABILITIES];
  size_t count = 0;
  const char *p = (const char *)data;
  size_t remaining = size;
  while (remaining > 0 && count < C2_MAX_CAPABILITIES) {
    const char *nl = (const char *)memchr(p, '\n', remaining);
    size_t len = nl ? (size_t)(nl - p) : remaining;
    caps[count++] = c2_str_of(p, len);
    if (!nl)
      break;
    remaining -= len + 1;
    p = nl + 1;
  }
  c2_str_list list = {caps, count, C2_MAX_CAPABILITIES};
  char canon[1024];
  (void)c2_auth_canonical(c2_str_of("uuid", 4), (int64_t)size, c2_str_lit("n"),
                          &list, canon, sizeof(canon), NULL);

  /* Over the capability bound the function must reject before touching the
   * array (items only has C2_MAX_CAPABILITIES entries). */
  {
    c2_str_list over = {caps, C2_MAX_CAPABILITIES + 1, C2_MAX_CAPABILITIES};
    (void)c2_auth_canonical(c2_str_of("uuid", 4), 0, c2_str_lit("n"), &over,
                            canon, sizeof(canon), NULL);
  }

  /* Identity-signature helper with a fake signer, exercising the base64url
   * encoding of a variable-length signature. */
  {
    c2_crypto_backend be;
    memset(&be, 0, sizeof(be));
    be.ecdsa_p256_sign_der = fake_sign;
    uint8_t priv[C2_P256_PRIV_BYTES] = {0};
    char sig_b64[256];
    size_t sb = 0;
    size_t cap = size % sizeof(sig_b64);
    (void)c2_sign_uuid_base64(&be, priv, c2_str_of((const char *)data, size),
                              sig_b64, cap, &sb);
  }

  return 0;
}
