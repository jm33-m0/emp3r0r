#include "stub_crypto.h"

#include <string.h>

static uint8_t ks_byte(const uint8_t key[C2_AES_KEY_BYTES],
                       const uint8_t nonce[C2_GCM_NONCE_BYTES], size_t i) {
  return (uint8_t)(key[i % C2_AES_KEY_BYTES] ^ nonce[i % C2_GCM_NONCE_BYTES] ^
                   (uint8_t)(i * 131u + 17u));
}

static uint64_t fnv1a(const uint8_t *p, size_t n, uint64_t h) {
  for (size_t i = 0; i < n; i++) {
    h ^= p[i];
    h *= 1099511628211ULL;
  }
  return h;
}

static void stub_tag(const uint8_t key[C2_AES_KEY_BYTES],
                     const uint8_t nonce[C2_GCM_NONCE_BYTES], const uint8_t *pt,
                     size_t n, uint8_t tag[C2_GCM_TAG_BYTES]) {
  uint64_t h = fnv1a(pt, n, fnv1a(nonce, C2_GCM_NONCE_BYTES,
                                 fnv1a(key, C2_AES_KEY_BYTES,
                                       1469598103934665603ULL)));
  for (size_t i = 0; i < C2_GCM_TAG_BYTES; i++) {
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    tag[i] = (uint8_t)(h >> (8 * (i % 8)));
  }
}

static int stub_seal(void *ctx, const uint8_t key[C2_AES_KEY_BYTES],
                     const uint8_t nonce[C2_GCM_NONCE_BYTES], const uint8_t *in,
                     size_t in_len, uint8_t *out, size_t out_cap,
                     size_t *out_len) {
  (void)ctx;
  if (out_cap < in_len + C2_GCM_TAG_BYTES)
    return -1;
  for (size_t i = 0; i < in_len; i++)
    out[i] = (uint8_t)(in[i] ^ ks_byte(key, nonce, i));
  stub_tag(key, nonce, in, in_len, out + in_len);
  *out_len = in_len + C2_GCM_TAG_BYTES;
  return 0;
}

static int stub_open(void *ctx, const uint8_t key[C2_AES_KEY_BYTES],
                     const uint8_t nonce[C2_GCM_NONCE_BYTES], const uint8_t *in,
                     size_t in_len, uint8_t *out, size_t out_cap,
                     size_t *out_len) {
  (void)ctx;
  if (in_len < C2_GCM_TAG_BYTES)
    return -1;
  size_t n = in_len - C2_GCM_TAG_BYTES;
  if (out_cap < n)
    return -1;
  for (size_t i = 0; i < n; i++)
    out[i] = (uint8_t)(in[i] ^ ks_byte(key, nonce, i));
  uint8_t want[C2_GCM_TAG_BYTES];
  stub_tag(key, nonce, out, n, want);
  if (memcmp(want, in + n, C2_GCM_TAG_BYTES) != 0)
    return -1;
  *out_len = n;
  return 0;
}

static int stub_random(void *ctx, uint8_t *buf, size_t len) {
  uint32_t *ctr = (uint32_t *)ctx;
  for (size_t i = 0; i < len; i++) {
    *ctr = *ctr * 1664525u + 1013904223u;
    buf[i] = (uint8_t)(*ctr >> 24);
  }
  return 0;
}

void stub_crypto_init(c2_crypto_backend *be, uint32_t *rng_state) {
  memset(be, 0, sizeof(*be));
  be->ctx = rng_state;
  be->random = stub_random;
  be->aes256_gcm_seal = stub_seal;
  be->aes256_gcm_open = stub_open;
}
