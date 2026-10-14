/*
 * test_c2_crypto.c — backend-agnostic known-answer and property tests for a
 * c2_crypto_backend.
 *
 * The same test is compiled twice, once per backend, by selecting the opener
 * with -DTEST_OPEN=... / -DTEST_CLOSE=.... It asserts against published test
 * vectors (RFC 5869, RFC 6070-style PBKDF2, FIPS SHA/MD5) plus round-trip and
 * negative properties (tampered tag/signature must fail), so a silently broken
 * backend cannot pass.
 */

#include "c2_crypto.h"

#include "test.h"

#include <stdlib.h>
#include <string.h>

/* The provider under test is linked in directly; one provider defines
 * c2_crypto_open/c2_crypto_close. */
#ifndef TEST_OPEN
#define TEST_OPEN c2_crypto_open
#endif
#ifndef TEST_CLOSE
#define TEST_CLOSE c2_crypto_close
#endif

static void hex(const uint8_t *p, size_t n, char *out) {
  c2_hex_encode(p, n, out);
  out[n * 2] = '\0';
}

static void check_hex(const uint8_t *got, size_t n, const char *want) {
  char buf[256];
  hex(got, n, buf);
  CHECK(strcmp(buf, want) == 0);
  if (strcmp(buf, want) != 0)
    fprintf(stderr, "    got  %s\n    want %s\n", buf, want);
}

static void test_hash_kdf(c2_crypto_backend *be) {
  uint8_t out[C2_SHA256_BYTES];

  /* SHA-256("abc") */
  CHECK_EQ_LONG(be->sha256(be->ctx, (const uint8_t *)"abc", 3, out), 0);
  check_hex(out, C2_SHA256_BYTES,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  /* MD5("") */
  uint8_t md[C2_MD5_BYTES];
  CHECK_EQ_LONG(be->md5(be->ctx, (const uint8_t *)"", 0, md), 0);
  check_hex(md, C2_MD5_BYTES, "d41d8cd98f00b204e9800998ecf8427e");

  /* HKDF-SHA256 RFC 5869 test case 1. */
  {
    uint8_t ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));
    uint8_t salt[13] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    uint8_t info[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                        0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    uint8_t okm[42];
    CHECK_EQ_LONG(be->hkdf_sha256(be->ctx, ikm, sizeof(ikm), salt,
                                  sizeof(salt), info, sizeof(info), okm,
                                  sizeof(okm)),
                  0);
    check_hex(okm, sizeof(okm),
              "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5b"
              "f34007208d5b887185865");
  }

  /* PBKDF2-HMAC-SHA256("password","salt",1,32). */
  {
    uint8_t dk[C2_AES_KEY_BYTES];
    CHECK_EQ_LONG(be->pbkdf2_sha256(be->ctx, (const uint8_t *)"password", 8,
                                    (const uint8_t *)"salt", 4, 1, dk,
                                    sizeof(dk)),
                  0);
    check_hex(dk, sizeof(dk),
              "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
  }
}

static void test_gcm(c2_crypto_backend *be) {
  uint8_t key[C2_AES_KEY_BYTES];
  uint8_t nonce[C2_GCM_NONCE_BYTES];
  CHECK_EQ_LONG(be->random(be->ctx, key, sizeof(key)), 0);
  CHECK_EQ_LONG(be->random(be->ctx, nonce, sizeof(nonce)), 0);

  const uint8_t msg[] = "the quick brown fox jumps over the lazy dog";
  size_t msg_len = sizeof(msg) - 1;
  uint8_t ct[sizeof(msg) + C2_GCM_TAG_BYTES];
  size_t ct_len = 0;
  CHECK_EQ_LONG(be->aes256_gcm_seal(be->ctx, key, nonce, msg, msg_len, ct,
                                    sizeof(ct), &ct_len),
                0);
  CHECK_EQ_LONG(ct_len, msg_len + C2_GCM_TAG_BYTES);

  uint8_t pt[sizeof(msg)];
  size_t pt_len = 0;
  CHECK_EQ_LONG(be->aes256_gcm_open(be->ctx, key, nonce, ct, ct_len, pt,
                                    sizeof(pt), &pt_len),
                0);
  CHECK_EQ_LONG(pt_len, msg_len);
  CHECK_BYTES(pt, msg, msg_len);

  /* Any tag bit flip must fail authentication. */
  ct[ct_len - 1] ^= 0x01;
  CHECK(be->aes256_gcm_open(be->ctx, key, nonce, ct, ct_len, pt, sizeof(pt),
                            &pt_len) != 0);

  /* Wrong key must fail too. */
  ct[ct_len - 1] ^= 0x01;
  key[0] ^= 0x01;
  CHECK(be->aes256_gcm_open(be->ctx, key, nonce, ct, ct_len, pt, sizeof(pt),
                            &pt_len) != 0);
}

static void test_p256(c2_crypto_backend *be) {
  uint8_t a_priv[C2_P256_PRIV_BYTES], a_pub[C2_P256_PUB_BYTES];
  uint8_t b_priv[C2_P256_PRIV_BYTES], b_pub[C2_P256_PUB_BYTES];
  CHECK_EQ_LONG(be->ec_p256_keygen(be->ctx, a_priv, a_pub), 0);
  CHECK_EQ_LONG(be->ec_p256_keygen(be->ctx, b_priv, b_pub), 0);
  CHECK(memcmp(a_priv, b_priv, sizeof(a_priv)) != 0);
  CHECK(memcmp(a_pub, b_pub, sizeof(a_pub)) != 0);

  /* ECDH must be symmetric. */
  uint8_t ab[C2_P256_COORD_BYTES], ba[C2_P256_COORD_BYTES];
  CHECK_EQ_LONG(be->ecdh_p256(be->ctx, a_priv, b_pub, ab), 0);
  CHECK_EQ_LONG(be->ecdh_p256(be->ctx, b_priv, a_pub, ba), 0);
  CHECK_BYTES(ab, ba, sizeof(ab));

  /* A point that is not on the curve must be rejected (all-zero X||Y). */
  uint8_t bad[C2_P256_PUB_BYTES];
  memset(bad, 0, sizeof(bad));
  CHECK(be->ecdh_p256(be->ctx, a_priv, bad, ab) != 0);

  /* ECDSA sign/verify and tamper rejection. */
  const uint8_t msg[] = "sign me";
  size_t msg_len = sizeof(msg) - 1;
  uint8_t sig[80];
  size_t sig_len = 0;
  CHECK_EQ_LONG(be->ecdsa_p256_sign_der(be->ctx, a_priv, msg, msg_len, sig,
                                        sizeof(sig), &sig_len),
                0);
  CHECK(sig_len > 0 && sig_len <= sizeof(sig));
  CHECK_EQ_LONG(be->ecdsa_p256_verify_der(be->ctx, a_pub, msg, msg_len, sig,
                                          sig_len),
                0);

  /* Mutated message and mutated signature must both fail. */
  uint8_t msg2[sizeof(msg)];
  memcpy(msg2, msg, msg_len);
  msg2[0] ^= 0x01;
  CHECK(be->ecdsa_p256_verify_der(be->ctx, a_pub, msg2, msg_len, sig,
                                  sig_len) != 0);
  sig[sig_len / 2] ^= 0x01;
  CHECK(be->ecdsa_p256_verify_der(be->ctx, a_pub, msg, msg_len, sig,
                                  sig_len) != 0);
}

static void test_derivations(c2_crypto_backend *be) {
  /* PSK = first 32 ASCII chars of lowercase hex MD5(magic). */
  uint8_t psk[C2_AES_KEY_BYTES];
  CHECK_EQ_LONG(c2_psk_from_magic(be, "test", 4, psk), 0);
  CHECK_BYTES(psk, "098f6bcd4621d373cade4e832627b4f6", 32);

  /* Session key is deterministic in (shared, uuid) and uuid-dependent. */
  uint8_t shared[C2_P256_COORD_BYTES];
  memset(shared, 0x42, sizeof(shared));
  uint8_t k1[C2_AES_KEY_BYTES], k2[C2_AES_KEY_BYTES], k3[C2_AES_KEY_BYTES];
  CHECK_EQ_LONG(c2_derive_session_key(be, shared, c2_str_lit("uuid-1"), k1), 0);
  CHECK_EQ_LONG(c2_derive_session_key(be, shared, c2_str_lit("uuid-1"), k2), 0);
  CHECK_EQ_LONG(c2_derive_session_key(be, shared, c2_str_lit("uuid-2"), k3), 0);
  CHECK_BYTES(k1, k2, sizeof(k1));
  CHECK(memcmp(k1, k3, sizeof(k1)) != 0);
}

int main(void) {
  c2_crypto_backend *be = TEST_OPEN();
  if (be == NULL) {
    /* Backend not available on this host: skip rather than fail. */
    printf("%s: backend unavailable, skipped\n", __FILE__);
    return 0;
  }
  test_hash_kdf(be);
  test_gcm(be);
  test_p256(be);
  test_derivations(be);
  TEST_CLOSE(be);
  TEST_DONE();
}
