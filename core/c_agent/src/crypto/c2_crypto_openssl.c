/*
 * c2_crypto_openssl.c — c2_crypto_backend over the system libcrypto.
 *
 * Every symbol is resolved at runtime through dynload.h, so the agent neither
 * links against libcrypto nor needs its headers at build time. Only the stable,
 * public OpenSSL ABI is used (EVP for AES-GCM/HMAC/PBKDF2, the EC/ECDSA
 * primitives for P-256). libcrypto.so.3 (OpenSSL 3.x), libcrypto.so.1.1 and
 * libcrypto.so.10 (OpenSSL 1.0.2, as shipped by RHEL/CentOS 7) are tried in
 * turn; the 1.1-only BN_bn2binpad is emulated on 1.0.2 with BN_bn2bin.
 *
 * The backend is deliberately not thread-safe: the protocol layer is used from
 * one tunnel goroutine, matching the Go agent's single message-tunnel loop.
 */

#include "c2_crypto.h"

#include "util/dynload.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL ABI constants (from <openssl/ec.h>, <openssl/evp.h>). */
#define C2_NID_X9_62_PRIME256V1 415
#define C2_POINT_CONVERSION_UNCOMPRESSED 4
#define C2_EVP_CTRL_GCM_SET_IVLEN 0x9
#define C2_EVP_CTRL_GCM_GET_TAG 0x10
#define C2_EVP_CTRL_GCM_SET_TAG 0x11

/* Opaque OpenSSL types. */
typedef struct engine_st ENGINE;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_md_st EVP_MD;
typedef struct ec_key_st EC_KEY;
typedef struct ec_group_st EC_GROUP;
typedef struct ec_point_st EC_POINT;
typedef struct bignum_st BIGNUM;
typedef struct bn_ctx_st BN_CTX;
typedef struct ecdsa_sig_st ECDSA_SIG;

typedef struct {
  dynload dl;
  void *handle;

  int (*RAND_bytes)(unsigned char *, int);
  unsigned char *(*SHA256)(const unsigned char *, size_t, unsigned char *);
  unsigned char *(*MD5)(const unsigned char *, size_t, unsigned char *);
  unsigned char *(*HMAC)(const EVP_MD *, const void *, int,
                         const unsigned char *, size_t, unsigned char *,
                         unsigned int *);
  int (*PKCS5_PBKDF2_HMAC)(const char *, int, const unsigned char *, int, int,
                           const EVP_MD *, int, unsigned char *);
  const EVP_MD *(*EVP_sha256)(void);

  EVP_CIPHER_CTX *(*EVP_CIPHER_CTX_new)(void);
  void (*EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX *);
  const EVP_CIPHER *(*EVP_aes_256_gcm)(void);
  int (*EVP_EncryptInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                            const unsigned char *, const unsigned char *);
  int (*EVP_EncryptUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *,
                           const unsigned char *, int);
  int (*EVP_EncryptFinal_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);
  int (*EVP_DecryptInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                            const unsigned char *, const unsigned char *);
  int (*EVP_DecryptUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *,
                           const unsigned char *, int);
  int (*EVP_DecryptFinal_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);
  int (*EVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX *, int, int, void *);

  EC_KEY *(*EC_KEY_new_by_curve_name)(int);
  void (*EC_KEY_free)(EC_KEY *);
  int (*EC_KEY_generate_key)(EC_KEY *);
  const BIGNUM *(*EC_KEY_get0_private_key)(const EC_KEY *);
  const EC_POINT *(*EC_KEY_get0_public_key)(const EC_KEY *);
  int (*EC_KEY_set_private_key)(EC_KEY *, const BIGNUM *);
  int (*EC_KEY_set_public_key)(EC_KEY *, const EC_POINT *);
  const EC_GROUP *(*EC_KEY_get0_group)(const EC_KEY *);

  EC_GROUP *(*EC_GROUP_new_by_curve_name)(int);
  void (*EC_GROUP_free)(EC_GROUP *);
  EC_POINT *(*EC_POINT_new)(const EC_GROUP *);
  void (*EC_POINT_free)(EC_POINT *);
  int (*EC_POINT_is_on_curve)(const EC_GROUP *, const EC_POINT *, BN_CTX *);
  int (*EC_POINT_oct2point)(const EC_GROUP *, EC_POINT *,
                            const unsigned char *, size_t, BN_CTX *);
  int (*EC_POINT_point2oct)(const EC_GROUP *, const EC_POINT *, int,
                            unsigned char *, size_t, BN_CTX *);
  int (*EC_POINT_mul)(const EC_GROUP *, EC_POINT *, const BIGNUM *,
                      const EC_POINT *, const BIGNUM *, BN_CTX *);
  int (*EC_POINT_get_affine_coordinates_GFp)(const EC_GROUP *, const EC_POINT *,
                                             BIGNUM *, BIGNUM *, BN_CTX *);

  BIGNUM *(*BN_new)(void);
  void (*BN_free)(BIGNUM *);
  BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
  int (*BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
  int (*BN_bn2bin)(const BIGNUM *, unsigned char *);
  int (*BN_num_bits)(const BIGNUM *);
  BN_CTX *(*BN_CTX_new)(void);
  void (*BN_CTX_free)(BN_CTX *);

  ECDSA_SIG *(*ECDSA_do_sign)(const unsigned char *, int, EC_KEY *);
  int (*ECDSA_do_verify)(const unsigned char *, int, const ECDSA_SIG *,
                         EC_KEY *);
  void (*ECDSA_SIG_free)(ECDSA_SIG *);
  int (*i2d_ECDSA_SIG)(const ECDSA_SIG *, unsigned char **);
  ECDSA_SIG *(*d2i_ECDSA_SIG)(ECDSA_SIG **, const unsigned char **, long);
} openssl_ctx;

/* ------------------------------------------------------------------------- */
/* Loading                                                                    */
/* ------------------------------------------------------------------------- */

static void *sym(openssl_ctx *c, const char *name) {
  return dynload_sym(&c->dl, c->handle, name);
}

#define LOAD(field, name)                                                      \
  do {                                                                         \
    void *p_ = sym(c, name);                                                   \
    if (p_ == NULL)                                                            \
      goto fail;                                                               \
    memcpy(&(c->field), &p_, sizeof(p_));                                      \
  } while (0)

/* Optional symbol: absent on older OpenSSL, so a NULL result is not fatal. */
#define LOAD_OPT(field, name)                                                  \
  do {                                                                         \
    void *p_ = sym(c, name);                                                   \
    memcpy(&(c->field), &p_, sizeof(p_));                                      \
  } while (0)

static int load_symbols(openssl_ctx *c) {
  LOAD(RAND_bytes, "RAND_bytes");
  LOAD(SHA256, "SHA256");
  LOAD(MD5, "MD5");
  LOAD(HMAC, "HMAC");
  LOAD(PKCS5_PBKDF2_HMAC, "PKCS5_PBKDF2_HMAC");
  LOAD(EVP_sha256, "EVP_sha256");
  LOAD(EVP_CIPHER_CTX_new, "EVP_CIPHER_CTX_new");
  LOAD(EVP_CIPHER_CTX_free, "EVP_CIPHER_CTX_free");
  LOAD(EVP_aes_256_gcm, "EVP_aes_256_gcm");
  LOAD(EVP_EncryptInit_ex, "EVP_EncryptInit_ex");
  LOAD(EVP_EncryptUpdate, "EVP_EncryptUpdate");
  LOAD(EVP_EncryptFinal_ex, "EVP_EncryptFinal_ex");
  LOAD(EVP_DecryptInit_ex, "EVP_DecryptInit_ex");
  LOAD(EVP_DecryptUpdate, "EVP_DecryptUpdate");
  LOAD(EVP_DecryptFinal_ex, "EVP_DecryptFinal_ex");
  LOAD(EVP_CIPHER_CTX_ctrl, "EVP_CIPHER_CTX_ctrl");
  LOAD(EC_KEY_new_by_curve_name, "EC_KEY_new_by_curve_name");
  LOAD(EC_KEY_free, "EC_KEY_free");
  LOAD(EC_KEY_generate_key, "EC_KEY_generate_key");
  LOAD(EC_KEY_get0_private_key, "EC_KEY_get0_private_key");
  LOAD(EC_KEY_get0_public_key, "EC_KEY_get0_public_key");
  LOAD(EC_KEY_set_private_key, "EC_KEY_set_private_key");
  LOAD(EC_KEY_set_public_key, "EC_KEY_set_public_key");
  LOAD(EC_KEY_get0_group, "EC_KEY_get0_group");
  LOAD(EC_GROUP_new_by_curve_name, "EC_GROUP_new_by_curve_name");
  LOAD(EC_GROUP_free, "EC_GROUP_free");
  LOAD(EC_POINT_new, "EC_POINT_new");
  LOAD(EC_POINT_free, "EC_POINT_free");
  LOAD(EC_POINT_is_on_curve, "EC_POINT_is_on_curve");
  LOAD(EC_POINT_oct2point, "EC_POINT_oct2point");
  LOAD(EC_POINT_point2oct, "EC_POINT_point2oct");
  LOAD(EC_POINT_mul, "EC_POINT_mul");
  LOAD(EC_POINT_get_affine_coordinates_GFp,
       "EC_POINT_get_affine_coordinates_GFp");
  LOAD(BN_new, "BN_new");
  LOAD(BN_free, "BN_free");
  LOAD(BN_bin2bn, "BN_bin2bn");
  /* BN_bn2binpad is OpenSSL >= 1.1.0; 1.0.2 needs the emulation below. */
  LOAD_OPT(BN_bn2binpad, "BN_bn2binpad");
  LOAD_OPT(BN_bn2bin, "BN_bn2bin");
  LOAD_OPT(BN_num_bits, "BN_num_bits");
  if (c->BN_bn2binpad == NULL &&
      (c->BN_bn2bin == NULL || c->BN_num_bits == NULL))
    goto fail;
  LOAD(BN_CTX_new, "BN_CTX_new");
  LOAD(BN_CTX_free, "BN_CTX_free");
  LOAD(ECDSA_do_sign, "ECDSA_do_sign");
  LOAD(ECDSA_do_verify, "ECDSA_do_verify");
  LOAD(ECDSA_SIG_free, "ECDSA_SIG_free");
  LOAD(i2d_ECDSA_SIG, "i2d_ECDSA_SIG");
  LOAD(d2i_ECDSA_SIG, "d2i_ECDSA_SIG");
  return 0;
fail:
  return -1;
}

#undef LOAD

/* ------------------------------------------------------------------------- */
/* Primitives                                                                 */
/* ------------------------------------------------------------------------- */

static int os_random(void *vctx, uint8_t *buf, size_t len) {
  openssl_ctx *c = (openssl_ctx *)vctx;
  if (len > (size_t)INT_MAX)
    return -1;
  return c->RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}

static int os_sha256(void *vctx, const uint8_t *data, size_t len,
                     uint8_t out[C2_SHA256_BYTES]) {
  openssl_ctx *c = (openssl_ctx *)vctx;
  return c->SHA256(data, len, out) != NULL ? 0 : -1;
}

static int os_md5(void *vctx, const uint8_t *data, size_t len,
                  uint8_t out[C2_MD5_BYTES]) {
  openssl_ctx *c = (openssl_ctx *)vctx;
  return c->MD5(data, len, out) != NULL ? 0 : -1;
}

static int hmac_sha256(openssl_ctx *c, const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[C2_SHA256_BYTES]) {
  unsigned int n = 0;
  const EVP_MD *md = c->EVP_sha256();
  if (key_len > (size_t)INT_MAX)
    return -1;
  if (c->HMAC(md, key, (int)key_len, data, data_len, out, &n) == NULL)
    return -1;
  return n == C2_SHA256_BYTES ? 0 : -1;
}

/* HKDF-Extract + Expand (RFC 5869) on HMAC-SHA256. */
static int os_hkdf(void *vctx, const uint8_t *ikm, size_t ikm_len,
                   const uint8_t *salt, size_t salt_len, const uint8_t *info,
                   size_t info_len, uint8_t *out, size_t out_len) {
  openssl_ctx *c = (openssl_ctx *)vctx;
  if (out_len == 0)
    return 0;
  if (out_len > (size_t)255 * C2_SHA256_BYTES || info_len > (1u << 20))
    return -1;
  if (info_len > 0 && info == NULL)
    return -1;

  uint8_t zero_salt[C2_SHA256_BYTES] = {0};
  const uint8_t *use_salt = salt;
  size_t use_salt_len = salt_len;
  if (salt == NULL || salt_len == 0) {
    use_salt = zero_salt;
    use_salt_len = sizeof(zero_salt);
  }

  uint8_t prk[C2_SHA256_BYTES];
  if (hmac_sha256(c, use_salt, use_salt_len, ikm, ikm_len, prk) != 0)
    return -1;

  uint8_t t[C2_SHA256_BYTES];
  size_t t_len = 0;
  size_t off = 0;
  uint8_t counter = 1;
  while (off < out_len) {
    /* T(i) = HMAC(PRK, T(i-1) || info || i) */
    size_t data_len = t_len + info_len + 1;
    uint8_t *data = (uint8_t *)malloc(data_len);
    if (data == NULL)
      return -1;
    if (t_len)
      memcpy(data, t, t_len);
    if (info_len)
      memcpy(data + t_len, info, info_len);
    data[data_len - 1] = counter;

    int rc = hmac_sha256(c, prk, sizeof(prk), data, data_len, t);
    free(data);
    if (rc != 0)
      return -1;
    t_len = C2_SHA256_BYTES;

    size_t n = out_len - off;
    if (n > t_len)
      n = t_len;
    memcpy(out + off, t, n);
    off += n;
    counter++;
  }
  c2_secure_zero(prk, sizeof(prk));
  c2_secure_zero(t, sizeof(t));
  return 0;
}

static int os_pbkdf2(void *vctx, const uint8_t *password, size_t password_len,
                     const uint8_t *salt, size_t salt_len, uint32_t iterations,
                     uint8_t *out, size_t out_len) {
  openssl_ctx *c = (openssl_ctx *)vctx;
  if (password_len > (size_t)INT_MAX || salt_len > (size_t)INT_MAX ||
      out_len > (size_t)INT_MAX || iterations > (uint32_t)INT_MAX)
    return -1;
  return c->PKCS5_PBKDF2_HMAC((const char *)password, (int)password_len, salt,
                              (int)salt_len, (int)iterations, c->EVP_sha256(),
                              (int)out_len, out) == 1
             ? 0
             : -1;
}

static int os_seal(void *vctx, const uint8_t key[C2_AES_KEY_BYTES],
                   const uint8_t nonce[C2_GCM_NONCE_BYTES], const uint8_t *in,
                   size_t in_len, uint8_t *out, size_t out_cap,
                   size_t *out_len) {
  openssl_ctx *c = (openssl_ctx *)vctx;
  if (in_len > (size_t)INT_MAX || out_cap < in_len + C2_GCM_TAG_BYTES)
    return -1;
  EVP_CIPHER_CTX *ctx = c->EVP_CIPHER_CTX_new();
  if (ctx == NULL)
    return -1;
  int ok = 0;
  int outl = 0, tmpl = 0;
  if (c->EVP_EncryptInit_ex(ctx, c->EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    goto done;
  if (c->EVP_CIPHER_CTX_ctrl(ctx, C2_EVP_CTRL_GCM_SET_IVLEN,
                             C2_GCM_NONCE_BYTES, NULL) != 1)
    goto done;
  if (c->EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
    goto done;
  if (in_len > 0 &&
      c->EVP_EncryptUpdate(ctx, out, &outl, in, (int)in_len) != 1)
    goto done;
  if (c->EVP_EncryptFinal_ex(ctx, out + outl, &tmpl) != 1)
    goto done;
  outl += tmpl;
  if (c->EVP_CIPHER_CTX_ctrl(ctx, C2_EVP_CTRL_GCM_GET_TAG, C2_GCM_TAG_BYTES,
                             out + outl) != 1)
    goto done;
  *out_len = (size_t)outl + C2_GCM_TAG_BYTES;
  ok = 1;
done:
  c->EVP_CIPHER_CTX_free(ctx);
  return ok ? 0 : -1;
}

static int os_open(void *vctx, const uint8_t key[C2_AES_KEY_BYTES],
                   const uint8_t nonce[C2_GCM_NONCE_BYTES], const uint8_t *in,
                   size_t in_len, uint8_t *out, size_t out_cap,
                   size_t *out_len) {
  openssl_ctx *c = (openssl_ctx *)vctx;
  if (in_len < C2_GCM_TAG_BYTES)
    return -1;
  size_t ct_len = in_len - C2_GCM_TAG_BYTES;
  if (ct_len > (size_t)INT_MAX || out_cap < ct_len)
    return -1;
  EVP_CIPHER_CTX *ctx = c->EVP_CIPHER_CTX_new();
  if (ctx == NULL)
    return -1;
  int ok = 0;
  int outl = 0, tmpl = 0;
  if (c->EVP_DecryptInit_ex(ctx, c->EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    goto done;
  if (c->EVP_CIPHER_CTX_ctrl(ctx, C2_EVP_CTRL_GCM_SET_IVLEN,
                             C2_GCM_NONCE_BYTES, NULL) != 1)
    goto done;
  if (c->EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
    goto done;
  if (ct_len > 0 &&
      c->EVP_DecryptUpdate(ctx, out, &outl, in, (int)ct_len) != 1)
    goto done;
  if (c->EVP_CIPHER_CTX_ctrl(ctx, C2_EVP_CTRL_GCM_SET_TAG, C2_GCM_TAG_BYTES,
                             (void *)(in + ct_len)) != 1)
    goto done;
  if (c->EVP_DecryptFinal_ex(ctx, out + outl, &tmpl) != 1)
    goto done;
  *out_len = (size_t)outl + (size_t)tmpl;
  ok = 1;
done:
  c->EVP_CIPHER_CTX_free(ctx);
  return ok ? 0 : -1;
}

/* Build a peer EC_POINT from the agent's X||Y wire form on `group`. */
static EC_POINT *point_from_pub(openssl_ctx *c, const EC_GROUP *group,
                                const uint8_t pub[C2_P256_PUB_BYTES],
                                BN_CTX *bn) {
  uint8_t sec1[1 + C2_P256_PUB_BYTES];
  sec1[0] = C2_POINT_CONVERSION_UNCOMPRESSED;
  memcpy(sec1 + 1, pub, C2_P256_PUB_BYTES);
  EC_POINT *pt = c->EC_POINT_new(group);
  if (pt == NULL)
    return NULL;
  if (c->EC_POINT_oct2point(group, pt, sec1, sizeof(sec1), bn) != 1 ||
      c->EC_POINT_is_on_curve(group, pt, bn) != 1) {
    c->EC_POINT_free(pt);
    return NULL;
  }
  return pt;
}

/* BN_bn2binpad is OpenSSL >= 1.1.0. On 1.0.2, pad BN_bn2bin's big-endian
 * output with leading zero bytes to the requested width. Returns `tolen` on
 * success, like BN_bn2binpad, and -1 when the value does not fit. */
static int os_bn2binpad(openssl_ctx *c, const BIGNUM *bn, unsigned char *to,
                        int tolen) {
  if (c->BN_bn2binpad != NULL)
    return c->BN_bn2binpad(bn, to, tolen);
  int bytes = (c->BN_num_bits(bn) + 7) / 8;
  if (bytes < 0 || bytes > tolen)
    return -1;
  memset(to, 0, (size_t)(tolen - bytes));
  if (bytes > 0 && c->BN_bn2bin(bn, to + (tolen - bytes)) != bytes)
    return -1;
  return tolen;
}

static int os_ec_keygen(void *vctx, uint8_t priv[C2_P256_PRIV_BYTES],
                        uint8_t pub[C2_P256_PUB_BYTES]) {
  openssl_ctx *c = (openssl_ctx *)vctx;
  EC_KEY *key = c->EC_KEY_new_by_curve_name(C2_NID_X9_62_PRIME256V1);
  if (key == NULL)
    return -1;
  int ok = 0;
  if (c->EC_KEY_generate_key(key) != 1)
    goto done;
  const BIGNUM *d = c->EC_KEY_get0_private_key(key);
  if (d == NULL || os_bn2binpad(c, d, priv, C2_P256_PRIV_BYTES) !=
                       (int)C2_P256_PRIV_BYTES)
    goto done;
  const EC_GROUP *group = c->EC_KEY_get0_group(key);
  const EC_POINT *p = c->EC_KEY_get0_public_key(key);
  uint8_t sec1[1 + C2_P256_PUB_BYTES];
  if (c->EC_POINT_point2oct(group, p, C2_POINT_CONVERSION_UNCOMPRESSED, sec1,
                            sizeof(sec1), NULL) != sizeof(sec1))
    goto done;
  memcpy(pub, sec1 + 1, C2_P256_PUB_BYTES);
  ok = 1;
done:
  c->EC_KEY_free(key);
  return ok ? 0 : -1;
}

static int os_ecdh(void *vctx, const uint8_t priv[C2_P256_PRIV_BYTES],
                   const uint8_t peer_pub[C2_P256_PUB_BYTES],
                   uint8_t shared[C2_P256_COORD_BYTES]) {
  openssl_ctx *c = (openssl_ctx *)vctx;
  EC_GROUP *group = c->EC_GROUP_new_by_curve_name(C2_NID_X9_62_PRIME256V1);
  BN_CTX *bn = c->BN_CTX_new();
  EC_POINT *peer = NULL;
  EC_POINT *res = NULL;
  BIGNUM *d = NULL;
  BIGNUM *x = NULL;
  int ok = 0;
  if (group == NULL || bn == NULL)
    goto done;

  peer = point_from_pub(c, group, peer_pub, bn);
  if (peer == NULL)
    goto done;
  d = c->BN_bin2bn(priv, C2_P256_PRIV_BYTES, NULL);
  if (d == NULL)
    goto done;
  res = c->EC_POINT_new(group);
  x = c->BN_new();
  if (res == NULL || x == NULL)
    goto done;
  if (c->EC_POINT_mul(group, res, NULL, peer, d, bn) != 1)
    goto done;
  if (c->EC_POINT_get_affine_coordinates_GFp(group, res, x, NULL, bn) != 1)
    goto done;
  if (os_bn2binpad(c, x, shared, C2_P256_COORD_BYTES) !=
      (int)C2_P256_COORD_BYTES)
    goto done;
  ok = 1;
done:
  if (x)
    c->BN_free(x);
  if (res)
    c->EC_POINT_free(res);
  if (d)
    c->BN_free(d);
  if (peer)
    c->EC_POINT_free(peer);
  if (bn)
    c->BN_CTX_free(bn);
  if (group)
    c->EC_GROUP_free(group);
  return ok ? 0 : -1;
}

/* Build an EC_KEY holding just `priv` (enough for ECDSA_do_sign). */
static EC_KEY *eckey_from_priv(openssl_ctx *c,
                               const uint8_t priv[C2_P256_PRIV_BYTES]) {
  EC_KEY *key = c->EC_KEY_new_by_curve_name(C2_NID_X9_62_PRIME256V1);
  if (key == NULL)
    return NULL;
  BIGNUM *d = c->BN_bin2bn(priv, C2_P256_PRIV_BYTES, NULL);
  if (d == NULL || c->EC_KEY_set_private_key(key, d) != 1) {
    if (d)
      c->BN_free(d);
    c->EC_KEY_free(key);
    return NULL;
  }
  c->BN_free(d);
  return key;
}

static int os_ecdsa_sign(void *vctx, const uint8_t priv[C2_P256_PRIV_BYTES],
                         const uint8_t *msg, size_t msg_len, uint8_t *sig,
                         size_t sig_cap, size_t *sig_len) {
  openssl_ctx *c = (openssl_ctx *)vctx;
  if (sig_cap < 72) /* max DER size of a P-256 ECDSA signature */
    return -1;
  uint8_t digest[C2_SHA256_BYTES];
  if (c->SHA256(msg, msg_len, digest) == NULL)
    return -1;
  EC_KEY *key = eckey_from_priv(c, priv);
  if (key == NULL)
    return -1;
  ECDSA_SIG *s = c->ECDSA_do_sign(digest, C2_SHA256_BYTES, key);
  c->EC_KEY_free(key);
  if (s == NULL)
    return -1;
  uint8_t der[72];
  unsigned char *pp = der;
  int n = c->i2d_ECDSA_SIG(s, &pp);
  c->ECDSA_SIG_free(s);
  if (n <= 0 || (size_t)n > sig_cap)
    return -1;
  memcpy(sig, der, (size_t)n);
  *sig_len = (size_t)n;
  return 0;
}

static int os_ecdsa_verify(void *vctx, const uint8_t pub[C2_P256_PUB_BYTES],
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len) {
  openssl_ctx *c = (openssl_ctx *)vctx;
  if (sig_len > (size_t)LONG_MAX)
    return -1;
  uint8_t digest[C2_SHA256_BYTES];
  if (c->SHA256(msg, msg_len, digest) == NULL)
    return -1;

  EC_KEY *key = c->EC_KEY_new_by_curve_name(C2_NID_X9_62_PRIME256V1);
  BN_CTX *bn = c->BN_CTX_new();
  if (key == NULL || bn == NULL)
    goto fail;
  EC_POINT *pt = point_from_pub(c, c->EC_KEY_get0_group(key), pub, bn);
  if (pt == NULL)
    goto fail;
  int set = c->EC_KEY_set_public_key(key, pt);
  c->EC_POINT_free(pt);
  if (set != 1)
    goto fail;

  const unsigned char *pp = sig;
  ECDSA_SIG *s = c->d2i_ECDSA_SIG(NULL, &pp, (long)sig_len);
  if (s == NULL)
    goto fail;
  int ok = c->ECDSA_do_verify(digest, C2_SHA256_BYTES, s, key);
  c->ECDSA_SIG_free(s);
  c->EC_KEY_free(key);
  c->BN_CTX_free(bn);
  return ok == 1 ? 0 : -1;

fail:
  if (key)
    c->EC_KEY_free(key);
  if (bn)
    c->BN_CTX_free(bn);
  return -1;
}

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                  */
/* ------------------------------------------------------------------------- */

c2_crypto_backend *c2_crypto_open(void) {
  static const char *names[] = {
      "libcrypto.so.3",     "libcrypto.so.1.1",   "libcrypto.so.10",
      "libcrypto.so.1.0.0", "libcrypto.so.1.0.2", "libcrypto.so",
      NULL};
  openssl_ctx *c = (openssl_ctx *)calloc(1, sizeof(*c));
  if (c == NULL)
    return NULL;
  dynload_reset(&c->dl);
  for (size_t i = 0; names[i] != NULL; i++) {
    c->handle = dynload_open(&c->dl, names[i], RTLD_LAZY | RTLD_LOCAL);
    if (c->handle != NULL)
      break;
  }
  if (c->handle == NULL || load_symbols(c) != 0) {
    if (c->handle)
      dynload_close(&c->dl, c->handle);
    free(c);
    return NULL;
  }

  c2_crypto_backend *be = (c2_crypto_backend *)calloc(1, sizeof(*be));
  if (be == NULL) {
    dynload_close(&c->dl, c->handle);
    free(c);
    return NULL;
  }
  be->ctx = c;
  be->random = os_random;
  be->aes256_gcm_seal = os_seal;
  be->aes256_gcm_open = os_open;
  be->sha256 = os_sha256;
  be->md5 = os_md5;
  be->hkdf_sha256 = os_hkdf;
  be->pbkdf2_sha256 = os_pbkdf2;
  be->ecdh_p256 = os_ecdh;
  be->ec_p256_keygen = os_ec_keygen;
  be->ecdsa_p256_sign_der = os_ecdsa_sign;
  be->ecdsa_p256_verify_der = os_ecdsa_verify;
  return be;
}

void c2_crypto_close(c2_crypto_backend *be) {
  if (be == NULL)
    return;
  openssl_ctx *c = (openssl_ctx *)be->ctx;
  if (c != NULL) {
    if (c->handle != NULL)
      dynload_close(&c->dl, c->handle);
    c2_secure_zero(c, sizeof(*c));
    free(c);
  }
  free(be);
}
