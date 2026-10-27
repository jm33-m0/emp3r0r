/*
 * mbedtls.c — c2_crypto_backend over mbedTLS (self-contained).
 *
 * mbedTLS is compiled directly into the agent, so this backend has no runtime
 * dependency and is the guaranteed fallback when libcrypto is unavailable. It
 * implements the same vtable as openssl.c; the protocol layer cannot
 * tell them apart.
 *
 * MBEDTLS_ALLOW_PRIVATE_ACCESS lets this file build the ECDSA key context from
 * a raw private scalar (mbedTLS exposes no public importer for that); it is the
 * documented escape hatch for in-tree consumers.
 */

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "crypto.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/md5.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>

typedef struct {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context drbg;
} mbedtls_ctx;

/* ------------------------------------------------------------------------- */
/* Primitives                                                                 */
/* ------------------------------------------------------------------------- */

static int mb_random(void *vctx, uint8_t *buf, size_t len) {
  mbedtls_ctx *c = (mbedtls_ctx *)vctx;
  return mbedtls_ctr_drbg_random(&c->drbg, buf, len) == 0 ? 0 : -1;
}

static int mb_sha256(void *vctx, const uint8_t *data, size_t len,
                     uint8_t out[C2_SHA256_BYTES]) {
  (void)vctx;
  return mbedtls_sha256(data, len, out, 0) == 0 ? 0 : -1;
}

static int mb_md5(void *vctx, const uint8_t *data, size_t len,
                  uint8_t out[C2_MD5_BYTES]) {
  (void)vctx;
  return mbedtls_md5(data, len, out) == 0 ? 0 : -1;
}

static int mb_hkdf(void *vctx, const uint8_t *ikm, size_t ikm_len,
                   const uint8_t *salt, size_t salt_len, const uint8_t *info,
                   size_t info_len, uint8_t *out, size_t out_len) {
  (void)vctx;
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (md == NULL)
    return -1;
  return mbedtls_hkdf(md, salt, salt_len, ikm, ikm_len, info, info_len, out,
                      out_len) == 0
             ? 0
             : -1;
}

static int mb_pbkdf2(void *vctx, const uint8_t *password, size_t password_len,
                     const uint8_t *salt, size_t salt_len, uint32_t iterations,
                     uint8_t *out, size_t out_len) {
  (void)vctx;
  if (iterations > (uint32_t)UINT_MAX || out_len > (size_t)UINT32_MAX)
    return -1;
  return mbedtls_pkcs5_pbkdf2_hmac_ext(
             MBEDTLS_MD_SHA256, password, password_len, salt, salt_len,
             (unsigned int)iterations, (uint32_t)out_len, out) == 0
             ? 0
             : -1;
}

static int mb_seal(void *vctx, const uint8_t key[C2_AES_KEY_BYTES],
                   const uint8_t nonce[C2_GCM_NONCE_BYTES], const uint8_t *in,
                   size_t in_len, uint8_t *out, size_t out_cap,
                   size_t *out_len) {
  (void)vctx;
  if (out_cap < in_len + C2_GCM_TAG_BYTES)
    return -1;
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (rc == 0)
    rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, in_len, nonce,
                                   C2_GCM_NONCE_BYTES, NULL, 0, in, out,
                                   C2_GCM_TAG_BYTES, out + in_len);
  mbedtls_gcm_free(&gcm);
  if (rc != 0)
    return -1;
  *out_len = in_len + C2_GCM_TAG_BYTES;
  return 0;
}

static int mb_open(void *vctx, const uint8_t key[C2_AES_KEY_BYTES],
                   const uint8_t nonce[C2_GCM_NONCE_BYTES], const uint8_t *in,
                   size_t in_len, uint8_t *out, size_t out_cap,
                   size_t *out_len) {
  (void)vctx;
  if (in_len < C2_GCM_TAG_BYTES)
    return -1;
  size_t ct_len = in_len - C2_GCM_TAG_BYTES;
  if (out_cap < ct_len)
    return -1;
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (rc == 0)
    rc = mbedtls_gcm_auth_decrypt(&gcm, ct_len, nonce, C2_GCM_NONCE_BYTES, NULL,
                                  0, in + ct_len, C2_GCM_TAG_BYTES, in, out);
  mbedtls_gcm_free(&gcm);
  if (rc != 0)
    return -1;
  *out_len = ct_len;
  return 0;
}

/* Load the P-256 group used by every P-256 operation. Caller frees. */
static int load_p256(mbedtls_ecp_group *grp) {
  mbedtls_ecp_group_init(grp);
  return mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1) == 0 ? 0 : -1;
}

static int mb_keygen(void *vctx, uint8_t priv[C2_P256_PRIV_BYTES],
                     uint8_t pub[C2_P256_PUB_BYTES]) {
  mbedtls_ctx *c = (mbedtls_ctx *)vctx;
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point q;
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&q);
  if (load_p256(&grp) != 0)
    return -1;
  int ok = 0;
  if (mbedtls_ecp_gen_privkey(&grp, &d, mbedtls_ctr_drbg_random, &c->drbg) != 0)
    goto done;
  if (mbedtls_ecp_mul(&grp, &q, &d, &grp.G, mbedtls_ctr_drbg_random,
                      &c->drbg) != 0)
    goto done;
  if (mbedtls_mpi_write_binary(&d, priv, C2_P256_PRIV_BYTES) != 0)
    goto done;
  uint8_t sec1[1 + C2_P256_PUB_BYTES];
  size_t olen = 0;
  if (mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                     &olen, sec1, sizeof(sec1)) != 0 ||
      olen != sizeof(sec1))
    goto done;
  memcpy(pub, sec1 + 1, C2_P256_PUB_BYTES);
  ok = 1;
done:
  mbedtls_ecp_point_free(&q);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return ok ? 0 : -1;
}

static int mb_pub_from_priv(void *vctx, const uint8_t priv[C2_P256_PRIV_BYTES],
                            uint8_t pub[C2_P256_PUB_BYTES]) {
  mbedtls_ctx *c = (mbedtls_ctx *)vctx;
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point q;
  uint8_t sec1[1 + C2_P256_PUB_BYTES];
  size_t olen = 0;
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&q);
  if (load_p256(&grp) != 0)
    return -1;
  int ok = 0;
  if (mbedtls_mpi_read_binary(&d, priv, C2_P256_PRIV_BYTES) != 0)
    goto done;
  if (mbedtls_ecp_check_privkey(&grp, &d) != 0)
    goto done;
  if (mbedtls_ecp_mul(&grp, &q, &d, &grp.G, mbedtls_ctr_drbg_random,
                      &c->drbg) != 0)
    goto done;
  if (mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                     &olen, sec1, sizeof(sec1)) != 0 ||
      olen != sizeof(sec1))
    goto done;
  memcpy(pub, sec1 + 1, C2_P256_PUB_BYTES);
  ok = 1;
done:
  mbedtls_ecp_point_free(&q);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return ok ? 0 : -1;
}

static int mb_ecdh(void *vctx, const uint8_t priv[C2_P256_PRIV_BYTES],
                   const uint8_t peer_pub[C2_P256_PUB_BYTES],
                   uint8_t shared[C2_P256_COORD_BYTES]) {
  mbedtls_ctx *c = (mbedtls_ctx *)vctx;
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point peer;
  mbedtls_ecp_point res;
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&peer);
  mbedtls_ecp_point_init(&res);
  if (load_p256(&grp) != 0)
    return -1;
  int ok = 0;
  uint8_t sec1[1 + C2_P256_PUB_BYTES];
  sec1[0] = 0x04;
  memcpy(sec1 + 1, peer_pub, C2_P256_PUB_BYTES);
  if (mbedtls_mpi_read_binary(&d, priv, C2_P256_PRIV_BYTES) != 0)
    goto done;
  if (mbedtls_ecp_point_read_binary(&grp, &peer, sec1, sizeof(sec1)) != 0)
    goto done;
  if (mbedtls_ecp_check_pubkey(&grp, &peer) != 0)
    goto done;
  if (mbedtls_ecp_mul(&grp, &res, &d, &peer, mbedtls_ctr_drbg_random,
                      &c->drbg) != 0)
    goto done;
  if (mbedtls_mpi_write_binary(&res.X, shared, C2_P256_COORD_BYTES) != 0)
    goto done;
  ok = 1;
done:
  mbedtls_ecp_point_free(&res);
  mbedtls_ecp_point_free(&peer);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return ok ? 0 : -1;
}

/* Build an ECDSA context from a raw private scalar (public point included). */
static int ecdsa_from_priv(mbedtls_ctx *c, mbedtls_ecdsa_context *ec,
                           const uint8_t priv[C2_P256_PRIV_BYTES]) {
  mbedtls_ecdsa_init(ec);
  if (mbedtls_ecp_group_load(&ec->grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
    goto fail;
  if (mbedtls_mpi_read_binary(&ec->d, priv, C2_P256_PRIV_BYTES) != 0)
    goto fail;
  if (mbedtls_ecp_mul(&ec->grp, &ec->Q, &ec->d, &ec->grp.G,
                      mbedtls_ctr_drbg_random, &c->drbg) != 0)
    goto fail;
  return 0;
fail:
  mbedtls_ecdsa_free(ec);
  return -1;
}

static int mb_ecdsa_sign(void *vctx, const uint8_t priv[C2_P256_PRIV_BYTES],
                         const uint8_t *msg, size_t msg_len, uint8_t *sig,
                         size_t sig_cap, size_t *sig_len) {
  mbedtls_ctx *c = (mbedtls_ctx *)vctx;
  uint8_t digest[C2_SHA256_BYTES];
  if (mbedtls_sha256(msg, msg_len, digest, 0) != 0)
    return -1;
  mbedtls_ecdsa_context ec;
  if (ecdsa_from_priv(c, &ec, priv) != 0)
    return -1;
  size_t n = 0;
  int rc = mbedtls_ecdsa_write_signature(&ec, MBEDTLS_MD_SHA256, digest,
                                         sizeof(digest), sig, sig_cap, &n,
                                         mbedtls_ctr_drbg_random, &c->drbg);
  mbedtls_ecdsa_free(&ec);
  if (rc != 0)
    return -1;
  *sig_len = n;
  return 0;
}

static int mb_ecdsa_verify(void *vctx, const uint8_t pub[C2_P256_PUB_BYTES],
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len) {
  (void)vctx;
  uint8_t digest[C2_SHA256_BYTES];
  if (mbedtls_sha256(msg, msg_len, digest, 0) != 0)
    return -1;
  mbedtls_ecdsa_context ec;
  mbedtls_ecdsa_init(&ec);
  if (mbedtls_ecp_group_load(&ec.grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
    goto fail;
  uint8_t sec1[1 + C2_P256_PUB_BYTES];
  sec1[0] = 0x04;
  memcpy(sec1 + 1, pub, C2_P256_PUB_BYTES);
  if (mbedtls_ecp_point_read_binary(&ec.grp, &ec.Q, sec1, sizeof(sec1)) != 0)
    goto fail;
  if (mbedtls_ecp_check_pubkey(&ec.grp, &ec.Q) != 0)
    goto fail;
  int rc =
      mbedtls_ecdsa_read_signature(&ec, digest, sizeof(digest), sig, sig_len);
  mbedtls_ecdsa_free(&ec);
  return rc == 0 ? 0 : -1;
fail:
  mbedtls_ecdsa_free(&ec);
  return -1;
}

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                  */
/* ------------------------------------------------------------------------- */

c2_crypto_backend *c2_crypto_open(void) {
  mbedtls_ctx *c = (mbedtls_ctx *)calloc(1, sizeof(*c));
  if (c == NULL)
    return NULL;
  mbedtls_entropy_init(&c->entropy);
  mbedtls_ctr_drbg_init(&c->drbg);
  /* No project-identifying personalization string ships in the agent. */
  if (mbedtls_ctr_drbg_seed(&c->drbg, mbedtls_entropy_func, &c->entropy, NULL,
                            0) != 0) {
    mbedtls_ctr_drbg_free(&c->drbg);
    mbedtls_entropy_free(&c->entropy);
    free(c);
    return NULL;
  }

  c2_crypto_backend *be = (c2_crypto_backend *)calloc(1, sizeof(*be));
  if (be == NULL) {
    mbedtls_ctr_drbg_free(&c->drbg);
    mbedtls_entropy_free(&c->entropy);
    free(c);
    return NULL;
  }
  be->ctx = c;
  be->random = mb_random;
  be->aes256_gcm_seal = mb_seal;
  be->aes256_gcm_open = mb_open;
  be->sha256 = mb_sha256;
  be->md5 = mb_md5;
  be->hkdf_sha256 = mb_hkdf;
  be->pbkdf2_sha256 = mb_pbkdf2;
  be->ecdh_p256 = mb_ecdh;
  be->ec_p256_keygen = mb_keygen;
  be->ec_p256_pub_from_priv = mb_pub_from_priv;
  be->ecdsa_p256_sign_der = mb_ecdsa_sign;
  be->ecdsa_p256_verify_der = mb_ecdsa_verify;
  return be;
}

void c2_crypto_close(c2_crypto_backend *be) {
  if (be == NULL)
    return;
  mbedtls_ctx *c = (mbedtls_ctx *)be->ctx;
  if (c != NULL) {
    mbedtls_ctr_drbg_free(&c->drbg);
    mbedtls_entropy_free(&c->entropy);
    c2_secure_zero(c, sizeof(*c));
    free(c);
  }
  free(be);
}
