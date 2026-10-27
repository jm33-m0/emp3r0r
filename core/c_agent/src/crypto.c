/*
 * crypto.c — backend-independent derivations from crypto.h.
 *
 * These put no crypto primitive of their own: they compose the backend's MD5
 * and HKDF exactly the way the Go agent does, so both sides derive the same
 * PSK and session key.
 */

#include "crypto.h"

#include <string.h>

c2_status c2_psk_from_magic(const c2_crypto_backend *be, const char *magic,
                            size_t magic_len, uint8_t psk[C2_AES_KEY_BYTES]) {
  if (be == NULL || be->md5 == NULL || psk == NULL)
    return C2_ERR_ARG;
  if (magic_len > 0 && magic == NULL)
    return C2_ERR_ARG;

  uint8_t digest[C2_MD5_BYTES];
  if (be->md5(be->ctx, (const uint8_t *)magic, magic_len, digest) != 0)
    return C2_ERR_CRYPTO;

  /* The PSK is the ASCII hex text (32 chars), not the raw 16-byte digest. */
  char hex[C2_MD5_HEX_BYTES];
  c2_hex_encode(digest, sizeof(digest), hex);
  memcpy(psk, hex, C2_AES_KEY_BYTES);
  c2_secure_zero(digest, sizeof(digest));
  c2_secure_zero(hex, sizeof(hex));
  return C2_OK;
}

c2_status c2_derive_session_key(const c2_crypto_backend *be,
                                const uint8_t shared[C2_P256_COORD_BYTES],
                                c2_str agent_uuid,
                                uint8_t out[C2_AES_KEY_BYTES]) {
  if (be == NULL || be->hkdf_sha256 == NULL || shared == NULL || out == NULL)
    return C2_ERR_ARG;
  if (agent_uuid.len > 0 && agent_uuid.ptr == NULL)
    return C2_ERR_ARG;

  /* info = "client-session:" + AgentUUID. Both peers use the same string. */
  static const char prefix[] = C2_PFS_INFO_PREFIX;
  static const char salt[] = C2_PFS_SALT;
  size_t prefix_len = sizeof(prefix) - 1;
  char info[sizeof(prefix) - 1 + 128];
  if (agent_uuid.len > sizeof(info) - prefix_len)
    return C2_ERR_OVERFLOW;
  memcpy(info, prefix, prefix_len);
  if (agent_uuid.len)
    memcpy(info + prefix_len, agent_uuid.ptr, agent_uuid.len);
  size_t info_len = prefix_len + agent_uuid.len;

  int rc = be->hkdf_sha256(
      be->ctx, shared, C2_P256_COORD_BYTES, (const uint8_t *)salt,
      sizeof(salt) - 1, (const uint8_t *)info, info_len, out, C2_AES_KEY_BYTES);
  c2_secure_zero(info, sizeof(info));
  return rc == 0 ? C2_OK : C2_ERR_CRYPTO;
}

/* ------------------------------------------------------------------------- */
/* Password-based AES-256-GCM (memfs entries, build config)                   */
/* ------------------------------------------------------------------------- */

#define C2_PW_SALT_BYTES 16u
#define C2_PW_ITERATIONS 100000u

static c2_status derive_password_key(const c2_crypto_backend *be,
                                     c2_str password, const uint8_t *salt,
                                     size_t salt_len,
                                     uint8_t key[C2_AES_KEY_BYTES]) {
  if (be->pbkdf2_sha256 == NULL)
    return C2_ERR_UNSUPPORTED;
  if (password.len > 0 && password.ptr == NULL)
    return C2_ERR_ARG;
  int rc = be->pbkdf2_sha256(be->ctx, (const uint8_t *)password.ptr,
                             password.len, salt, salt_len, C2_PW_ITERATIONS,
                             key, C2_AES_KEY_BYTES);
  return rc == 0 ? C2_OK : C2_ERR_CRYPTO;
}

c2_status c2_aes_gcm_encrypt_password(const c2_crypto_backend *be,
                                      c2_str password, const uint8_t *plain,
                                      size_t plain_len, uint8_t *out,
                                      size_t out_cap, size_t *out_len) {
  if (be == NULL || out == NULL || out_len == NULL)
    return C2_ERR_ARG;
  if (plain_len > 0 && plain == NULL)
    return C2_ERR_ARG;
  if (be->random == NULL || be->aes256_gcm_seal == NULL)
    return C2_ERR_UNSUPPORTED;
  size_t overhead = C2_PW_SALT_BYTES + C2_GCM_NONCE_BYTES + C2_GCM_TAG_BYTES;
  if (plain_len > out_cap || out_cap - plain_len < overhead)
    return C2_ERR_NOMEM;

  uint8_t salt[C2_PW_SALT_BYTES];
  uint8_t nonce[C2_GCM_NONCE_BYTES];
  uint8_t key[C2_AES_KEY_BYTES];
  if (be->random(be->ctx, salt, sizeof(salt)) != 0 ||
      be->random(be->ctx, nonce, sizeof(nonce)) != 0)
    return C2_ERR_CRYPTO;
  c2_status st = derive_password_key(be, password, salt, sizeof(salt), key);
  if (st != C2_OK) {
    c2_secure_zero(key, sizeof(key));
    return st;
  }

  uint8_t *ct = out + C2_PW_SALT_BYTES + C2_GCM_NONCE_BYTES;
  size_t ct_len = 0;
  int rc = be->aes256_gcm_seal(be->ctx, key, nonce, plain, plain_len, ct,
                               out_cap - C2_PW_SALT_BYTES - C2_GCM_NONCE_BYTES,
                               &ct_len);
  c2_secure_zero(key, sizeof(key));
  if (rc != 0)
    return C2_ERR_CRYPTO;
  memcpy(out, salt, sizeof(salt));
  memcpy(out + C2_PW_SALT_BYTES, nonce, sizeof(nonce));
  *out_len = C2_PW_SALT_BYTES + C2_GCM_NONCE_BYTES + ct_len;
  return C2_OK;
}

c2_status c2_aes_gcm_decrypt_password(const c2_crypto_backend *be,
                                      c2_str password, const uint8_t *enc,
                                      size_t enc_len, uint8_t *out,
                                      size_t out_cap, size_t *out_len) {
  if (be == NULL || enc == NULL || out == NULL)
    return C2_ERR_ARG;
  if (enc_len < C2_PW_SALT_BYTES + C2_GCM_NONCE_BYTES + C2_GCM_TAG_BYTES)
    return C2_ERR_PROTO;
  if (be->aes256_gcm_open == NULL)
    return C2_ERR_UNSUPPORTED;

  const uint8_t *salt = enc;
  const uint8_t *nonce = enc + C2_PW_SALT_BYTES;
  const uint8_t *ct = nonce + C2_GCM_NONCE_BYTES;
  size_t ct_len = enc_len - C2_PW_SALT_BYTES - C2_GCM_NONCE_BYTES;

  uint8_t key[C2_AES_KEY_BYTES];
  c2_status st = derive_password_key(be, password, salt, C2_PW_SALT_BYTES, key);
  if (st != C2_OK) {
    c2_secure_zero(key, sizeof(key));
    return st;
  }
  size_t pt_len = 0;
  int rc = be->aes256_gcm_open(be->ctx, key, nonce, ct, ct_len, out, out_cap,
                               &pt_len);
  c2_secure_zero(key, sizeof(key));
  if (rc != 0)
    return C2_ERR_CRYPTO;
  if (out_len)
    *out_len = pt_len;
  return C2_OK;
}

/* ------------------------------------------------------------------------- */
/* P-256 public key PEM (PKIX SubjectPublicKeyInfo)                           */
/* ------------------------------------------------------------------------- */

/*
 * DER for a P-256 SPKI is fully determined except for the 64-byte point:
 *
 *   SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 }, BIT STRING 04 X Y }
 *
 * so the fixed 27-byte prefix is prepended to X||Y. The server parses it with
 * x509.ParsePKIXPublicKey, i.e. it must be exactly this structure.
 */
static const uint8_t c2_spki_p256_prefix[27] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04};

size_t c2_p256_pub_to_pem(const uint8_t pub[C2_P256_PUB_BYTES], char *out,
                          size_t cap) {
  static const char b64[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  static const char begin[] = "-----BEGIN PUBLIC KEY-----\n";
  static const char end[] = "-----END PUBLIC KEY-----\n";
  if (pub == NULL || out == NULL)
    return 0;

  uint8_t der[sizeof(c2_spki_p256_prefix) + C2_P256_PUB_BYTES];
  memcpy(der, c2_spki_p256_prefix, sizeof(c2_spki_p256_prefix));
  memcpy(der + sizeof(c2_spki_p256_prefix), pub, C2_P256_PUB_BYTES);

  char b64buf[4 * ((sizeof(der) + 2) / 3)];
  size_t bl = 0;
  for (size_t i = 0; i < sizeof(der); i += 3) {
    uint32_t v = (uint32_t)der[i] << 16;
    if (i + 1 < sizeof(der))
      v |= (uint32_t)der[i + 1] << 8;
    if (i + 2 < sizeof(der))
      v |= (uint32_t)der[i + 2];
    b64buf[bl++] = b64[(v >> 18) & 0x3f];
    b64buf[bl++] = b64[(v >> 12) & 0x3f];
    b64buf[bl++] = (i + 1 < sizeof(der)) ? b64[(v >> 6) & 0x3f] : '=';
    b64buf[bl++] = (i + 2 < sizeof(der)) ? b64[v & 0x3f] : '=';
  }

  size_t o = 0;
#define PEM_PUT(s, n)                                                          \
  do {                                                                         \
    if (o + (n) + 1 > cap)                                                     \
      return 0;                                                                \
    memcpy(out + o, (s), (n));                                                 \
    o += (n);                                                                  \
  } while (0)
  PEM_PUT(begin, sizeof(begin) - 1);
  for (size_t i = 0; i < bl; i += 64) {
    size_t n = bl - i < 64 ? bl - i : 64;
    PEM_PUT(b64buf + i, n);
    PEM_PUT("\n", 1);
  }
  PEM_PUT(end, sizeof(end) - 1);
#undef PEM_PUT

  out[o] = '\0';
  c2_secure_zero(b64buf, sizeof(b64buf));
  return o;
}
