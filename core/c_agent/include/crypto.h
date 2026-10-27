#ifndef C2_CRYPTO_H
#define C2_CRYPTO_H

/*
 * crypto.h — crypto contract for a C2 agent.
 *
 * The agent needs AES-256-GCM, SHA-256, HMAC/HKDF-SHA256, MD5, P-256 ECDH and
 * P-256 ECDSA/DER. Rather than hard-code one library, the protocol layer takes
 * a small backend vtable. A hosted agent can plug in OpenSSL/libcrypto (loaded
 * with dynload.h in the stager), mbedTLS, or a freestanding implementation;
 * the framing and message code never call the library directly.
 *
 * Every method returns 0 (C2_OK) on success and a negative c2_status otherwise.
 * Buffer-capacity violations must be reported, never written past.
 */

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct c2_crypto_backend {
  /*
   * Cryptographically secure random bytes. MUST use the platform CSPRNG
   * (getrandom/urandom/BCryptGenRandom), never rand().
   */
  int (*random)(void *ctx, uint8_t *buf, size_t len);

  /*
   * AES-256-GCM seal/open with no additional authenticated data. `out` holds
   * ciphertext || 16-byte tag; the nonce is supplied separately and is never
   * written by the backend. `out_cap` must be at least in_len + 16.
   */
  int (*aes256_gcm_seal)(void *ctx, const uint8_t key[C2_AES_KEY_BYTES],
                         const uint8_t nonce[C2_GCM_NONCE_BYTES],
                         const uint8_t *in, size_t in_len, uint8_t *out,
                         size_t out_cap, size_t *out_len);
  int (*aes256_gcm_open)(void *ctx, const uint8_t key[C2_AES_KEY_BYTES],
                         const uint8_t nonce[C2_GCM_NONCE_BYTES],
                         const uint8_t *in, size_t in_len, uint8_t *out,
                         size_t out_cap, size_t *out_len);

  /* One-shot SHA-256 and MD5. */
  int (*sha256)(void *ctx, const uint8_t *data, size_t len,
                uint8_t out[C2_SHA256_BYTES]);
  int (*md5)(void *ctx, const uint8_t *data, size_t len,
             uint8_t out[C2_MD5_BYTES]);

  /*
   * HKDF-SHA256 (RFC 5869). salt/info may be NULL when their length is 0.
   * `out_len` may be any length up to 255*32.
   */
  int (*hkdf_sha256)(void *ctx, const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len, const uint8_t *info,
                     size_t info_len, uint8_t *out, size_t out_len);

  /*
   * PBKDF2-HMAC-SHA256. Used only to decrypt the embedded build config.
   */
  int (*pbkdf2_sha256)(void *ctx, const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations, uint8_t *out, size_t out_len);

  /*
   * P-256 key agreement. `priv` is the 32-byte big-endian scalar, `peer_pub` is
   * X||Y (32+32), `shared` receives the 32-byte X coordinate of the shared
   * point. The backend MUST reject a point that is not on the curve.
   */
  int (*ecdh_p256)(void *ctx, const uint8_t priv[C2_P256_PRIV_BYTES],
                   const uint8_t peer_pub[C2_P256_PUB_BYTES],
                   uint8_t shared[C2_P256_COORD_BYTES]);

  /*
   * P-256 keygen. Writes the 32-byte scalar to `priv` and X||Y to `pub`.
   */
  int (*ec_p256_keygen)(void *ctx, uint8_t priv[C2_P256_PRIV_BYTES],
                        uint8_t pub[C2_P256_PUB_BYTES]);

  /*
   * Derive the P-256 public key X||Y for an existing 32-byte scalar. Used to
   * restore the exact identity key cached by a supervising launcher; must
   * reject zero/out-of-range scalars and the point at infinity.
   */
  int (*ec_p256_pub_from_priv)(void *ctx,
                               const uint8_t priv[C2_P256_PRIV_BYTES],
                               uint8_t pub[C2_P256_PUB_BYTES]);

  /*
   * ECDSA P-256 over SHA-256(message), signature encoded as ASN.1 DER
   * SEQUENCE { INTEGER r, INTEGER s }. This is exactly what the C2 expects in
   * MsgAuth.AgentProof (raw bytes).
   */
  int (*ecdsa_p256_sign_der)(void *ctx, const uint8_t priv[C2_P256_PRIV_BYTES],
                             const uint8_t *msg, size_t msg_len, uint8_t *sig,
                             size_t sig_cap, size_t *sig_len);
  int (*ecdsa_p256_verify_der)(void *ctx, const uint8_t pub[C2_P256_PUB_BYTES],
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len);

  /* Opaque backend state (library handle, arena, ...). May be NULL. */
  void *ctx;
} c2_crypto_backend;

/*
 * Derive the per-build pre-shared key from the MagicString:
 *
 *   hexMD5 = lowercase hex of MD5(magic)      (32 ASCII chars)
 *   psk    = first 32 ASCII bytes of hexMD5
 *
 * The PSK is the AES-256 key every stream starts on. It is weak bootstrap
 * secrecy by design (see PROTOCOL.md §13); never carry sensitive data
 * before the PFS handshake completes.
 */
c2_status c2_psk_from_magic(const c2_crypto_backend *be, const char *magic,
                            size_t magic_len, uint8_t psk[C2_AES_KEY_BYTES]);

/*
 * Derive the 32-byte ephemeral session key from an ECDH shared secret:
 *
 *   HKDF-SHA256(ikm=shared, salt="session-key-salt-v1",
 *               info="client-session:" + agentUUID, L=32)
 *
 * Both peers use the same info string; the server does not flip the label.
 */
c2_status c2_derive_session_key(const c2_crypto_backend *be,
                                const uint8_t shared[C2_P256_COORD_BYTES],
                                c2_str agent_uuid,
                                uint8_t out[C2_AES_KEY_BYTES]);

/*
 * Encode a P-256 public key (X||Y) as a PEM "PUBLIC KEY" SubjectPublicKeyInfo,
 * which is what the C2's x509.ParsePKIXPublicKey expects in
 * Emp3r0rAgent.PublicKey. Writes a NUL-terminated PEM into `out` and returns
 * its length (excluding the terminator), or 0 when it does not fit.
 */
size_t c2_p256_pub_to_pem(const uint8_t pub[C2_P256_PUB_BYTES], char *out,
                          size_t cap);

/*
 * Password-based AES-256-GCM in the same container format as Go's
 * crypto.AES_GCM_Encrypt:
 *
 *   salt[16] || nonce[12] || AES-256-GCM(ciphertext || tag)
 *   key = PBKDF2-HMAC-SHA256(password, salt, 100000, 32)
 *
 * Used for agent file storage (memfs) and the embedded build config. The
 * password may be empty, in which case the primitives are still keyed (an
 * empty password is a valid PBKDF2 input); callers that want "no encryption"
 * simply skip calling these.
 */
c2_status c2_aes_gcm_encrypt_password(const c2_crypto_backend *be,
                                      c2_str password, const uint8_t *plain,
                                      size_t plain_len, uint8_t *out,
                                      size_t out_cap, size_t *out_len);
c2_status c2_aes_gcm_decrypt_password(const c2_crypto_backend *be,
                                      c2_str password, const uint8_t *enc,
                                      size_t enc_len, uint8_t *out,
                                      size_t out_cap, size_t *out_len);

/* ------------------------------------------------------------------------- */
/* Provider contract                                                          */
/* ------------------------------------------------------------------------- */

/*
 * Exactly one crypto provider is compiled in, selected with `CRYPTO=<name>`
 * (see the Makefile): src/crypto/c2_crypto_<name>.c. A provider implements this
 * contract and nothing in the protocol layer depends on which library it uses.
 *
 *   openssl (default): dlopen the system libcrypto, no build-time dependency.
 *   mbedtls:           the vendored, self-contained mbedTLS (CRYPTO=mbedtls).
 *
 * Add a provider by dropping src/crypto/c2_crypto_<name>.c into the tree and
 * building with CRYPTO=<name>.
 *
 * c2_crypto_open returns NULL when the primitives are unavailable on this
 * host; the returned backend is freed with c2_crypto_close.
 */
c2_crypto_backend *c2_crypto_open(void);
void c2_crypto_close(c2_crypto_backend *be);

#ifdef __cplusplus
}
#endif

#endif /* C2_CRYPTO_H */
