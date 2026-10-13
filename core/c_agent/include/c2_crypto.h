#ifndef C2_CRYPTO_H
#define C2_CRYPTO_H

/*
 * c2_crypto.h — crypto contract for a C2 agent.
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

#include "c2_common.h"

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
  int (*pbkdf2_sha256)(void *ctx, const uint8_t *password,
                       size_t password_len, const uint8_t *salt,
                       size_t salt_len, uint32_t iterations, uint8_t *out,
                       size_t out_len);

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
   * ECDSA P-256 over SHA-256(message), signature encoded as ASN.1 DER
   * SEQUENCE { INTEGER r, INTEGER s }. This is exactly what the C2 expects in
   * MsgAuth.AgentProof and MsgTunData.AgentUUIDSig (then base64url-encoded).
   */
  int (*ecdsa_p256_sign_der)(void *ctx, const uint8_t priv[C2_P256_PRIV_BYTES],
                             const uint8_t *msg, size_t msg_len, uint8_t *sig,
                             size_t sig_cap, size_t *sig_len);
  int (*ecdsa_p256_verify_der)(void *ctx,
                               const uint8_t pub[C2_P256_PUB_BYTES],
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
 * secrecy by design (see PROTOCOL.md §13); never carry sensitive data before
 * the PFS handshake completes.
 */
int c2_psk_from_magic(const c2_crypto_backend *be, const char *magic,
                      size_t magic_len, uint8_t psk[C2_AES_KEY_BYTES]);

/*
 * Derive the 32-byte ephemeral session key from an ECDH shared secret:
 *
 *   HKDF-SHA256(ikm=shared, salt="session-key-salt-v1",
 *               info="client-session:" + agentUUID, L=32)
 *
 * Both peers use the same info string; the server does not flip the label.
 */
int c2_derive_session_key(const c2_crypto_backend *be,
                          const uint8_t shared[C2_P256_COORD_BYTES],
                          c2_str agent_uuid,
                          uint8_t out[C2_AES_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* C2_CRYPTO_H */
