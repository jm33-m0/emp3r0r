#ifndef C2_STUB_CRYPTO_H
#define C2_STUB_CRYPTO_H

/*
 * stub_crypto.h — deterministic, non-secure AEAD backend for tests and
 * fuzzers. It isolates the SecureConn framing logic from real crypto: the tag
 * depends on the key, so a wrong key still fails authentication, but the
 * primitive is a trivial XOR stream.
 *
 * `rng_state` is caller-owned and used for nonces/padding.
 */

#include "c2_crypto.h"

void stub_crypto_init(c2_crypto_backend *be, uint32_t *rng_state);

#endif /* C2_STUB_CRYPTO_H */
