#ifndef C2_STUB_CRYPTO_H
#define C2_STUB_CRYPTO_H

/*
 * stub_crypto.h — deterministic, non-secure backend for tests and fuzzers. It
 * isolates the framing, config-container and session logic from real crypto:
 * the AEAD tag depends on the key, so a wrong key still fails authentication,
 * but every primitive is a trivial deterministic function.
 *
 * `rng_state` is caller-owned and used for nonces/padding. It must outlive the
 * backend (a static/global in single-threaded fuzz harnesses).
 */

#include "crypto.h"

void stub_crypto_init(c2_crypto_backend *be, uint32_t *rng_state);

#endif /* C2_STUB_CRYPTO_H */
