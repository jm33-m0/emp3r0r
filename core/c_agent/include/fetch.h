#ifndef C2_FETCH_H
#define C2_FETCH_H

/*
 * fetch.h — the one way a C2-hosted file reaches the agent.
 *
 * Module payloads, dependency images, the console `download` command and the
 * operator `put` upload are all the same transfer: the C2 registers a name on
 * the www route, the agent fetches it, verifies the digest the C2 supplied and
 * only then commits the bytes. Payloads are hosted gzipped and are unwrapped
 * here, so the loader and the memfs cache always see the plain image.
 */

#include "common.h"
#include "memfile.h"
#include "transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Fetch a hosted payload into memory and unwrap it. `gz_cap` bounds the
 * compressed body, `obj_cap` the unwrapped image.
 *
 * `checksum` (hex, may be empty) covers one of two artifacts, because the C2
 * hashes what it happens to have: a module payload is hashed after gzip, a
 * dependency image before it. `checksum_on_image` picks which side of the
 * unwrap it is compared against, so neither caller invents its own copy of the
 * transfer.
 *
 * On C2_OK *out is a malloc'd buffer the caller frees, and *out_len its length.
 */
c2_status c2_fetch_payload(c2_agent_session *s, c2_str name,
                           const char *checksum, int checksum_on_image,
                           size_t gz_cap, size_t obj_cap, uint8_t **out,
                           size_t *out_len, char *err, int err_cap);

/*
 * Deliver a hosted file to `dest`: a memfs key or a disk path. A disk
 * destination streams through `<dest>.part` and is renamed only after the digest
 * matches, so memory never bounds the transfer. A memfs destination is buffered
 * because memfs is memory.
 *
 * `checksum` (hex, may be empty) and the computed digest in `got_hex`
 * (optional) compare case-insensitively. `err` receives the failure reason.
 */
c2_status c2_deliver_file(c2_agent_session *s, c2_memfile *mem, c2_str name,
                          const char *dest, const char *checksum, char *got_hex,
                          size_t got_cap, char *err, int err_cap);

#ifdef __cplusplus
}
#endif

#endif /* C2_FETCH_H */
