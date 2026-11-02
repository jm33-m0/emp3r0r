#ifndef C2_FILE_TRANSFER_H
#define C2_FILE_TRANSFER_H

/*
 * file_transfer.h — agent-side file transfer primitives.
 *
 * `put` streams one operator-registered file from the www route into a
 * destination on the agent, hashing as it arrives and verifying the digest once
 * the transfer completes. This is the same download primitive the module
 * dispatcher uses for payloads, so operator file uploads need no BOF.
 */

#include "common.h"
#include "memfile.h"
#include "transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stream one operator-registered file from the www route into `dest` (a memfs
 * key or a disk path). The body is hashed as it arrives; `checksum` (hex, may
 * be
 * empty) is verified once the transfer completes and the destination is only
 * committed then. `got_hex` (optional) receives the computed digest; `err`
 * receives a human-readable failure reason.
 */
c2_status c2_agent_put_file(c2_agent_session *s, c2_memfile *mem,
                            const char *name, const char *dest,
                            const char *checksum, char *got_hex, size_t got_cap,
                            char *err, int err_cap);

#ifdef __cplusplus
}
#endif

#endif /* C2_FILE_TRANSFER_H */
