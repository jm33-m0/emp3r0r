#ifndef C2_BOF_HOST_H
#define C2_BOF_HOST_H

/*
 * bof_host.h — the host primitives a BOF can reach at runtime.
 *
 * The loader resolves `ReadFile`, `WriteFile`, `UploadFile` and `Sha256Hex`
 * through these callbacks, which back them with the agent's memfs, the disk,
 * the C2 session and the crypto backend. A BOF never sees a file descriptor,
 * a socket or a key.
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

#ifdef __cplusplus
}
#endif

#endif /* C2_BOF_HOST_H */
