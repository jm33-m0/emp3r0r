/*
 * rvvm.c — RV32IMA guest execution via the rvvm_linux dependency.
 * See rvvm.h. Linux-only; other platforms get an unsupported stub.
 */

#include "rvvm.h"

#ifdef __linux__

#include "rvvm_abi.h"
#include "util/elfload.h"

extern char **environ;

#include <stdlib.h>
#include <string.h>

typedef char *(*c2_rv_run_fn)(const uint8_t *image, size_t image_len,
                              const struct rv_bof_args *args);
typedef const char *(*c2_rv_err_fn)(void);
typedef void (*c2_rv_free_fn)(char *);

static char *dup_cstr(const char *s) {
  size_t n = strlen(s) + 1;
  char *p = (char *)malloc(n);
  if (p != NULL)
    memcpy(p, s, n);
  return p;
}

c2_status c2_rv_run(const uint8_t *loader_so, size_t loader_len,
                    const uint8_t *image, size_t image_len,
                    const uint8_t *bof_args, size_t bof_len,
                    const c2_bof_host *host, char **out) {
  if (loader_so == NULL || loader_len == 0 || image == NULL || image_len == 0 ||
      out == NULL)
    return C2_ERR_ARG;
  *out = NULL;
  if (bof_len > 0 && bof_args == NULL)
    return C2_ERR_ARG;

  char err[160];
  elfload_module *mod = elfload_map(loader_so, loader_len, err, sizeof(err));
  if (mod == NULL) {
    *out = dup_cstr(err[0] != '\0' ? err : "interpreter image rejected");
    return C2_ERR_IO;
  }

  if (host != NULL) {
    typedef void (*set_host_fn)(void *, c2_bof_read_fn, c2_bof_write_fn,
                                c2_bof_upload_fn, c2_bof_sha256_fn,
                                c2_bof_relay_fn, c2_bof_exec_fn);
    set_host_fn set_host = (set_host_fn)elfload_sym(mod, "SetHostBridge");
    if (set_host != NULL)
      set_host(host->ctx, host->read, host->write, host->upload, host->sha256,
               host->relay, host->exec);
  }

  c2_rv_run_fn run = (c2_rv_run_fn)elfload_sym(mod, "Run");
  c2_rv_err_fn last_err = (c2_rv_err_fn)elfload_sym(mod, "LastError");
  c2_rv_free_fn release = (c2_rv_free_fn)elfload_sym(mod, "Free");
  if (run == NULL || last_err == NULL || release == NULL) {
    elfload_free(mod);
    return C2_ERR_UNSUPPORTED;
  }

  /* Hand the guest the agent environment, like a native BOF sees. */
  size_t env_len = 0;
  if (environ != NULL) {
    for (char **e = environ; *e != NULL; e++)
      env_len += strlen(*e) + 1;
  }
  uint8_t *env = NULL;
  if (env_len > 0) {
    env = (uint8_t *)malloc(env_len);
    if (env != NULL) {
      size_t off = 0;
      for (char **e = environ; *e != NULL; e++) {
        size_t l = strlen(*e);
        memcpy(env + off, *e, l + 1);
        off += l + 1;
      }
    } else {
      env_len = 0;
    }
  }

  struct rv_bof_args args;
  args.buf = bof_args;
  args.len = bof_len;
  args.env = env;
  args.env_len = env_len;
  char *o = run(image, image_len, &args);
  free(env);
  if (o == NULL) {
    const char *e = last_err();
    if (e != NULL && e[0] != '\0')
      *out = dup_cstr(e);
    elfload_free(mod);
    return C2_ERR_PROTO;
  }

  /* The interpreter owns the buffer; copy it out before unmapping the image. */
  char *copy = dup_cstr(o);
  release(o);
  elfload_free(mod);
  if (copy == NULL)
    return C2_ERR_NOMEM;
  *out = copy;
  return C2_OK;
}

#else /* !__linux__ */

c2_status c2_rv_run(const uint8_t *loader_so, size_t loader_len,
                    const uint8_t *image, size_t image_len,
                    const uint8_t *bof_args, size_t bof_len,
                    const c2_bof_host *host, char **out) {
  (void)loader_so;
  (void)loader_len;
  (void)image;
  (void)image_len;
  (void)bof_args;
  (void)bof_len;
  (void)host;
  (void)out;
  return C2_ERR_UNSUPPORTED;
}

#endif /* __linux__ */
