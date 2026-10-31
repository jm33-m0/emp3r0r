/*
 * rvvm.c — RV32IMA guest execution via the rvvm_linux dependency.
 * See rvvm.h. Linux-only; other platforms get an unsupported stub.
 */

#include "rvvm.h"

#ifdef __linux__

#include "util/elfload.h"

#include <stdlib.h>
#include <string.h>

/* Must match struct rv_bof_args in core/modules/rvvm/rvvm.c. */
typedef struct {
  const uint8_t *buf;
  size_t len;
  const c2_rv_lib *libs;
  size_t nlibs;
} rv_bof_args;

typedef char *(*c2_rv_run_fn)(const uint8_t *image, size_t image_len,
                              const char *entry, const rv_bof_args *args);
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
                    const uint8_t *image, size_t image_len, const char *entry,
                    const uint8_t *bof_args, size_t bof_len,
                    const c2_rv_lib *libs, size_t nlibs, char **out) {
  if (loader_so == NULL || loader_len == 0 || image == NULL || image_len == 0 ||
      out == NULL)
    return C2_ERR_ARG;
  *out = NULL;
  if (bof_len > 0 && bof_args == NULL)
    return C2_ERR_ARG;
  if (nlibs > 0 && libs == NULL)
    return C2_ERR_ARG;

  char err[160];
  elfload_module *mod = elfload_map(loader_so, loader_len, err, sizeof(err));
  if (mod == NULL) {
    *out = dup_cstr(err[0] != '\0' ? err : "interpreter image rejected");
    return C2_ERR_IO;
  }

  c2_rv_run_fn run = (c2_rv_run_fn)elfload_sym(mod, "rv_run");
  c2_rv_err_fn last_err = (c2_rv_err_fn)elfload_sym(mod, "rv_last_error");
  c2_rv_free_fn release = (c2_rv_free_fn)elfload_sym(mod, "rv_free");
  if (run == NULL || last_err == NULL || release == NULL) {
    elfload_free(mod);
    return C2_ERR_UNSUPPORTED;
  }

  rv_bof_args args;
  args.buf = bof_args;
  args.len = bof_len;
  args.libs = libs;
  args.nlibs = nlibs;
  char *o =
      run(image, image_len, (entry != NULL && entry[0]) ? entry : "", &args);
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
                    const uint8_t *image, size_t image_len, const char *entry,
                    const uint8_t *bof_args, size_t bof_len,
                    const c2_rv_lib *libs, size_t nlibs, char **out) {
  (void)loader_so;
  (void)loader_len;
  (void)image;
  (void)image_len;
  (void)entry;
  (void)bof_args;
  (void)bof_len;
  (void)libs;
  (void)nlibs;
  (void)out;
  return C2_ERR_UNSUPPORTED;
}

#endif /* __linux__ */
