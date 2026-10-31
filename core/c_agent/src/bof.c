/*
 * bof.c — Linux BOF execution via the coffloader_linux dependency.
 * See bof.h. Linux-only; other platforms get an unsupported stub.
 */

#include "bof.h"

#ifdef __linux__

#include "util/elfload.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Loader invocation                                                          */
/* ------------------------------------------------------------------------- */

typedef char *(*c2_bof_run_fn)(const uint8_t *obj_buf, size_t object_size,
                               const char *func_name, const uint8_t *args_buf,
                               int args_len);
typedef const char *(*c2_bof_err_fn)(void);
typedef void (*c2_bof_free_fn)(char *);

static char *dup_cstr(const char *s) {
  size_t n = strlen(s) + 1;
  char *p = (char *)malloc(n);
  if (p != NULL)
    memcpy(p, s, n);
  return p;
}

c2_status c2_bof_run(const uint8_t *loader_so, size_t loader_len,
                     const uint8_t *bof, size_t bof_len,
                     const char *export_name, const uint8_t *args,
                     size_t args_len, char **out) {
  if (loader_so == NULL || loader_len == 0 || bof == NULL || bof_len == 0 ||
      out == NULL)
    return C2_ERR_ARG;
  *out = NULL;
  if (args_len > 0 && args == NULL)
    return C2_ERR_ARG;
  if (args_len > (size_t)0x7fffffff)
    return C2_ERR_OVERFLOW;

  char err[160];
  elfload_module *mod = elfload_map(loader_so, loader_len, err, sizeof(err));
  if (mod == NULL) {
    *out = dup_cstr(err[0] != '\0' ? err : "loader image rejected");
    return C2_ERR_IO;
  }

  c2_bof_run_fn run = (c2_bof_run_fn)elfload_sym(mod, "bof_run");
  c2_bof_err_fn last_err = (c2_bof_err_fn)elfload_sym(mod, "bof_last_error");
  c2_bof_free_fn release = (c2_bof_free_fn)elfload_sym(mod, "bof_free");
  if (run == NULL || last_err == NULL || release == NULL) {
    elfload_free(mod);
    return C2_ERR_UNSUPPORTED;
  }

  char *o = run(bof, bof_len,
                (export_name != NULL && export_name[0]) ? export_name : "go",
                args, (int)args_len);
  if (o == NULL) {
    const char *e = last_err();
    if (e != NULL && e[0] != '\0')
      *out = dup_cstr(e);
    elfload_free(mod);
    return C2_ERR_PROTO;
  }

  /* The loader owns the allocation; copy it out and free it before the image
   * is unmapped, then hand the copy to the caller. */
  char *copy = dup_cstr(o);
  release(o);
  elfload_free(mod);
  if (copy == NULL)
    return C2_ERR_NOMEM;
  *out = copy;
  return C2_OK;
}

#else /* !__linux__ */

c2_status c2_bof_pack_args(const c2_str *args, size_t argc, uint8_t *out,
                           size_t out_cap, size_t *out_len) {
  (void)args;
  (void)argc;
  (void)out;
  (void)out_cap;
  (void)out_len;
  return C2_ERR_UNSUPPORTED;
}

c2_status c2_bof_run(const uint8_t *loader_so, size_t loader_len,
                     const uint8_t *bof, size_t bof_len,
                     const char *export_name, const uint8_t *args,
                     size_t args_len, char **out) {
  (void)loader_so;
  (void)loader_len;
  (void)bof;
  (void)bof_len;
  (void)export_name;
  (void)args;
  (void)args_len;
  (void)out;
  return C2_ERR_UNSUPPORTED;
}

#endif /* __linux__ */
