/*
 * bof.c — Linux BOF execution via the coffloader_linux dependency.
 * See bof.h. Linux-only; other platforms get an unsupported stub.
 */

#include "bof.h"

#ifdef __linux__

#include "util/dynload.h"
#include "util/elfload.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Argument packing                                                           */
/* ------------------------------------------------------------------------- */

typedef struct {
  uint8_t *buf;
  size_t cap;
  size_t len;
} abuf;

static int ab_put(abuf *b, const void *p, size_t n) {
  if (n > b->cap - b->len)
    return -1;
  if (n)
    memcpy(b->buf + b->len, p, n);
  b->len += n;
  return 0;
}

static int ab_u16(abuf *b, uint16_t v) {
  uint8_t t[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
  return ab_put(b, t, sizeof(t));
}

static int ab_u32(abuf *b, uint32_t v) {
  uint8_t t[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16),
                  (uint8_t)(v >> 24)};
  return ab_put(b, t, sizeof(t));
}

static int parse_i64(const char *s, size_t n, int64_t *out) {
  if (n == 0)
    return -1;
  size_t i = 0;
  int neg = 0;
  if (s[i] == '-') {
    neg = 1;
    i++;
  }
  if (i == n)
    return -1;
  int64_t v = 0;
  for (; i < n; i++) {
    if (s[i] < '0' || s[i] > '9')
      return -1;
    v = v * 10 + (s[i] - '0');
  }
  *out = neg ? -v : v;
  return 0;
}

/* UTF-8 -> UTF-16LE, matching Go's utf16.Encode in packLinuxArgs. */
static int utf8_to_utf16le(const char *s, size_t n, uint8_t *out, size_t cap,
                           size_t *out_len) {
  size_t o = 0;
  for (size_t i = 0; i < n;) {
    unsigned char c = (unsigned char)s[i];
    uint32_t cp;
    int len;
    if (c < 0x80) {
      cp = c;
      len = 1;
    } else if ((c & 0xE0) == 0xC0) {
      cp = c & 0x1F;
      len = 2;
    } else if ((c & 0xF0) == 0xE0) {
      cp = c & 0x0F;
      len = 3;
    } else if ((c & 0xF8) == 0xF0) {
      cp = c & 0x07;
      len = 4;
    } else {
      return -1;
    }
    if (i + (size_t)len > n)
      return -1;
    for (int k = 1; k < len; k++) {
      if (((unsigned char)s[i + k] & 0xC0) != 0x80)
        return -1;
      cp = (cp << 6) | ((unsigned char)s[i + k] & 0x3F);
    }
    i += (size_t)len;

    if (cp <= 0xFFFF) {
      if (o + 2 > cap)
        return -1;
      out[o++] = (uint8_t)cp;
      out[o++] = (uint8_t)(cp >> 8);
    } else {
      cp -= 0x10000;
      uint16_t hi = (uint16_t)(0xD800 + (cp >> 10));
      uint16_t lo = (uint16_t)(0xDC00 + (cp & 0x3FF));
      if (o + 4 > cap)
        return -1;
      out[o++] = (uint8_t)hi;
      out[o++] = (uint8_t)(hi >> 8);
      out[o++] = (uint8_t)lo;
      out[o++] = (uint8_t)(lo >> 8);
    }
  }
  *out_len = o;
  return 0;
}

c2_status c2_bof_pack_args(const c2_str *args, size_t argc, uint8_t *out,
                           size_t out_cap, size_t *out_len) {
  if (out == NULL || out_len == NULL || out_cap < 4)
    return C2_ERR_ARG;
  if (argc > 0 && args == NULL)
    return C2_ERR_ARG;

  /* The body starts after the uint32 length prefix. */
  abuf body = {out + 4, out_cap - 4, 0};
  for (size_t i = 0; i < argc; i++) {
    c2_str a = args[i];
    if (a.len == 0 || a.ptr == NULL)
      return C2_ERR_ARG;
    char kind = a.ptr[0];
    const char *v = a.ptr + 1;
    size_t vlen = a.len - 1;

    switch (kind) {
    case 'i': {
      int64_t n;
      if (parse_i64(v, vlen, &n) != 0 || ab_u32(&body, (uint32_t)n) != 0)
        return C2_ERR_ARG;
      break;
    }
    case 's': {
      int64_t n;
      if (parse_i64(v, vlen, &n) != 0 || ab_u16(&body, (uint16_t)n) != 0)
        return C2_ERR_ARG;
      break;
    }
    case 'z':
      /* Length-prefixed, NUL-terminated: BOFs routinely pass the extracted
       * pointer to BeaconPrintf("%s"), matching the Windows COFFLoader ABI. */
      if (ab_u32(&body, (uint32_t)(vlen + 1)) != 0 ||
          ab_put(&body, v, vlen) != 0 || ab_put(&body, "", 1) != 0)
        return C2_ERR_NOMEM;
      break;
    case 'Z': {
      uint8_t *tmp = (uint8_t *)malloc(vlen * 4 + 4);
      if (tmp == NULL)
        return C2_ERR_NOMEM;
      size_t wlen = 0;
      if (utf8_to_utf16le(v, vlen, tmp, vlen * 4 + 4, &wlen) != 0) {
        free(tmp);
        return C2_ERR_ARG;
      }
      /* NUL-terminated wide string; the terminator is part of the length. */
      c2_status st = (ab_u32(&body, (uint32_t)(wlen + 2)) != 0 ||
                      ab_put(&body, tmp, wlen) != 0 || ab_u16(&body, 0) != 0)
                         ? C2_ERR_NOMEM
                         : C2_OK;
      free(tmp);
      if (st != C2_OK)
        return st;
      break;
    }
    case 'b': {
      uint8_t *tmp = (uint8_t *)malloc(vlen / 2 + 1);
      if (tmp == NULL)
        return C2_ERR_NOMEM;
      long n = c2_hex_decode(v, vlen, tmp, vlen / 2 + 1);
      if (n < 0) {
        free(tmp);
        return C2_ERR_ARG;
      }
      c2_status st = (ab_u32(&body, (uint32_t)n) != 0 ||
                      ab_put(&body, tmp, (size_t)n) != 0)
                         ? C2_ERR_NOMEM
                         : C2_OK;
      free(tmp);
      if (st != C2_OK)
        return st;
      break;
    }
    default:
      return C2_ERR_ARG;
    }
  }

  /* Prepend the total body length. */
  uint32_t bl = (uint32_t)body.len;
  out[0] = (uint8_t)bl;
  out[1] = (uint8_t)(bl >> 8);
  out[2] = (uint8_t)(bl >> 16);
  out[3] = (uint8_t)(bl >> 24);
  *out_len = 4 + body.len;
  return C2_OK;
}

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

  /* The loader imports dlsym and pthread_mutex_* which live outside libc on
   * older glibc (libdl.so.2 / libpthread.so.0). Pre-load those host
   * dependencies so the in-memory relocation pass can bind them; on glibc >=
   * 2.34 they are in libc and this is a harmless no-op. */
  static const char *const host_deps[] = {"libdl.so.2", "libpthread.so.0"};
  dynload dl;
  dynload_reset(&dl);
  if (dynload_resolve(&dl) == 0) {
    for (size_t i = 0; i < sizeof(host_deps) / sizeof(host_deps[0]); i++)
      (void)dynload_open(&dl, host_deps[i], RTLD_NOW | RTLD_LOCAL);
  }

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
