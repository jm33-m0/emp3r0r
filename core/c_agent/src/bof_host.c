/*
 * bof_host.c — the host primitives a BOF reaches through the loader.
 *
 * A BOF is untrusted: every path is either a canonical memfs key or a disk
 * path, reads are bounded, and an upload streams from the source instead of
 * materialising the file. Errors come back as a status plus a short message
 * the BOF can print.
 */

#define _POSIX_C_SOURCE 200809L

#include "bof_host.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define C2_BOF_FILE_MAX (64u * 1024u * 1024u)

static void set_err(char *err, int cap, const char *msg) {
  if (err != NULL && cap > 0)
    snprintf(err, (size_t)cap, "%s", msg);
}

static void set_status_err(char *err, int cap, c2_status st) {
  set_err(err, cap, c2_status_str(st));
}

static void set_too_large_err(char *err, int err_cap) {
  if (err == NULL || err_cap <= 0)
    return;
  snprintf(err, (size_t)err_cap, "file too large (limit %lu bytes)",
           (unsigned long)C2_BOF_FILE_MAX);
}

static c2_status read_disk(const char *path, uint8_t **out, size_t *out_len) {
  *out = NULL;
  *out_len = 0;
  FILE *f = fopen(path, "rb");
  if (f == NULL)
    return C2_ERR_IO;
  if (fseeko(f, 0, SEEK_END) != 0) {
    fclose(f);
    return C2_ERR_IO;
  }
  off_t end = ftello(f);
  if (end < 0 || fseeko(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return C2_ERR_IO;
  }
  size_t len = (size_t)end;
  if (len > C2_BOF_FILE_MAX) {
    fclose(f);
    return C2_ERR_OVERFLOW;
  }
  uint8_t *buf = (uint8_t *)malloc(len > 0 ? len : 1);
  if (buf == NULL) {
    fclose(f);
    return C2_ERR_NOMEM;
  }
  if (len > 0 && fread(buf, 1, len, f) != len) {
    free(buf);
    fclose(f);
    return C2_ERR_IO;
  }
  fclose(f);
  *out = buf;
  *out_len = len;
  return C2_OK;
}

static c2_status read_mem(c2_memfile *mem, const char *path, uint8_t **out,
                          size_t *out_len) {
  *out = NULL;
  *out_len = 0;
  char key[PATH_MAX];
  size_t key_len = c2_memfile_path_key(path, key, sizeof(key));
  if (key_len == 0)
    return C2_ERR_ARG;
  return c2_memfile_read_alloc(mem, c2_str_of(key, key_len), out, out_len);
}

int c2_bof_host_read(void *vctx, const char *path, uint8_t **out, size_t *len,
                     char *err, int err_cap) {
  c2_bof_host_ctx *ctx = (c2_bof_host_ctx *)vctx;
  if (ctx == NULL || path == NULL || path[0] == '\0' || out == NULL ||
      len == NULL) {
    set_err(err, err_cap, "invalid argument");
    return C2_ERR_ARG;
  }
  *out = NULL;
  *len = 0;

  c2_status st;
  if (c2_memfile_is_path(path)) {
    st = read_mem(ctx->mem, path, out, len);
  } else {
    st = read_disk(path, out, len);
  }
  if (st == C2_ERR_OVERFLOW)
    set_too_large_err(err, err_cap);
  else if (st != C2_OK)
    set_status_err(err, err_cap, st);
  return (int)st;
}

int c2_bof_host_write(void *vctx, const char *path, const uint8_t *data,
                      size_t len, char *err, int err_cap) {
  c2_bof_host_ctx *ctx = (c2_bof_host_ctx *)vctx;
  if (ctx == NULL || path == NULL || path[0] == '\0' ||
      (len > 0 && data == NULL)) {
    set_err(err, err_cap, "invalid argument");
    return C2_ERR_ARG;
  }

  if (c2_memfile_is_path(path)) {
    char key[PATH_MAX];
    size_t key_len = c2_memfile_path_key(path, key, sizeof(key));
    if (key_len == 0) {
      set_err(err, err_cap, "invalid memfs path");
      return C2_ERR_ARG;
    }
    c2_status st =
        c2_memfile_write(ctx->mem, c2_str_of(key, key_len), data, len);
    if (st != C2_OK)
      set_status_err(err, err_cap, st);
    return (int)st;
  }

  FILE *f = fopen(path, "wb");
  if (f == NULL) {
    set_err(err, err_cap, "cannot open destination");
    return C2_ERR_IO;
  }
  size_t wrote = len > 0 ? fwrite(data, 1, len, f) : 0;
  int failed = ferror(f) || wrote != len;
  if (fclose(f) != 0)
    failed = 1;
  if (failed) {
    set_err(err, err_cap, "cannot write destination");
    return C2_ERR_IO;
  }
  return C2_OK;
}

/* The session pulls upload chunks; a disk source reads on demand, a memfs
 * source is already in memory. */
static c2_status disk_chunk(void *vctx, uint8_t *out, size_t cap, size_t *len) {
  FILE *f = (FILE *)vctx;
  size_t n = fread(out, 1, cap, f);
  if (n == 0 && ferror(f))
    return C2_ERR_IO;
  *len = n;
  return C2_OK;
}

typedef struct {
  const uint8_t *data;
  size_t len;
  size_t off;
} mem_reader;

static c2_status mem_chunk(void *vctx, uint8_t *out, size_t cap, size_t *len) {
  mem_reader *r = (mem_reader *)vctx;
  size_t n = r->len - r->off;
  if (n > cap)
    n = cap;
  if (n > 0)
    memcpy(out, r->data + r->off, n);
  r->off += n;
  *len = n;
  return C2_OK;
}

int c2_bof_host_upload(void *vctx, const char *token, const char *path,
                       unsigned long offset, char *err, int err_cap) {
  c2_bof_host_ctx *ctx = (c2_bof_host_ctx *)vctx;
  if (ctx == NULL || ctx->s == NULL || token == NULL || token[0] == '\0' ||
      path == NULL || path[0] == '\0') {
    set_err(err, err_cap, "invalid argument");
    return C2_ERR_ARG;
  }
  c2_str tok = c2_str_of(token, strlen(token));
  c2_status st;

  if (c2_memfile_is_path(path)) {
    char key[PATH_MAX];
    size_t key_len = c2_memfile_path_key(path, key, sizeof(key));
    if (key_len == 0) {
      set_err(err, err_cap, "invalid memfs path");
      return C2_ERR_ARG;
    }
    uint8_t *data = NULL;
    size_t len = 0;
    st = c2_memfile_read_alloc(ctx->mem, c2_str_of(key, key_len), &data, &len);
    if (st != C2_OK) {
      set_status_err(err, err_cap, st);
      return (int)st;
    }
    if ((size_t)offset > len) {
      free(data);
      set_err(err, err_cap, "offset past end of file");
      return C2_ERR_ARG;
    }
    mem_reader r = {data + offset, len - (size_t)offset, 0};
    st = c2_session_upload_stream(ctx->s, tok, mem_chunk, &r);
    free(data);
    if (st != C2_OK) {
      set_status_err(err, err_cap, st);
      return (int)st;
    }
    return C2_OK;
  }

  struct stat sb;
  if (stat(path, &sb) != 0) {
    set_err(err, err_cap, "cannot stat source file");
    return C2_ERR_IO;
  }
  if (!S_ISREG(sb.st_mode)) {
    set_err(err, err_cap, "source is not a regular file");
    return C2_ERR_ARG;
  }
  if (sb.st_size < 0 || (off_t)offset > sb.st_size) {
    set_err(err, err_cap, "offset past end of file");
    return C2_ERR_ARG;
  }
  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    set_err(err, err_cap, "cannot open source file");
    return C2_ERR_IO;
  }
  if (offset > 0 && fseeko(f, (off_t)offset, SEEK_SET) != 0) {
    fclose(f);
    set_err(err, err_cap, "cannot seek source file");
    return C2_ERR_IO;
  }
  st = c2_session_upload_stream(ctx->s, tok, disk_chunk, f);
  fclose(f);
  if (st != C2_OK) {
    set_status_err(err, err_cap, st);
    return (int)st;
  }
  return C2_OK;
}

int c2_bof_host_sha256(void *vctx, const uint8_t *data, size_t len, char *hex,
                       size_t hex_cap, char *err, int err_cap) {
  c2_bof_host_ctx *ctx = (c2_bof_host_ctx *)vctx;
  if (ctx == NULL || ctx->s == NULL || (len > 0 && data == NULL) ||
      hex == NULL || hex_cap < C2_SHA256_BYTES * 2 + 1) {
    set_err(err, err_cap, "invalid argument");
    return C2_ERR_ARG;
  }
  const c2_crypto_backend *be = ctx->s->be;
  void *be_ctx = be != NULL ? be->ctx : NULL;
  if (be == NULL || be->sha256 == NULL) {
    set_err(err, err_cap, "sha256 unavailable");
    return C2_ERR_UNSUPPORTED;
  }
  uint8_t digest[C2_SHA256_BYTES];
  if (be->sha256(be_ctx, data, len, digest) != 0) {
    set_err(err, err_cap, "sha256 failed");
    return C2_ERR_CRYPTO;
  }
  c2_hex_encode(digest, sizeof(digest), hex);
  hex[sizeof(digest) * 2] = '\0';
  return C2_OK;
}
