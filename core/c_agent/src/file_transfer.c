/*
 * file_transfer.c — operator file upload (`put`).
 *
 * This is the module-payload download path with a destination: the body comes
 * over the www route with the same session primitive a module payload uses, the
 * name is a token the operator registered for this agent, and the digest is
 * verified before the destination is committed.
 */

#define _POSIX_C_SOURCE 200809L

#include "file_transfer.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* A memfs destination is memory by definition, so it is buffered; disk
 * destinations are streamed and unbounded. */
#define C2_PUT_MEM_MAX (64u * 1024u * 1024u)

static void set_err(char *err, int cap, const char *msg) {
  if (err != NULL && cap > 0)
    snprintf(err, (size_t)cap, "%s", msg);
}

static c2_status ensure_parent_dirs(const char *path) {
  char tmp[PATH_MAX];
  size_t len = strlen(path);
  if (len == 0 || len >= sizeof(tmp))
    return C2_ERR_ARG;
  memcpy(tmp, path, len + 1);
  for (char *p = tmp + 1; *p != '\0'; p++) {
    if (*p != '/')
      continue;
    *p = '\0';
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
      return C2_ERR_IO;
    *p = '/';
  }
  return C2_OK;
}

/* sha256_final frees the streaming context, so a path that abandons the digest
 * calls it to release the context it will not use. */
static void hash_abort(const c2_crypto_backend *be, void *be_ctx, void *hash) {
  if (hash != NULL)
    be->sha256_final(be_ctx, hash, (uint8_t[C2_SHA256_BYTES]){0});
}

typedef struct {
  FILE *f;      /* disk sink; NULL writes into buf (memfs) */
  uint8_t *buf; /* memfs sink: memfs is memory */
  size_t cap;
  size_t len;
  const c2_crypto_backend *be;
  void *be_ctx;
  void *hash;
} put_sink;

static c2_status put_sink_write(void *vctx, const uint8_t *data, size_t len) {
  put_sink *d = (put_sink *)vctx;
  if (len == 0)
    return C2_OK;
  if (d->f != NULL) {
    if (fwrite(data, 1, len, d->f) != len)
      return C2_ERR_IO;
  } else {
    if (len > d->cap - d->len)
      return C2_ERR_NOMEM;
    memcpy(d->buf + d->len, data, len);
  }
  d->len += len;
  if (d->hash != NULL &&
      d->be->sha256_update(d->be_ctx, d->hash, data, len) != 0)
    return C2_ERR_CRYPTO;
  return C2_OK;
}

c2_status c2_agent_put_file(c2_agent_session *s, c2_memfile *mem,
                            const char *name, const char *dest,
                            const char *checksum, char *got_hex, size_t got_cap,
                            char *err, int err_cap) {
  if (s == NULL || name == NULL || name[0] == '\0' || dest == NULL ||
      dest[0] == '\0') {
    set_err(err, err_cap, "invalid argument");
    return C2_ERR_ARG;
  }
  if (checksum == NULL)
    checksum = "";
  if (got_hex != NULL && got_cap > 0)
    got_hex[0] = '\0';

  const c2_crypto_backend *be = s->be;
  void *be_ctx = be != NULL ? be->ctx : NULL;
  int want_hash = checksum[0] != '\0' || (got_hex != NULL && got_cap > 0);
  put_sink sink = {0};
  sink.be = be;
  sink.be_ctx = be_ctx;

  if (want_hash) {
    if (be == NULL || be->sha256_new == NULL || be->sha256_update == NULL ||
        be->sha256_final == NULL) {
      set_err(err, err_cap, "sha256 unavailable");
      return C2_ERR_UNSUPPORTED;
    }
    sink.hash = be->sha256_new(be_ctx);
    if (sink.hash == NULL) {
      set_err(err, err_cap, "sha256 unavailable");
      return C2_ERR_NOMEM;
    }
  }

  int mem_dest = c2_memfile_is_path(dest);
  char part[PATH_MAX];
  part[0] = '\0';

  if (mem_dest) {
    sink.cap = C2_PUT_MEM_MAX;
    sink.buf = (uint8_t *)malloc(sink.cap);
    if (sink.buf == NULL) {
      hash_abort(be, be_ctx, sink.hash);
      set_err(err, err_cap, "out of memory");
      return C2_ERR_NOMEM;
    }
  } else {
    if (ensure_parent_dirs(dest) != C2_OK) {
      hash_abort(be, be_ctx, sink.hash);
      set_err(err, err_cap, "cannot create destination directory");
      return C2_ERR_IO;
    }
    int n = snprintf(part, sizeof(part), "%s.part", dest);
    if (n < 0 || (size_t)n >= sizeof(part)) {
      hash_abort(be, be_ctx, sink.hash);
      set_err(err, err_cap, "destination path too long");
      return C2_ERR_ARG;
    }
    sink.f = fopen(part, "wb");
    if (sink.f == NULL) {
      hash_abort(be, be_ctx, sink.hash);
      set_err(err, err_cap, "cannot create destination file");
      return C2_ERR_IO;
    }
  }

  c2_status st = c2_session_download_stream(s, c2_str_of(name, strlen(name)),
                                            put_sink_write, &sink);

  uint8_t digest[C2_SHA256_BYTES];
  int have_digest = 0;
  if (sink.hash != NULL) {
    have_digest = be->sha256_final(be_ctx, sink.hash, digest) == 0;
    sink.hash = NULL;
  }
  if (sink.f != NULL) {
    int ioerr = ferror(sink.f);
    if (fclose(sink.f) != 0 || ioerr)
      st = C2_ERR_IO;
    sink.f = NULL;
  }

  char got[C2_SHA256_BYTES * 2 + 1];
  got[0] = '\0';
  if (have_digest) {
    c2_hex_encode(digest, sizeof(digest), got);
    got[sizeof(digest) * 2] = '\0';
  }

  if (st == C2_OK && sink.len == 0) {
    st = C2_ERR_PROTO;
    set_err(err, err_cap, "the C2 served no data");
  }
  if (st == C2_OK && checksum[0] != '\0' &&
      (!have_digest || !c2_str_eq_ci(got, checksum))) {
    st = C2_ERR_CRYPTO;
    set_err(err, err_cap, "checksum mismatch");
  }

  if (st == C2_OK) {
    if (mem_dest) {
      char key[PATH_MAX];
      size_t key_len = c2_memfile_path_key(dest, key, sizeof(key));
      if (key_len == 0) {
        st = C2_ERR_ARG;
      } else {
        st = c2_memfile_write(mem, c2_str_of(key, key_len), sink.buf, sink.len);
      }
    } else if (rename(part, dest) != 0) {
      st = C2_ERR_IO;
    }
  }

  if (st != C2_OK) {
    if (!mem_dest && part[0] != '\0')
      (void)remove(part);
    free(sink.buf);
    if (err != NULL && err_cap > 0 && err[0] == '\0')
      set_err(err, err_cap,
              st == C2_ERR_IO ? "cannot write destination" : c2_status_str(st));
    return st;
  }

  if (got_hex != NULL && got_cap > 0)
    snprintf(got_hex, got_cap, "%s", got);
  free(sink.buf);
  return C2_OK;
}
