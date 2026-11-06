/*
 * rvvmrun — run an RV32 BOF guest through rvvm.c as a normal process.
 *
 * The interpreter is linked in directly instead of being mapped as the
 * rvvm_linux module, so a debugger sees the loader, the guest memory bus and
 * the syscall gate in one address space:
 *
 *   gdb --args rvvmrun guest.rv
 *   (gdb) break rv_guest_syscall
 *   (gdb) break rv_run_state
 *
 * A guest image is a static RV32 musl executable: a BOF object linked with the
 * guest entry shim and the guest linker script. `rvvmrun build` produces one
 * from the same objects the C2 links, keeping the symbol table so a guest trap
 * is reported as a function name instead of a bare address.
 *
 * Usage:
 *
 *   rvvmrun [options] <image.rv> [BOF argument ...]
 *   rvvmrun build -o <image.rv> <payload.rv.o|library.a> ...
 *
 * BOF arguments use the C2 wire format: `z:string`, `i:int32`, `s:int16`,
 * `b:hexbytes`, `Z:wide-string`. A bare argument is a string, so
 * `rvvmrun cat.rv /etc/hostname` packs the same block as
 * `rvvmrun cat.rv z:/etc/hostname`.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "rvvm_abi.h"

extern char *Run(const uint8_t *image, size_t len,
                 const struct rv_bof_args *args);
extern const char *LastError(void);
extern int ExitCode(void);
extern void Free(char *out);
#ifdef RV_TRACE
extern void SetTrace(FILE *out);
#endif

/* The interpreter rejects a larger argument block and the agent never sends
 * one; stopping here keeps a stray argument list from allocating without
 * bound. */
#define MAX_ARG_BLOCK (1u << 20)
#define MAX_ENV_ENTRIES 256
#define MAX_ENV_BLOCK (1u << 20)
/* The guest arena is 64 MiB; a larger image cannot be mapped. Refuse it here
 * instead of allocating an arbitrary file in the debugger. */
#define MAX_IMAGE_BYTES (64u << 20)

/* Guest image build defaults. The Makefile points these at the guest entry
 * shim and linker script the C2 embeds. */
#ifndef RV_GUEST_SHIM
#define RV_GUEST_SHIM ""
#endif
#ifndef RV_GUEST_LD
#define RV_GUEST_LD ""
#endif

/* ---- ELF32 helpers ------------------------------------------------------- */

#define ELF_EHDR_SIZE 52u
#define ELF_SHDR_SIZE 40u
#define ELF_SYM_SIZE 16u
#define ELF_PT_LOAD 1u
#define ELF_SHT_SYMTAB 2u
#define ELF_STT_FUNC 2u

typedef struct {
  const uint8_t *img;
  size_t len;
  uint32_t shoff;
  uint16_t shent;
  uint16_t shnum;
  uint16_t shstrndx;
  const uint8_t *shstr;
  uint32_t shstr_size;
} elf_view;

static uint16_t le16(const uint8_t *p) {
  return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static void wr32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static int in_image(size_t off, size_t n, size_t total) {
  return off <= total && n <= total - off;
}

static int elf_view_open(elf_view *v, const uint8_t *img, size_t len) {
  memset(v, 0, sizeof(*v));
  if (len < ELF_EHDR_SIZE || memcmp(img, "\177ELF", 4) != 0 || img[4] != 1 ||
      img[5] != 1)
    return 0;
  v->img = img;
  v->len = len;
  v->shoff = le32(img + 32);
  v->shent = le16(img + 46);
  v->shnum = le16(img + 48);
  v->shstrndx = le16(img + 50);
  if (v->shent < ELF_SHDR_SIZE || v->shnum == 0 ||
      !in_image(v->shoff, (size_t)v->shnum * v->shent, len))
    return 0;
  if (v->shstrndx >= v->shnum)
    return 1; /* no section-name table; address and program headers remain */
  const uint8_t *sh = img + v->shoff + (size_t)v->shstrndx * v->shent;
  uint32_t off = le32(sh + 16);
  uint32_t size = le32(sh + 20);
  if (!in_image(off, size, len))
    return 1;
  v->shstr = img + off;
  v->shstr_size = size;
  return 1;
}

static const uint8_t *elf_shdr(const elf_view *v, uint16_t i) {
  if (i >= v->shnum)
    return NULL;
  size_t off = v->shoff + (size_t)i * v->shent;
  if (!in_image(off, v->shent, v->len))
    return NULL;
  return v->img + off;
}

static const char *elf_sec_name(const elf_view *v, const uint8_t *sh) {
  if (v->shstr == NULL)
    return "";
  uint32_t name = le32(sh);
  if (name >= v->shstr_size)
    return "";
  const char *s = (const char *)(v->shstr + name);
  if (memchr(s, '\0', v->shstr_size - name) == NULL)
    return "";
  return s;
}

/* Locate a section by name; returns its file image and, when asked, its
 * guest address. */
static const uint8_t *elf_section(const elf_view *v, const char *name,
                                  uint32_t *addr, uint32_t *size) {
  for (uint16_t i = 0; i < v->shnum; i++) {
    const uint8_t *sh = elf_shdr(v, i);
    if (sh == NULL || strcmp(elf_sec_name(v, sh), name) != 0)
      continue;
    uint32_t off = le32(sh + 16);
    uint32_t len = le32(sh + 20);
    if (!in_image(off, len, v->len))
      return NULL;
    if (addr != NULL)
      *addr = le32(sh + 12);
    if (size != NULL)
      *size = len;
    return v->img + off;
  }
  return NULL;
}

/* Name the function that contains `pc`. The build mode keeps the symbol
 * table so a trapped guest is identified by name. */
static int elf_function_at(const elf_view *v, uint32_t pc, const char **name,
                           uint32_t *off) {
  uint32_t best = 0;
  uint32_t best_off = 0;
  const char *best_name = NULL;
  for (uint16_t i = 0; i < v->shnum; i++) {
    const uint8_t *sh = elf_shdr(v, i);
    if (sh == NULL || le32(sh + 4) != ELF_SHT_SYMTAB)
      continue;
    uint32_t symoff = le32(sh + 16);
    uint32_t symsize = le32(sh + 20);
    uint32_t link = le32(sh + 24);
    uint32_t entsz = le32(sh + 36);
    if (entsz < ELF_SYM_SIZE || !in_image(symoff, symsize, v->len) ||
        (size_t)link >= v->shnum)
      continue;
    const uint8_t *strsh = elf_shdr(v, (uint16_t)link);
    if (strsh == NULL)
      continue;
    uint32_t stroff = le32(strsh + 16);
    uint32_t strsize = le32(strsh + 20);
    if (!in_image(stroff, strsize, v->len))
      continue;
    const char *strtab = (const char *)(v->img + stroff);
    uint32_t count = symsize / entsz;
    for (uint32_t s = 0; s < count; s++) {
      const uint8_t *sym = v->img + symoff + (size_t)s * entsz;
      uint32_t value = le32(sym + 4);
      uint32_t size = le32(sym + 8);
      uint8_t info = sym[12];
      uint16_t shndx = le16(sym + 14);
      uint32_t nameoff = le32(sym);
      if ((info & 0xfu) != ELF_STT_FUNC || shndx == 0 || nameoff >= strsize)
        continue;
      if (size != 0 ? (pc < value || pc - value >= size) : pc < value)
        continue;
      if (best_name != NULL && value <= best)
        continue;
      const char *candidate = strtab + nameoff;
      if (memchr(candidate, '\0', strsize - nameoff) == NULL)
        continue;
      best = value;
      best_off = pc - value;
      best_name = candidate;
    }
  }
  if (best_name == NULL)
    return -1;
  *name = best_name;
  *off = best_off;
  return 0;
}

static void describe_pc(const elf_view *v, uint32_t pc, const char *prefix) {
  const char *name = NULL;
  uint32_t off = 0;
  if (elf_function_at(v, pc, &name, &off) == 0)
    fprintf(stderr, "rvvmrun: %s0x%08x is %s+0x%x\n", prefix, pc, name, off);
  else
    fprintf(stderr, "rvvmrun: %s0x%08x has no symbol\n", prefix, pc);
}

/* ---- growable byte buffer ------------------------------------------------ */

typedef struct {
  uint8_t *buf;
  size_t len;
  size_t cap;
} bytes;

static void bytes_free(bytes *b) {
  free(b->buf);
  b->buf = NULL;
  b->len = 0;
  b->cap = 0;
}

static int bytes_reserve(bytes *b, size_t extra) {
  if (extra <= b->cap - b->len)
    return 0;
  size_t cap = b->cap != 0 ? b->cap : 256u;
  size_t need = b->len + extra;
  if (need < b->len)
    return -1;
  while (cap < need) {
    if (cap > (size_t)-1 / 2)
      return -1;
    cap <<= 1;
  }
  uint8_t *p = (uint8_t *)realloc(b->buf, cap);
  if (p == NULL)
    return -1;
  b->buf = p;
  b->cap = cap;
  return 0;
}

static int bytes_put(bytes *b, const void *data, size_t len) {
  if (bytes_reserve(b, len) != 0)
    return -1;
  if (len != 0)
    memcpy(b->buf + b->len, data, len);
  b->len += len;
  return 0;
}

static int bytes_u16(bytes *b, uint16_t v) {
  uint8_t t[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
  return bytes_put(b, t, sizeof(t));
}

static int bytes_u32(bytes *b, uint32_t v) {
  uint8_t t[4];
  wr32(t, v);
  return bytes_put(b, t, sizeof(t));
}

/* ---- BOF argument packing ------------------------------------------------ */

/* UTF-8 to UTF-16LE with the 2-byte terminator, matching the C2 and
 * c2_bof_pack_args. */
static int utf8_to_utf16le(const char *s, size_t len, bytes *out) {
  size_t i = 0;
  while (i < len) {
    unsigned char c = (unsigned char)s[i];
    uint32_t cp;
    int n;
    if (c < 0x80) {
      cp = c;
      n = 1;
    } else if ((c & 0xE0) == 0xC0) {
      cp = c & 0x1Fu;
      n = 2;
    } else if ((c & 0xF0) == 0xE0) {
      cp = c & 0x0Fu;
      n = 3;
    } else if ((c & 0xF8) == 0xF0) {
      cp = c & 0x07u;
      n = 4;
    } else {
      return -1;
    }
    if (i + (size_t)n > len)
      return -1;
    for (int k = 1; k < n; k++) {
      if (((unsigned char)s[i + (size_t)k] & 0xC0) != 0x80)
        return -1;
      cp = (cp << 6) | ((unsigned char)s[i + (size_t)k] & 0x3Fu);
    }
    i += (size_t)n;
    if (cp <= 0xFFFF) {
      if (bytes_u16(out, (uint16_t)cp) != 0)
        return -1;
    } else {
      cp -= 0x10000;
      uint16_t hi = (uint16_t)(0xD800u + (cp >> 10));
      uint16_t lo = (uint16_t)(0xDC00u + (cp & 0x3FFu));
      if (bytes_u16(out, hi) != 0 || bytes_u16(out, lo) != 0)
        return -1;
    }
  }
  return bytes_u16(out, 0);
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int parse_int(const char *s, long long lo, long long hi,
                     long long *out) {
  char *end = NULL;
  errno = 0;
  long long v = strtoll(s, &end, 10);
  if (errno != 0 || end == s || *end != '\0' || v < lo || v > hi)
    return -1;
  *out = v;
  return 0;
}

/* Append one argument to the wire body. A token is `type:value` when the
 * first character names a type and the second is ':'; anything else is a
 * string. */
static int pack_arg(bytes *body, const char *arg) {
  char kind = 'z';
  const char *val = arg;
  if (arg[0] != '\0' && arg[1] == ':' && strchr("iszZb", arg[0]) != NULL) {
    kind = arg[0];
    val = arg + 2;
  }
  switch (kind) {
  case 'z': {
    size_t n = strlen(val) + 1;
    if (bytes_u32(body, (uint32_t)n) != 0)
      return -1;
    return bytes_put(body, val, n);
  }
  case 'i': {
    long long v;
    if (parse_int(val, -2147483648LL, 4294967295LL, &v) != 0)
      return -1;
    return bytes_u32(body, (uint32_t)v);
  }
  case 's': {
    long long v;
    if (parse_int(val, -32768LL, 65535LL, &v) != 0)
      return -1;
    return bytes_u16(body, (uint16_t)v);
  }
  case 'b': {
    size_t n = strlen(val);
    if (n % 2 != 0)
      return -1;
    n /= 2;
    if (n > MAX_ARG_BLOCK || bytes_reserve(body, 4u + n) != 0)
      return -1;
    uint8_t *dst = body->buf + body->len;
    wr32(dst, (uint32_t)n);
    for (size_t i = 0; i < n; i++) {
      int hi = hex_value(val[i * 2]);
      int lo = hex_value(val[i * 2 + 1]);
      if (hi < 0 || lo < 0)
        return -1;
      dst[4 + i] = (uint8_t)((hi << 4) | lo);
    }
    body->len += 4u + n;
    return 0;
  }
  case 'Z': {
    bytes wide = {0};
    int rc = -1;
    if (utf8_to_utf16le(val, strlen(val), &wide) == 0 &&
        bytes_u32(body, (uint32_t)wide.len) == 0 &&
        bytes_put(body, wide.buf, wide.len) == 0)
      rc = 0;
    bytes_free(&wide);
    return rc;
  }
  default:
    return -1;
  }
}

/* Build the packed block BeaconDataParse expects: uint32 body length followed
 * by the arguments. */
static int pack_args(int argc, char **argv, bytes *out) {
  bytes body = {0};
  int rc = -1;
  for (int i = 0; i < argc; i++) {
    if (pack_arg(&body, argv[i]) != 0) {
      fprintf(stderr, "rvvmrun: bad argument %d: %s\n", i + 1, argv[i]);
      goto done;
    }
    if (body.len > MAX_ARG_BLOCK - 4) {
      fprintf(stderr, "rvvmrun: argument block exceeds %u bytes\n",
              MAX_ARG_BLOCK);
      goto done;
    }
  }
  if (bytes_u32(out, (uint32_t)body.len) != 0 ||
      bytes_put(out, body.buf, body.len) != 0) {
    fprintf(stderr, "rvvmrun: out of memory packing arguments\n");
    goto done;
  }
  rc = 0;
done:
  bytes_free(&body);
  return rc;
}

/* ---- environment --------------------------------------------------------- */

/* Add or replace KEY=VALUE in the entry list. */
static int env_set(char **entries, int *count, const char *kv) {
  const char *eq = strchr(kv, '=');
  if (eq == NULL)
    return -1;
  size_t klen = (size_t)(eq - kv) + 1; /* the key and its '=' */
  for (int i = 0; i < *count; i++) {
    if (strncmp(entries[i], kv, klen) != 0)
      continue;
    char *dup = strdup(kv);
    if (dup == NULL)
      return -1;
    free(entries[i]);
    entries[i] = dup;
    return 0;
  }
  if (*count >= MAX_ENV_ENTRIES)
    return -1;
  entries[*count] = strdup(kv);
  if (entries[*count] == NULL)
    return -1;
  (*count)++;
  return 0;
}

/* The guest sees the runner's environment, like a native BOF sees the agent's,
 * with -E overrides applied. */
static int build_env(char **extra, int nextra, bytes *out, int *count) {
  extern char **environ;
  char *entries[MAX_ENV_ENTRIES];
  int n = 0;
  for (char **e = environ; e != NULL && *e != NULL; e++) {
    if (env_set(entries, &n, *e) != 0)
      break;
  }
  for (int i = 0; i < nextra; i++) {
    if (env_set(entries, &n, extra[i]) != 0) {
      fprintf(stderr, "rvvmrun: bad environment entry: %s\n", extra[i]);
      goto fail;
    }
  }
  for (int i = 0; i < n; i++) {
    size_t len = strlen(entries[i]) + 1;
    if (out->len + len > MAX_ENV_BLOCK) {
      fprintf(stderr, "rvvmrun: environment exceeds %u bytes\n", MAX_ENV_BLOCK);
      goto fail;
    }
    if (bytes_put(out, entries[i], len) != 0)
      goto fail;
  }
  *count = n;
  for (int i = 0; i < n; i++)
    free(entries[i]);
  return 0;
fail:
  for (int i = 0; i < n; i++)
    free(entries[i]);
  return -1;
}

/* ---- image and diagnostics ----------------------------------------------- */

static uint8_t *read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    fprintf(stderr, "rvvmrun: %s: %s\n", path, strerror(errno));
    return NULL;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fprintf(stderr, "rvvmrun: %s: %s\n", path, strerror(errno));
    fclose(f);
    return NULL;
  }
  long n = ftell(f);
  if (n <= 0 || fseek(f, 0, SEEK_SET) != 0) {
    fprintf(stderr, "rvvmrun: %s: empty image\n", path);
    fclose(f);
    return NULL;
  }
  if ((size_t)n > MAX_IMAGE_BYTES) {
    fprintf(stderr, "rvvmrun: %s: image exceeds %u bytes\n", path,
            MAX_IMAGE_BYTES);
    fclose(f);
    return NULL;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)n);
  if (buf == NULL) {
    fprintf(stderr, "rvvmrun: %s: out of memory\n", path);
    fclose(f);
    return NULL;
  }
  if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
    fprintf(stderr, "rvvmrun: %s: short read\n", path);
    free(buf);
    fclose(f);
    return NULL;
  }
  fclose(f);
  *len = (size_t)n;
  return buf;
}

static void dump_image(const elf_view *v, const char *path, size_t len) {
  const uint8_t *img = v->img;
  uint32_t entry = le32(img + 24);
  uint32_t phoff = le32(img + 28);
  uint16_t phent = le16(img + 42);
  uint16_t phnum = le16(img + 44);
  const char *name = NULL;
  uint32_t off = 0;

  fprintf(stderr, "image: %s (%zu bytes)\n", path, len);
  fprintf(stderr, "  entry: 0x%08x", entry);
  if (elf_function_at(v, entry, &name, &off) == 0)
    fprintf(stderr, " (%s+0x%x)", name, off);
  fprintf(stderr, "\n");

  uint32_t hdr_addr = 0;
  uint32_t hdr_size = 0;
  if (elf_section(v, ".rvhdr", &hdr_addr, &hdr_size) != NULL)
    fprintf(stderr, "  .rvhdr: 0x%08x (%u bytes)\n", hdr_addr, hdr_size);
  else
    fprintf(stderr, "  .rvhdr: none (guest starts without a BOF entry shim)\n");

  if (phnum == 0 || phent < 32 ||
      !in_image(phoff, (size_t)phnum * phent, len)) {
    fprintf(stderr, "  program headers: unreadable\n");
    return;
  }
  fprintf(stderr, "  program headers: %u\n", phnum);
  for (uint16_t i = 0; i < phnum; i++) {
    const uint8_t *ph = img + phoff + (size_t)i * phent;
    if (le32(ph) != ELF_PT_LOAD)
      continue;
    fprintf(stderr, "    PT_LOAD vaddr=0x%08x filesz=%u memsz=%u\n",
            le32(ph + 8), le32(ph + 16), le32(ph + 20));
  }
}

static void dump_hex(FILE *out, const uint8_t *p, size_t n) {
  for (size_t i = 0; i < n; i++)
    fprintf(out, "%02x", p[i]);
}

static void usage(FILE *out) {
  fprintf(out,
          "usage: rvvmrun [options] <image.rv> [BOF argument ...]\n"
          "       rvvmrun build -o <image.rv> <payload.rv.o|library.a> ...\n"
          "\n"
          "Run an RV32 BOF guest in the rvvm interpreter.\n"
          "\n"
          "run options:\n"
          "  -v, --verbose        print image layout, argument block and\n"
          "                       guest exit status\n"
          "  -t, --trace          trace guest syscalls to stderr\n"
          "  -E, --env KEY=VALUE  set or replace one guest environment\n"
          "                       entry; repeatable\n"
          "  -h, --help           show this help\n"
          "\n"
          "build options:\n"
          "  -o, --output PATH    guest image to write (required)\n"
          "  -g, --debug          link with -O Debug instead of ReleaseSmall\n"
          "      --zig PATH       zig binary (default: $ZIG or zig)\n"
          "      --shim PATH      guest entry shim source\n"
          "      --ld PATH        guest linker script\n"
          "  -v, --verbose        print the linker command line\n"
          "\n"
          "BOF arguments: z:string (default), i:int32, s:int16, b:hexbytes,\n"
          "Z:wide-string.\n");
}

/* ---- run mode ------------------------------------------------------------ */

static int cmd_run(int argc, char **argv) {
  static const struct option opts[] = {
      {"verbose", no_argument, NULL, 'v'},
      {"trace", no_argument, NULL, 't'},
      {"env", required_argument, NULL, 'E'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0},
  };
  int verbose = 0;
  int trace = 0;
  char *env_extra[MAX_ENV_ENTRIES];
  int env_nextra = 0;

  int c;
  while ((c = getopt_long(argc, argv, "vtE:h", opts, NULL)) != -1) {
    switch (c) {
    case 'v':
      verbose = 1;
      break;
    case 't':
      trace = 1;
      break;
    case 'E':
      if (env_nextra >= MAX_ENV_ENTRIES) {
        fprintf(stderr, "rvvmrun: too many environment entries\n");
        return 2;
      }
      env_extra[env_nextra++] = optarg;
      break;
    case 'h':
      usage(stdout);
      return 0;
    default:
      usage(stderr);
      return 2;
    }
  }
  if (optind >= argc) {
    usage(stderr);
    return 2;
  }

  const char *image_path = argv[optind];
  char **bof_argv = argv + optind + 1;
  int bof_argc = argc - optind - 1;

  size_t image_len = 0;
  uint8_t *image = read_file(image_path, &image_len);
  if (image == NULL)
    return 1;

  elf_view view;
  int have_view = elf_view_open(&view, image, image_len);
  if (verbose && have_view)
    dump_image(&view, image_path, image_len);

  bytes wire = {0};
  bytes env = {0};
  int env_count = 0;
  int status = 2;
  if (pack_args(bof_argc, bof_argv, &wire) != 0)
    goto out;
  if (build_env(env_extra, env_nextra, &env, &env_count) != 0)
    goto out;

  if (verbose) {
    fprintf(stderr, "  arguments: %d, block %zu bytes", bof_argc, wire.len);
    if (wire.len <= 32) {
      fprintf(stderr, " (");
      dump_hex(stderr, wire.buf, wire.len);
      fprintf(stderr, ")");
    }
    fprintf(stderr, "\n  environment: %d entries, %zu bytes\n", env_count,
            env.len);
  }

  struct rv_bof_args args;
  args.buf = wire.buf;
  args.len = wire.len;
  args.env = env.len != 0 ? env.buf : NULL;
  args.env_len = env.len;

#ifdef RV_TRACE
  if (trace)
    SetTrace(stderr);
#else
  if (trace)
    fprintf(stderr, "rvvmrun: built without RV_TRACE, no syscall trace\n");
#endif

  char *guest_out = Run(image, image_len, &args);
  if (guest_out == NULL) {
    const char *err = LastError();
    fprintf(stderr, "rvvmrun: %s\n", err[0] != '\0' ? err : "guest run failed");
    /* Report the trap PC as a function when one is named in the error. */
    const char *at = strstr(err, " at 0x");
    if (have_view && at != NULL && at[6] != '\0')
      describe_pc(&view, (uint32_t)strtoul(at + 6, NULL, 16), "");
    status = 125;
    goto out;
  }

  size_t out_len = strlen(guest_out);
  if (out_len != 0 && fwrite(guest_out, 1, out_len, stdout) != out_len) {
    fprintf(stderr, "rvvmrun: writing guest output: %s\n", strerror(errno));
    Free(guest_out);
    status = 1;
    goto out;
  }
  int guest_status = ExitCode();
  Free(guest_out);
  if (verbose)
    fprintf(stderr, "rvvmrun: %zu output bytes, guest exit status %d\n",
            out_len, guest_status);
  /* Mirror the guest's exit status; a status whose low byte is zero but that
   * is not a clean exit still has to look like a failure to a shell. */
  if (guest_status == 0) {
    status = 0;
  } else {
    status = guest_status & 0xff;
    if (status == 0)
      status = 1;
  }
out:
  bytes_free(&wire);
  bytes_free(&env);
  free(image);
  return status;
}

/* ---- build mode ---------------------------------------------------------- */

/* Resolve a path from the environment, falling back to the built-in default. */
static const char *resolve_path(const char *env_name, const char *fallback) {
  const char *env_value = getenv(env_name);
  if (env_value != NULL && env_value[0] != '\0')
    return env_value;
  return fallback;
}

static int run_linker(char **cmd, int verbose) {
  if (verbose) {
    fprintf(stderr, "rvvmrun:");
    for (char **p = cmd; *p != NULL; p++)
      fprintf(stderr, " %s", *p);
    fprintf(stderr, "\n");
  }
  pid_t pid = fork();
  if (pid < 0) {
    fprintf(stderr, "rvvmrun: fork: %s\n", strerror(errno));
    return 1;
  }
  if (pid == 0) {
    execvp(cmd[0], cmd);
    fprintf(stderr, "rvvmrun: %s: %s\n", cmd[0], strerror(errno));
    _exit(127);
  }
  int wstatus = 0;
  if (waitpid(pid, &wstatus, 0) < 0) {
    fprintf(stderr, "rvvmrun: waitpid: %s\n", strerror(errno));
    return 1;
  }
  if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0)
    return 0;
  if (WIFSIGNALED(wstatus))
    fprintf(stderr, "rvvmrun: linker killed by signal %d\n", WTERMSIG(wstatus));
  else
    fprintf(stderr, "rvvmrun: linker failed with status %d\n",
            WEXITSTATUS(wstatus));
  return 1;
}

static int cmd_build(int argc, char **argv) {
  static const struct option opts[] = {
      {"output", required_argument, NULL, 'o'},
      {"debug", no_argument, NULL, 'g'},
      {"zig", required_argument, NULL, 'z'},
      {"shim", required_argument, NULL, 's'},
      {"ld", required_argument, NULL, 'l'},
      {"verbose", no_argument, NULL, 'v'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0},
  };
  const char *output = NULL;
  const char *zig = NULL;
  const char *shim = NULL;
  const char *ld = NULL;
  int debug = 0;
  int verbose = 0;

  int c;
  while ((c = getopt_long(argc, argv, "o:gz:s:l:vh", opts, NULL)) != -1) {
    switch (c) {
    case 'o':
      output = optarg;
      break;
    case 'g':
      debug = 1;
      break;
    case 'z':
      zig = optarg;
      break;
    case 's':
      shim = optarg;
      break;
    case 'l':
      ld = optarg;
      break;
    case 'v':
      verbose = 1;
      break;
    case 'h':
      usage(stdout);
      return 0;
    default:
      usage(stderr);
      return 2;
    }
  }
  if (output == NULL || optind >= argc) {
    usage(stderr);
    return 2;
  }

  if (zig == NULL)
    zig = resolve_path("ZIG", "zig");
  if (shim == NULL)
    shim = resolve_path("RVVM_GUEST_SHIM", RV_GUEST_SHIM);
  if (ld == NULL)
    ld = resolve_path("RVVM_GUEST_LD", RV_GUEST_LD);
  if (shim[0] == '\0' || ld[0] == '\0') {
    fprintf(stderr,
            "rvvmrun: guest shim and linker script are unknown; pass --shim "
            "and --ld\n");
    return 2;
  }

  int inputs = argc - optind;
  /* Fixed linker arguments, the inputs, -femit-bin, and a NULL terminator. */
  size_t cap = (size_t)inputs + 16;
  char **cmd = (char **)calloc(cap, sizeof(*cmd));
  char *emit = (char *)malloc(strlen(output) + 16);
  if (cmd == NULL || emit == NULL) {
    fprintf(stderr, "rvvmrun: out of memory\n");
    free(cmd);
    free(emit);
    return 1;
  }
  snprintf(emit, strlen(output) + 16, "-femit-bin=%s", output);

  size_t i = 0;
  cmd[i++] = (char *)zig;
  cmd[i++] = "build-exe";
  cmd[i++] = "-target";
  cmd[i++] = "riscv32-linux-musl";
  cmd[i++] = "-mcpu=generic_rv32+a";
  cmd[i++] = "-static";
  cmd[i++] = "-O";
  cmd[i++] = debug ? "Debug" : "ReleaseSmall";
  cmd[i++] = "-fno-entry";
  /* Keep the symbol table so a trapped guest is named, not just addressed. */
  cmd[i++] = "-fno-strip";
  cmd[i++] = "-lc";
  cmd[i++] = "-T";
  cmd[i++] = (char *)ld;
  cmd[i++] = (char *)shim;
  for (int k = optind; k < argc; k++)
    cmd[i++] = argv[k];
  cmd[i++] = emit;
  cmd[i] = NULL;

  int status = run_linker(cmd, verbose);
  free(emit);
  free(cmd);
  return status;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "build") == 0)
    return cmd_build(argc - 1, argv + 1);
  return cmd_run(argc, argv);
}
