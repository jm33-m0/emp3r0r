#include <stddef.h>
#include <stdint.h>

#include "util/dynload.h"
#include "util/strings.h"
#include "util/utils.h"

/* ---- minimal ELF layout (no elf.h) ----
 *
 * Tables are read field-by-field from raw bytes rather than through a struct
 * pointer: an ELF offset is attacker-controlled and need not be aligned, and a
 * misaligned struct access is undefined behaviour. */
#define ELF64_EHDR_SIZE 64
#define ELF64_PHDR_SIZE 56
#define ELF64_DYN_SIZE 16
#define ELF64_SYM_SIZE 24

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

#define PT_LOAD_TYPE 1
#define PT_DYNAMIC_TYPE 2
#define DT_NULL 0
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_GNU_HASH 0x6ffffef5

#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EV_CURRENT 1

/* Defensive caps. Real modules are far below these; they only stop a corrupt
 * header from driving an unbounded walk. */
#define DYNLOAD_MAX_PHNUM 1024
#define DYNLOAD_MAX_SEGS 64

/* The primary symbol set follows DYNLOAD_MODE; the _ALT set is the other one,
 * used only by DYNLOAD_MODE_AUTO as a fallback. */
#if DYNLOAD_MODE == DYNLOAD_MODE_PUBLIC
#define DYNLOAD_SYM_DLOPEN "dlopen"
#define DYNLOAD_SYM_DLSYM "dlsym"
#define DYNLOAD_SYM_DLCLOSE "dlclose"
#define DYNLOAD_SYM_DLOPEN_ALT "__libc_dlopen_mode"
#define DYNLOAD_SYM_DLSYM_ALT "__libc_dlsym"
#define DYNLOAD_SYM_DLCLOSE_ALT "__libc_dlclose"
#else /* libc_dl and auto try the glibc-internal names first */
#define DYNLOAD_SYM_DLOPEN "__libc_dlopen_mode"
#define DYNLOAD_SYM_DLSYM "__libc_dlsym"
#define DYNLOAD_SYM_DLCLOSE "__libc_dlclose"
#define DYNLOAD_SYM_DLOPEN_ALT "dlopen"
#define DYNLOAD_SYM_DLSYM_ALT "dlsym"
#define DYNLOAD_SYM_DLCLOSE_ALT "dlclose"
#endif

/* ------------------------------------------------------------------------- */
/* Bounds-checked view of a mapped module                                      */
/* ------------------------------------------------------------------------- */

typedef struct {
  const uint8_t *base;
  size_t len; /* readable bytes starting at base */
} Mod;

static int mod_has(const Mod *m, const void *p, size_t n) {
  const uint8_t *bp = (const uint8_t *)p;
  if (bp < m->base)
    return 0;
  size_t off = (size_t)(bp - m->base);
  return off <= m->len && n <= m->len - off;
}

static const void *mod_at(const Mod *m, unsigned long off, size_t n) {
  if ((unsigned long)off > (unsigned long)m->len)
    return NULL;
  size_t o = (size_t)off;
  if (n > m->len - o)
    return NULL;
  return m->base + o;
}

/*
 * Resolve a DT_* pointer. In a loaded module the loader has already relocated
 * it to an absolute runtime address; in a flat in-memory image it is a base-
 * relative offset. Accept either, reject anything outside the module.
 */
static const void *mod_abs(const Mod *m, unsigned long v) {
  const void *p = (const void *)(uintptr_t)v;
  if (mod_has(m, p, 1))
    return p;
  return mod_at(m, v, 1);
}

/* A PT_LOAD segment, used to keep every read inside mapped memory (a module's
 * address span can contain unmapped gaps between segments). */
typedef struct {
  const uint8_t *p;
  size_t len;
} Seg;

static int seg_has(const Seg *segs, int nsegs, const void *p, size_t len) {
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

/* Bytes available at `p` up to the end of its containing segment, or 0. */
static size_t seg_avail(const Seg *segs, int nsegs, const void *p) {
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

/* Compare a NUL-terminated name at `s` (bounded by `max`) against `name`.
 * Never reads past s[max]; a name without a terminator within bounds fails. */
static int name_eq(const uint8_t *s, size_t max, const char *name) {
  for (size_t i = 0; i < max; i++) {
    unsigned char c = s[i];
    if (c != (unsigned char)name[i])
      return 0;
    if (c == 0)
      return 1;
  }
  return 0;
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static uint32_t rd32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
  return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

/* A program header, copied out of the (possibly unaligned) table. */
typedef struct {
  uint32_t p_type;
  unsigned long p_vaddr;
  unsigned long p_filesz;
  unsigned long p_memsz;
} PhdrInfo;

static int phdr_read(const Mod *m, size_t off, PhdrInfo *out) {
  if (off > m->len || ELF64_PHDR_SIZE > m->len - off)
    return 0;
  const uint8_t *p = m->base + off;
  out->p_type = rd32(p);
  out->p_vaddr = rd64(p + 16);
  out->p_filesz = rd64(p + 32);
  out->p_memsz = rd64(p + 40);
  return 1;
}

/* A DT_ entry, copied out of the (possibly unaligned) dynamic array. */
typedef struct {
  long d_tag;
  unsigned long d_val;
} DynInfo;

static int dyn_read(const Mod *m, size_t off, DynInfo *out) {
  if (off > m->len || ELF64_DYN_SIZE > m->len - off)
    return 0;
  const uint8_t *p = m->base + off;
  out->d_tag = (long)rd64(p);
  out->d_val = rd64(p + 8);
  return 1;
}

/* A dynamic symbol, copied out of the (possibly unaligned) symbol table. */
typedef struct {
  uint32_t st_name;
  uint16_t st_shndx;
  unsigned long st_value;
} SymInfo;

static int sym_read(const Mod *m, size_t sym_off, size_t idx, SymInfo *out) {
  if (sym_off > m->len)
    return 0;
  size_t avail = m->len - sym_off;
  if (idx >= avail / ELF64_SYM_SIZE)
    return 0;
  const uint8_t *p = m->base + sym_off + idx * ELF64_SYM_SIZE;
  out->st_name = rd32(p);
  out->st_shndx = (uint16_t)(p[6] | (p[7] << 8));
  out->st_value = rd64(p + 8);
  return 1;
}

/* ------------------------------------------------------------------------- */
/* /proc/self/maps parsing                                                     */
/* ------------------------------------------------------------------------- */

/* Parse a leading hex number (start address of a /proc/self/maps line). */
static unsigned long parse_hex(const char *s) {
  unsigned long v = 0;
  for (;; s++) {
    char c = *s;
    unsigned long d;
    if (c >= '0' && c <= '9')
      d = (unsigned long)(c - '0');
    else if (c >= 'a' && c <= 'f')
      d = (unsigned long)(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F')
      d = (unsigned long)(c - 'A' + 10);
    else
      break;
    if (v > (~0UL >> 4))
      break; /* saturate instead of wrapping */
    v = (v << 4) | d;
  }
  return v;
}

/* End address (the number after '-') of a maps line. */
static unsigned long maps_line_end(const char *line) {
  const char *p = line;
  while (*p && *p != '-')
    p++;
  if (*p != '-')
    return 0;
  return parse_hex(p + 1);
}

/* Pathname of a maps line: the field after "start-end perms offset dev inode". */
static const char *maps_line_path(const char *line) {
  int spaces = 0;
  for (const char *p = line; *p; p++) {
    if (*p == ' ' && ++spaces == 5)
      return p + 1;
  }
  return NULL;
}

static void copy_str(char *dst, size_t cap, const char *src) {
  size_t i = 0;
  if (cap == 0)
    return;
  for (; src && src[i] && i + 1 < cap; i++)
    dst[i] = src[i];
  dst[i] = '\0';
}

/*
 * Streaming line reader for /proc/self/maps. Lines are read in chunks so a
 * large maps file (many threads/mappings) is handled without a fixed-size
 * whole-file buffer. A line longer than `cap` is truncated; that is fine for
 * the fixed-width fields we parse and for real library paths.
 */
typedef struct {
  int fd;
  char buf[8192];
  size_t len;
  size_t pos;
} MapsReader;

static int maps_open(MapsReader *r) {
  r->fd = open("/proc/self/maps", O_RDONLY, 0);
  r->len = 0;
  r->pos = 0;
  return r->fd >= 0;
}

static void maps_close(MapsReader *r) {
  if (r->fd >= 0)
    close(r->fd);
  r->fd = -1;
}

static int maps_line(MapsReader *r, char *out, size_t cap) {
  size_t n = 0;
  for (;;) {
    if (r->pos >= r->len) {
      long got = read(r->fd, r->buf, sizeof(r->buf));
      if (got <= 0) {
        if (n > 0) {
          out[n] = '\0';
          return 1;
        }
        return 0;
      }
      r->len = (size_t)got;
      r->pos = 0;
    }
    while (r->pos < r->len) {
      char c = r->buf[r->pos++];
      if (c == '\n') {
        out[n] = '\0';
        return 1;
      }
      if (n + 1 < cap)
        out[n++] = c;
    }
  }
}

/* Incremental /proc/self/maps scanner shared by the file-backed finders and
 * the pure, fuzzable dynload_maps_find(). Keeping both on one line machine
 * means the fuzzer exercises the same logic the stager runs. */
typedef struct {
  const char *needle;
  int found;
  int done;
  unsigned long base;
  unsigned long end;
  char want[512];
} MapsScan;

static void maps_scan_init(MapsScan *s, const char *needle) {
  s->needle = needle;
  s->found = 0;
  s->done = 0;
  s->base = 0;
  s->end = 0;
  s->want[0] = '\0';
}

static void maps_scan_line(MapsScan *s, const char *line) {
  if (s->done)
    return;
  const char *path = maps_line_path(line);
  if (!s->found) {
    if (path && *path && strstr(path, s->needle)) {
      s->base = parse_hex(line);
      s->end = maps_line_end(line);
      copy_str(s->want, sizeof(s->want), path);
      s->found = 1;
    }
  } else if (path && strcmp(path, s->want) == 0) {
    unsigned long e = maps_line_end(line);
    if (e > s->end)
      s->end = e;
  } else if (path && *path) {
    s->done = 1; /* a different module: this one's mappings have ended */
  }
}

/* Pure parser over a length-delimited /proc/self/maps buffer (the input need
 * not be NUL-terminated). Exposed for the unit test and fuzzer, which feed it
 * arbitrary text; the file-backed finders use the same maps_scan_line(). */
unsigned long dynload_maps_find(const char *text, size_t len,
                                const char *needle, unsigned long *mod_end) {
  if (text == NULL || needle == NULL)
    return 0;
  MapsScan s;
  char line[512];
  maps_scan_init(&s, needle);
  size_t n = 0;
  for (size_t i = 0; i < len && !s.done; i++) {
    char c = text[i];
    if (c == '\n') {
      line[n] = '\0';
      maps_scan_line(&s, line);
      n = 0;
    } else if (n + 1 < sizeof(line)) {
      line[n++] = c;
    }
  }
  if (!s.done && n > 0) {
    line[n] = '\0';
    maps_scan_line(&s, line);
  }
  if (s.found && mod_end)
    *mod_end = s.end;
  return s.found ? s.base : 0;
}

/* Base of the first mapping whose pathname contains `needle`, and the end of
 * that module's contiguous mapping run when `mod_end` is non-NULL. */
static unsigned long maps_find(const char *needle, unsigned long *mod_end) {
  MapsReader r;
  char line[512];
  MapsScan s;
  maps_scan_init(&s, needle);
  if (!maps_open(&r))
    return 0;
  while (!s.done && maps_line(&r, line, sizeof(line)))
    maps_scan_line(&s, line);
  maps_close(&r);
  if (s.found && mod_end)
    *mod_end = s.end;
  return s.found ? s.base : 0;
}

unsigned long dynload_find_module(const char *needle, unsigned long *end) {
  return needle ? maps_find(needle, end) : 0;
}

unsigned long dynload_find_libc(unsigned long *end) {
  unsigned long base = maps_find("libc.so", end);
  if (base == 0)
    base = maps_find("libc-", end);
  /* musl keeps libc and the dynamic loader in a single file, mapped from
   * /lib/ld-musl-<arch>.so.1 (SONAME libc.musl-<arch>.so.1). The public
   * dlopen/dlsym/dlclose are exported from that segment. */
  if (base == 0)
    base = maps_find("ld-musl", end);
  if (base == 0)
    base = maps_find("libc.musl", end);
  return base;
}

/* ------------------------------------------------------------------------- */
/* Symbol resolution                                                           */
/* ------------------------------------------------------------------------- */

static int sym_named(const Mod *m, const Seg *segs, int nsegs, size_t str_off,
                     const SymInfo *sym, const char *name) {
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
    size_t sav = seg_avail(segs, nsegs, np);
    if (sav < max)
      max = sav;
  }
  return name_eq(np, max, name);
}

static void *sym_addr(const Mod *m, const Seg *segs, int nsegs,
                      unsigned long st_value) {
  const void *a = mod_at(m, st_value, 1);
  if (a == NULL)
    return NULL;
  if (nsegs > 0 && !seg_has(segs, nsegs, a, 1))
    return NULL;
  return (void *)a;
}

#if DYNLOAD_HASH_STYLE != DYNLOAD_HASH_SYSV
/* GNU ELF string hash used by DT_GNU_HASH tables. */
static uint32_t elf_gnu_hash(const char *name) {
  uint32_t h = 5381;
  for (const unsigned char *p = (const unsigned char *)name; *p; p++)
    h = (h << 5) + h + (uint32_t)*p;
  return h;
}

/*
 * DT_GNU_HASH: nbuckets, symoffset, bloom_size, bloom_shift, bloom[],
 * buckets[], chains[]. chains[] is indexed relative to symoffset.
 */
static void *resolve_sym_gnu(const Mod *m, const Seg *segs, int nsegs,
                             size_t sym_off, size_t str_off, const uint8_t *gp,
                             const char *name) {
  if (!mod_has(m, gp, 16))
    return NULL;
  uint32_t nbuckets = rd32(gp);
  uint32_t symoffset = rd32(gp + 4);
  uint32_t bloom_size = rd32(gp + 8);
  uint32_t bloom_shift = rd32(gp + 12);
  if (nbuckets == 0 || bloom_size == 0 || bloom_shift >= 64)
    return NULL;

  size_t off_bloom = 16;
  if ((size_t)bloom_size > (SIZE_MAX - off_bloom) / sizeof(uint64_t))
    return NULL;
  size_t off_buckets = off_bloom + (size_t)bloom_size * sizeof(uint64_t);
  if ((size_t)nbuckets > (SIZE_MAX - off_buckets) / sizeof(uint32_t))
    return NULL;
  size_t off_chains = off_buckets + (size_t)nbuckets * sizeof(uint32_t);
  if (!mod_has(m, gp, off_chains))
    return NULL;
  if (nsegs > 0 && !seg_has(segs, nsegs, gp, off_chains))
    return NULL;

  const uint8_t *bloom = gp + off_bloom;
  const uint8_t *buckets = gp + off_buckets;
  const uint8_t *chains = gp + off_chains;
  size_t chain_cap =
      (m->len - (size_t)(chains - m->base)) / sizeof(uint32_t);

  uint32_t h = elf_gnu_hash(name);
  /* Widen before the bloom shift: the hash itself is 32-bit but the shift
   * amount is a 6-bit value, so a 32-bit shift would be undefined for shift
   * >= 32 (glibc computes it on a 64-bit value). */
  uint64_t hw = (uint64_t)h;
  uint64_t word =
      rd64(bloom + (size_t)((h / 64) % bloom_size) * sizeof(uint64_t));
  uint64_t mask = (1ULL << (hw % 64)) | (1ULL << ((hw >> bloom_shift) % 64));
  if ((word & mask) != mask)
    return NULL;

  uint32_t si = rd32(buckets + (size_t)(h % nbuckets) * sizeof(uint32_t));
  if (si == 0 || si < symoffset)
    return NULL;
  size_t start = (size_t)si - symoffset;
  if (start >= chain_cap)
    return NULL;

  for (size_t i = start; i < chain_cap; i++) {
    uint32_t eh = rd32(chains + i * sizeof(uint32_t));
    if ((eh | 1) == (h | 1)) {
      SymInfo sym;
      if (sym_read(m, sym_off, (size_t)symoffset + i, &sym) &&
          sym_named(m, segs, nsegs, str_off, &sym, name))
        return sym_addr(m, segs, nsegs, sym.st_value);
    }
    if (eh & 1)
      break; /* chain terminator */
  }
  return NULL;
}
#endif /* DYNLOAD_HASH_STYLE != DYNLOAD_HASH_SYSV */

void *dynload_resolve_module(const void *base, size_t len, const char *name) {
  if (base == NULL || name == NULL || len < ELF64_EHDR_SIZE)
    return NULL;

  Mod m = {(const uint8_t *)base, len};
  const uint8_t *e = m.base;
  if (e[0] != ELFMAG0 || e[1] != ELFMAG1 || e[2] != ELFMAG2 || e[3] != ELFMAG3)
    return NULL;
  if (e[EI_CLASS] != ELFCLASS64 || e[EI_DATA] != ELFDATA2LSB ||
      e[EI_VERSION] != EV_CURRENT)
    return NULL;
  unsigned long phoff = rd64(e + 32);
  uint16_t phentsize = rd16(e + 54);
  uint16_t phnum = rd16(e + 56);
  if (phentsize != ELF64_PHDR_SIZE)
    return NULL;
  if (phnum == 0 || phnum > DYNLOAD_MAX_PHNUM)
    return NULL;

  Seg segs[DYNLOAD_MAX_SEGS];
  int nsegs = 0;
  size_t dyn_off = 0;
  size_t dyn_bytes = 0;
  int have_dyn = 0;
  for (unsigned i = 0; i < (unsigned)phnum; i++) {
    PhdrInfo ph;
    if (!phdr_read(&m, (size_t)phoff + (size_t)i * ELF64_PHDR_SIZE, &ph))
      break; /* the program-header array ended early */
    if (ph.p_type == PT_LOAD_TYPE && nsegs < DYNLOAD_MAX_SEGS) {
      const uint8_t *s = (const uint8_t *)mod_at(&m, ph.p_vaddr, 1);
      if (s) {
        size_t avail = m.len - (size_t)(s - m.base);
        size_t seglen = ph.p_memsz;
        if (seglen > avail)
          seglen = avail;
        segs[nsegs].p = s;
        segs[nsegs].len = seglen;
        nsegs++;
      }
    }
    if (ph.p_type == PT_DYNAMIC_TYPE && !have_dyn) {
      const uint8_t *dp = (const uint8_t *)mod_at(&m, ph.p_vaddr, 1);
      if (dp) {
        dyn_off = (size_t)(dp - m.base);
        size_t avail = m.len - dyn_off;
        dyn_bytes = (size_t)ph.p_filesz;
        if (dyn_bytes > avail)
          dyn_bytes = avail;
        have_dyn = 1;
      }
    }
  }
  if (!have_dyn || dyn_bytes < ELF64_DYN_SIZE)
    return NULL;
  if (nsegs > 0 && !seg_has(segs, nsegs, m.base + dyn_off, ELF64_DYN_SIZE))
    return NULL;

  unsigned long symtab_v = 0;
  unsigned long strtab_v = 0;
  unsigned long hash_v = 0;
  unsigned long ghash_v = 0;
  size_t dyn_count = dyn_bytes / ELF64_DYN_SIZE;
  for (size_t i = 0; i < dyn_count; i++) {
    DynInfo de;
    if (!dyn_read(&m, dyn_off + i * ELF64_DYN_SIZE, &de))
      break;
    if (de.d_tag == DT_NULL)
      break;
    if (de.d_tag == DT_SYMTAB)
      symtab_v = de.d_val;
    else if (de.d_tag == DT_STRTAB)
      strtab_v = de.d_val;
    else if (de.d_tag == DT_HASH)
      hash_v = de.d_val;
    else if (de.d_tag == DT_GNU_HASH)
      ghash_v = de.d_val;
  }
  if (symtab_v == 0 || strtab_v == 0)
    return NULL;
  /* hash_v/ghash_v are each unused when the build pins the other hash style. */
  (void)hash_v;
  (void)ghash_v;

  const uint8_t *symtab = (const uint8_t *)mod_abs(&m, symtab_v);
  const uint8_t *strtab = (const uint8_t *)mod_abs(&m, strtab_v);
  if (symtab == NULL || strtab == NULL)
    return NULL;
  if (nsegs > 0 && (!seg_has(segs, nsegs, symtab, ELF64_SYM_SIZE) ||
                    !seg_has(segs, nsegs, strtab, 1)))
    return NULL;

  size_t sym_off = (size_t)(symtab - m.base);
  size_t str_off = (size_t)(strtab - m.base);

#if DYNLOAD_HASH_STYLE != DYNLOAD_HASH_GNU
  /* SysV hash (DT_HASH): nbucket, nchain, buckets[], chains[]. nchain is the
   * exact symbol count, so a linear scan is safe once bounded by the module. */
  if (hash_v) {
    const uint8_t *hp = (const uint8_t *)mod_abs(&m, hash_v);
    if (hp == NULL || !mod_has(&m, hp, 2 * sizeof(uint32_t)))
      return NULL;
    uint32_t nbucket = rd32(hp);
    uint32_t nchain = rd32(hp + 4);
    size_t words = (size_t)nbucket + (size_t)nchain;
    if (words > SIZE_MAX / sizeof(uint32_t) - 2)
      return NULL;
    size_t bytes = (2 + words) * sizeof(uint32_t);
    if (!mod_has(&m, hp, bytes))
      return NULL;
    if (nsegs > 0 && !seg_has(segs, nsegs, hp, bytes))
      return NULL;
    if ((size_t)nchain > (m.len - sym_off) / ELF64_SYM_SIZE)
      return NULL;
    for (size_t i = 0; i < (size_t)nchain; i++) {
      SymInfo sym;
      if (!sym_read(&m, sym_off, i, &sym))
        break;
      if (sym_named(&m, segs, nsegs, str_off, &sym, name))
        return sym_addr(&m, segs, nsegs, sym.st_value);
    }
    return NULL;
  }
#endif

#if DYNLOAD_HASH_STYLE != DYNLOAD_HASH_SYSV
  if (ghash_v) {
    const uint8_t *gp = (const uint8_t *)mod_abs(&m, ghash_v);
    if (gp)
      return resolve_sym_gnu(&m, segs, nsegs, sym_off, str_off, gp, name);
    return NULL;
  }
#endif

  return NULL;
}

void dynload_reset(dynload *dl) {
  if (!dl)
    return;
  dl->resolved = 0;
  dl->open = 0;
  dl->sym = 0;
  dl->close = 0;
}

/* Resolve one set of three dl* symbols from libc. Returns 0 only when all
 * three were found, so the caller can try the fallback set. */
static int resolve_dl_set(const void *libc, size_t len, const char *open_name,
                          const char *sym_name, const char *close_name,
                          dlopen_fn *open, dlsym_fn *sym, dlclose_fn *close) {
  *open = (dlopen_fn)dynload_resolve_module(libc, len, open_name);
  *sym = (dlsym_fn)dynload_resolve_module(libc, len, sym_name);
  *close = (dlclose_fn)dynload_resolve_module(libc, len, close_name);
  return (*open && *sym && *close) ? 0 : -1;
}

int dynload_resolve(dynload *dl) {
  if (!dl)
    return -1;
  if (dl->open && dl->sym && dl->close)
    return 0;

  unsigned long end = 0;
  unsigned long libc = dynload_find_libc(&end);
  if (libc && end > libc) {
    size_t len = (size_t)(end - libc);
    const void *base = (const void *)libc;
    if (resolve_dl_set(base, len, DYNLOAD_SYM_DLOPEN, DYNLOAD_SYM_DLSYM,
                       DYNLOAD_SYM_DLCLOSE, &dl->open, &dl->sym,
                       &dl->close) != 0) {
#if DYNLOAD_MODE == DYNLOAD_MODE_AUTO
      /* __libc_dlopen_mode exists before glibc 2.34 and dlopen from 2.34 on;
       * neither is present on every host, so AUTO tries both. */
      (void)resolve_dl_set(base, len, DYNLOAD_SYM_DLOPEN_ALT,
                           DYNLOAD_SYM_DLSYM_ALT, DYNLOAD_SYM_DLCLOSE_ALT,
                           &dl->open, &dl->sym, &dl->close);
#endif
    }
  }
  dl->resolved = (dl->open && dl->sym && dl->close) ? 1 : 0;
  return dl->resolved ? 0 : -1;
}

void *dynload_open(dynload *dl, const char *soname, int flags) {
  if (dynload_resolve(dl) != 0)
    return NULL;
  return dl->open(soname, flags);
}

void *dynload_sym(dynload *dl, void *handle, const char *name) {
  if (dynload_resolve(dl) != 0)
    return NULL;
  return dl->sym(handle, name);
}

int dynload_close(dynload *dl, void *handle) {
  if (dynload_resolve(dl) != 0)
    return -1;
  return dl->close(handle);
}
