/*
 * elfload.c — in-memory ELF64 shared-object loader.
 * See elfload.h. The C counterpart of the Go agent's memmod.
 *
 * Linux-only (anonymous mmap + /proc/self/maps-backed host symbol lookup).
 */

/* MAP_ANONYMOUS under -std=c99. */
#define _GNU_SOURCE

#include "util/elfload.h"

#include "util/dynload.h"

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* ---- minimal ELF64 layout (no elf.h, matching dynload.c) ---------------- */

#define ELF64_EHDR_SIZE 64
#define ELF64_PHDR_SIZE 56
#define ELF64_DYN_SIZE 16
#define ELF64_SYM_SIZE 24
#define ELF64_RELA_SIZE 24

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EV_CURRENT 1

#define ET_DYN 3

#define EM_X86_64 62
#define EM_AARCH64 183
#define EM_RISCV 243

#define PT_LOAD 1
#define PT_DYNAMIC 2

#define PF_X 1
#define PF_W 2
#define PF_R 4

#define DT_NULL 0
#define DT_PLTRELSZ 2
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_RELAENT 9
#define DT_STRSZ 10
#define DT_SYMENT 11
#define DT_INIT 12
#define DT_PLTREL 20
#define DT_JMPREL 23
#define DT_INIT_ARRAY 25
#define DT_INIT_ARRAYSZ 27
#define DT_PLTREL_RELA 7

#define STT_GNU_IFUNC 10
#define SHN_UNDEF 0

/* x86_64 relocations (the only machine the coffloader_linux dependency is
 * built for), plus the handful shared with aarch64/riscv64. */
#define R_X86_64_NONE 0
#define R_X86_64_64 1
#define R_X86_64_PC32 2
#define R_X86_64_GLOB_DAT 6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_RELATIVE 8
#define R_X86_64_32 10
#define R_X86_64_32S 11
#define R_X86_64_IRELATIVE 37

#define R_AARCH64_ABS64 257
#define R_AARCH64_ABS32 258
#define R_AARCH64_PREL64 260
#define R_AARCH64_PREL32 261
#define R_AARCH64_GLOB_DAT 1025
#define R_AARCH64_JUMP_SLOT 1026
#define R_AARCH64_RELATIVE 1027
#define R_AARCH64_IRELATIVE 1032

#define R_RISCV_32 1
#define R_RISCV_64 2
#define R_RISCV_RELATIVE 3
#define R_RISCV_JUMP_SLOT 5
#define R_RISCV_IRELATIVE 58

/* Defensive caps so a corrupt header cannot drive huge allocations. */
#define ELFLOAD_MAX_PHNUM 256
#define ELFLOAD_MAX_SEGS 64
#define ELFLOAD_MAX_MAP (64u * 1024u * 1024u)
#define ELFLOAD_MAX_NAME 256

typedef struct {
  uint64_t vaddr;
  uint64_t memsz;
  uint64_t filesz;
  uint64_t offset;
  uint32_t flags;
} load_seg;

typedef struct {
  uint64_t init;
  uint64_t init_array;
  uint64_t init_array_sz;
} init_info;

struct elfload_module {
  uint8_t *map;
  size_t map_len;
  uint16_t machine;
};

/* Host libraries searched for an undefined (imported) symbol. libc covers
 * glibc and musl; the soname and the dashed real filename are both listed
 * because /proc/self/maps shows the latter on RHEL/CentOS. */
static const char *const host_libs[] = {
    "libc.so", "libc-", "libc.musl",   "ld-musl",
    "libm.so", "libm-", "libgcc_s.so", "libgcc_s-",
};

/* glibc before 2.34 keeps the dl* entry points in a separate library; libc
 * exports the internal __libc_* equivalents. Resolve those instead. */
static const struct {
  const char *name;
  const char *alias;
} host_aliases[] = {
    {"dlsym", "__libc_dlsym"},        {"__libc_dlsym", "dlsym"},
    {"dlopen", "__libc_dlopen_mode"}, {"__libc_dlopen_mode", "dlopen"},
    {"dlclose", "__libc_dlclose"},    {"__libc_dlclose", "dlclose"},
};

static void set_err(char *err, size_t cap, const char *msg) {
  if (err == NULL || cap == 0)
    return;
  size_t i = 0;
  for (; msg[i] != '\0' && i + 1 < cap; i++)
    err[i] = msg[i];
  err[i] = '\0';
}

static uint16_t rd16(const uint8_t *p) {
  return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t rd32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
  return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static size_t align_down(size_t v, size_t a) {
  return v & ~(a - 1);
}

#ifndef ELFLOAD_NO_EXEC
/* ---- crash guard ---------------------------------------------------------
 * A faulty image must not take the agent down. An image-supplied IFUNC
 * resolver or constructor can jump anywhere or fault; while one runs we catch
 * SIGSEGV/SIGBUS/SIGILL/SIGFPE and turn the fault into a clean rejection
 * instead of a process-wide crash. The guard is process-wide and not
 * re-entrant, matching elfload_map's single-threaded use; the BOF loader has
 * its own guard around execution. SA_ONSTACK plus a private stack lets a
 * constructor that overflows the stack be caught too. */
static sigjmp_buf g_guard_env;
static volatile sig_atomic_t g_guard_active;
static struct sigaction g_guard_old[32];
static const int g_guard_sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE};
#define G_GUARD_NSIG (sizeof(g_guard_sigs) / sizeof(g_guard_sigs[0]))

static void guard_handler(int sig, siginfo_t *info, void *ctx) {
  if (g_guard_active)
    siglongjmp(g_guard_env, 1);
  /* A signal from outside the guarded region: hand it back to whoever owned
   * the handler before us. */
  if (sig > 0 && sig < 32) {
    struct sigaction *old = &g_guard_old[sig];
    if ((old->sa_flags & SA_SIGINFO) && old->sa_sigaction != NULL) {
      old->sa_sigaction(sig, info, ctx);
      return;
    }
    if (old->sa_handler != SIG_IGN && old->sa_handler != SIG_DFL) {
      old->sa_handler(sig);
      return;
    }
  }
  signal(sig, SIG_DFL);
  raise(sig);
}

static void guard_install(void) {
  static char altstack[64 * 1024];
  static int altstack_ready;
  if (!altstack_ready) {
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    if (sigaltstack(&ss, NULL) == 0)
      altstack_ready = 1;
  }

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = guard_handler;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
  for (size_t i = 0; i < G_GUARD_NSIG; i++)
    sigaction(g_guard_sigs[i], &sa, &g_guard_old[g_guard_sigs[i]]);
  g_guard_active = 0;
}

static void guard_restore(void) {
  g_guard_active = 0;
  for (size_t i = 0; i < G_GUARD_NSIG; i++)
    sigaction(g_guard_sigs[i], &g_guard_old[g_guard_sigs[i]], NULL);
}
#endif /* !ELFLOAD_NO_EXEC */

/* ---- host symbol resolution --------------------------------------------- */

/* A GNU IFUNC's st_value is its resolver, not the callable implementation:
 * invoke it exactly as the dynamic linker does.
 *
 * ELFLOAD_NO_EXEC is defined only by the fuzz harness (fuzz/fuzz_elfload.c):
 * a hostile image can point an IFUNC/IRELATIVE entry at any address, so the
 * fuzzer records the resolver instead of calling attacker-chosen code. The
 * shipped agent never defines it. */
static void *ifunc_resolve(void *resolver) {
#ifdef ELFLOAD_NO_EXEC
  return resolver;
#else
  typedef void *(*ifunc_fn)(void);
  return ((ifunc_fn)resolver)();
#endif
}

static void *lookup_host_libs(const char *name) {
  for (size_t i = 0; i < sizeof(host_libs) / sizeof(host_libs[0]); i++) {
    unsigned long end = 0;
    unsigned long base = dynload_find_module(host_libs[i], &end);
    if (base == 0 || end <= base)
      continue;
    uint8_t info = 0;
    void *addr = dynload_lookup_module((const void *)base, (size_t)(end - base),
                                       name, &info);
    if (addr == NULL)
      continue;
    return ((info & 0xf) == STT_GNU_IFUNC) ? ifunc_resolve(addr) : addr;
  }
  return NULL;
}

static void *host_symbol(const char *name) {
  void *addr = lookup_host_libs(name);
  if (addr != NULL)
    return addr;
  for (size_t i = 0; i < sizeof(host_aliases) / sizeof(host_aliases[0]); i++) {
    if (strcmp(name, host_aliases[i].name) == 0)
      return lookup_host_libs(host_aliases[i].alias);
  }
  return NULL;
}

/* Copy a NUL-terminated name out of the module's string table, bounded by the
 * table size and the mapping. A missing terminator is a hard failure. */
static int module_name(const uint8_t *map, size_t map_len, size_t strtab_off,
                       size_t strsz, uint32_t st_name, char *out, size_t cap) {
  if (strtab_off > map_len)
    return 0;
  size_t avail = map_len - strtab_off;
  if (strsz != 0 && strsz < avail)
    avail = strsz;
  if (st_name >= avail)
    return 0;
  size_t n = 0;
  for (size_t i = st_name; i < avail; i++) {
    if (n + 1 >= cap)
      return 0;
    out[n] = (char)map[strtab_off + i];
    if (out[n] == '\0')
      return 1;
    n++;
  }
  return 0;
}

/* Resolve the symbol referenced by a relocation. Defined symbols become
 * load-bias-relative addresses; undefined ones are looked up in the host. */
static void *reloc_symbol(const uint8_t *map, size_t map_len, size_t symtab_off,
                          size_t strtab_off, size_t strsz, uint32_t sym_idx,
                          int *ok) {
  if (sym_idx == 0)
    return NULL;
  if (symtab_off > map_len ||
      (size_t)sym_idx > (map_len - symtab_off) / ELF64_SYM_SIZE) {
    *ok = 0;
    return NULL;
  }
  const uint8_t *s = map + symtab_off + (size_t)sym_idx * ELF64_SYM_SIZE;
  uint32_t st_name = rd32(s);
  uint8_t st_info = s[4];
  uint16_t st_shndx = rd16(s + 6);
  uint64_t st_value = rd64(s + 8);

  if (st_shndx != SHN_UNDEF) {
    if (st_value > map_len) {
      *ok = 0;
      return NULL;
    }
    return (void *)(map + st_value);
  }

  char name[ELFLOAD_MAX_NAME];
  if (!module_name(map, map_len, strtab_off, strsz, st_name, name,
                   sizeof(name))) {
    *ok = 0;
    return NULL;
  }
  void *addr = host_symbol(name);
  if (addr == NULL) {
    *ok = 0;
    return NULL;
  }
  if ((st_info & 0xf) == STT_GNU_IFUNC)
    addr = ifunc_resolve(addr);
  return addr;
}

/* ---- relocation application --------------------------------------------- */

static int wr64(uint8_t *map, size_t map_len, uint64_t off, uint64_t v) {
  if (off > map_len || sizeof(uint64_t) > map_len - off)
    return 0;
  memcpy(map + off, &v, sizeof(v));
  return 1;
}

static int wr32(uint8_t *map, size_t map_len, uint64_t off, uint32_t v) {
  if (off > map_len || sizeof(uint32_t) > map_len - off)
    return 0;
  memcpy(map + off, &v, sizeof(v));
  return 1;
}

/* R_*_IRELATIVE: the addend points at an IFUNC resolver to call immediately. */
static int wr_irelative(uint8_t *map, size_t map_len, uint64_t off,
                        uint64_t base, int64_t addend) {
  void *resolver = (void *)(uintptr_t)(base + (uint64_t)addend);
#ifdef ELFLOAD_NO_EXEC
  /* Fuzz builds record the resolver instead of calling it. */
  return wr64(map, map_len, off, (uint64_t)(uintptr_t)resolver);
#else
  void *resolved = resolver;
  guard_install();
  if (sigsetjmp(g_guard_env, 1) == 0) {
    g_guard_active = 1;
    resolved = ifunc_resolve(resolver);
    g_guard_active = 0;
  } else {
    g_guard_active = 0;
    guard_restore();
    return 0;
  }
  guard_restore();
  return wr64(map, map_len, off, (uint64_t)(uintptr_t)resolved);
#endif
}

static int apply_reloc(elfload_module *m, uint64_t off, uint32_t type,
                       uint64_t sym_value, int64_t addend) {
  uint8_t *map = m->map;
  size_t map_len = m->map_len;
  uint64_t base = (uint64_t)(uintptr_t)map;

  switch (m->machine) {
  case EM_X86_64:
    switch (type) {
    case R_X86_64_NONE:
      return 1;
    case R_X86_64_64:
    case R_X86_64_GLOB_DAT:
    case R_X86_64_JUMP_SLOT:
      return wr64(map, map_len, off, sym_value + (uint64_t)addend);
    case R_X86_64_RELATIVE:
      return wr64(map, map_len, off, base + (uint64_t)addend);
    case R_X86_64_IRELATIVE:
      return wr_irelative(map, map_len, off, base, addend);
    case R_X86_64_32: {
      int64_t v = (int64_t)sym_value + addend;
      if (v < 0 || v > 0xffffffffLL)
        return 0;
      return wr32(map, map_len, off, (uint32_t)v);
    }
    case R_X86_64_32S: {
      int64_t v = (int64_t)sym_value + addend;
      if (v < -0x80000000LL || v > 0x7fffffffLL)
        return 0;
      return wr32(map, map_len, off, (uint32_t)(int32_t)v);
    }
    case R_X86_64_PC32: {
      int64_t v = (int64_t)sym_value + addend - (int64_t)(base + off);
      if (v < -0x80000000LL || v > 0x7fffffffLL)
        return 0;
      return wr32(map, map_len, off, (uint32_t)(int32_t)v);
    }
    default:
      return 0;
    }
  case EM_AARCH64:
    switch (type) {
    case R_X86_64_NONE:
      return 1;
    case R_AARCH64_ABS64:
    case R_AARCH64_GLOB_DAT:
    case R_AARCH64_JUMP_SLOT:
      return wr64(map, map_len, off, sym_value + (uint64_t)addend);
    case R_AARCH64_RELATIVE:
      return wr64(map, map_len, off, base + (uint64_t)addend);
    case R_AARCH64_IRELATIVE:
      return wr_irelative(map, map_len, off, base, addend);
    case R_AARCH64_PREL64:
      return wr64(map, map_len, off,
                  sym_value + (uint64_t)addend - (base + off));
    case R_AARCH64_ABS32:
      return wr32(map, map_len, off, (uint32_t)(sym_value + (uint64_t)addend));
    case R_AARCH64_PREL32: {
      int64_t v = (int64_t)sym_value + addend - (int64_t)(base + off);
      if (v < -0x80000000LL || v > 0x7fffffffLL)
        return 0;
      return wr32(map, map_len, off, (uint32_t)(int32_t)v);
    }
    default:
      return 0;
    }
  case EM_RISCV:
    switch (type) {
    case R_X86_64_NONE:
      return 1;
    case R_RISCV_64:
    case R_RISCV_JUMP_SLOT:
      return wr64(map, map_len, off, sym_value + (uint64_t)addend);
    case R_RISCV_RELATIVE:
      return wr64(map, map_len, off, base + (uint64_t)addend);
    case R_RISCV_IRELATIVE:
      return wr_irelative(map, map_len, off, base, addend);
    case R_RISCV_32:
      return wr32(map, map_len, off, (uint32_t)(sym_value + (uint64_t)addend));
    default:
      return 0;
    }
  default:
    return 0;
  }
}

static int apply_rela(elfload_module *m, uint64_t rela_off, uint64_t rela_sz,
                      size_t symtab_off, size_t strtab_off, size_t strsz) {
  if (rela_sz == 0)
    return 1;
  if (rela_off > m->map_len || rela_sz > m->map_len - rela_off)
    return 0;
  if (rela_sz % ELF64_RELA_SIZE != 0)
    return 0;

  for (uint64_t off = 0; off < rela_sz; off += ELF64_RELA_SIZE) {
    const uint8_t *r = m->map + rela_off + off;
    uint64_t r_offset = rd64(r);
    uint64_t r_info = rd64(r + 8);
    int64_t addend = (int64_t)rd64(r + 16);
    uint32_t sym_idx = (uint32_t)(r_info >> 32);
    uint32_t type = (uint32_t)r_info;

    int ok = 1;
    void *sym = reloc_symbol(m->map, m->map_len, symtab_off, strtab_off, strsz,
                             sym_idx, &ok);
    if (!ok)
      return 0;
    if (!apply_reloc(m, r_offset, type, (uint64_t)sym, addend))
      return 0;
  }
  return 1;
}

/* ---- segment protection -------------------------------------------------- */

static int prot_from_flags(uint32_t flags) {
  int prot = 0;
  if (flags & PF_R)
    prot |= PROT_READ;
  if (flags & PF_W)
    prot |= PROT_WRITE;
  if (flags & PF_X)
    prot |= PROT_EXEC;
  return prot;
}

static void flush_icache(void *start, void *end) {
#if defined(__aarch64__) || defined(__arm__) || defined(__riscv)
  __builtin___clear_cache((char *)start, (char *)end);
#else
  (void)start;
  (void)end;
#endif
}

/* ---- initializers -------------------------------------------------------- */

static int run_init(elfload_module *m, const init_info *init) {
#ifdef ELFLOAD_NO_EXEC
  /* Fuzz builds do not execute image-supplied constructors (see
   * ifunc_resolve). */
  (void)m;
  (void)init;
  return 1;
#else
  guard_install();
  if (sigsetjmp(g_guard_env, 1) != 0) {
    g_guard_active = 0;
    guard_restore();
    return 0;
  }
  g_guard_active = 1;
  typedef void (*init_fn)(int, char **, char **);
  if (init->init != 0 && init->init <= m->map_len)
    ((init_fn)(m->map + init->init))(0, NULL, NULL);
  if (init->init_array != 0 && init->init_array_sz >= sizeof(uint64_t) &&
      init->init_array <= m->map_len &&
      init->init_array_sz <= m->map_len - init->init_array) {
    size_t count = (size_t)(init->init_array_sz / sizeof(uint64_t));
    const uint8_t *arr = m->map + init->init_array;
    /* The array was relocated above, so its entries are absolute runtime
     * addresses; bound-check them against the mapping, not its length. */
    uint64_t base = (uint64_t)(uintptr_t)m->map;
    for (size_t i = 0; i < count; i++) {
      uint64_t fn = rd64(arr + i * sizeof(uint64_t));
      if (fn != 0 && fn != UINT64_MAX && fn >= base && fn < base + m->map_len)
        ((init_fn)(uintptr_t)fn)(0, NULL, NULL);
    }
  }
  g_guard_active = 0;
  guard_restore();
  return 1;
#endif
}

/* ---- mapping ------------------------------------------------------------- */

elfload_module *elfload_map(const uint8_t *image, size_t len, char *err,
                            size_t err_cap) {
  if (err != NULL && err_cap != 0)
    err[0] = '\0';
  if (image == NULL || len < ELF64_EHDR_SIZE) {
    set_err(err, err_cap, "truncated ELF header");
    return NULL;
  }
  const uint8_t *e = image;
  if (e[0] != ELFMAG0 || e[1] != ELFMAG1 || e[2] != ELFMAG2 ||
      e[3] != ELFMAG3 || e[EI_CLASS] != ELFCLASS64 ||
      e[EI_DATA] != ELFDATA2LSB || e[EI_VERSION] != EV_CURRENT) {
    set_err(err, err_cap, "not an ELF64 little-endian image");
    return NULL;
  }
  if (rd16(e + 16) != ET_DYN) {
    set_err(err, err_cap, "not a shared object (ET_DYN)");
    return NULL;
  }
  uint16_t machine = rd16(e + 18);
  if (machine != EM_X86_64 && machine != EM_AARCH64 && machine != EM_RISCV) {
    set_err(err, err_cap, "unsupported ELF machine");
    return NULL;
  }
  /* An image for another machine would map but fault on the first call. */
  uint16_t host_machine = 0;
#if defined(__x86_64__)
  host_machine = EM_X86_64;
#elif defined(__aarch64__)
  host_machine = EM_AARCH64;
#elif defined(__riscv) && __riscv_xlen == 64
  host_machine = EM_RISCV;
#endif
  if (host_machine != 0 && machine != host_machine) {
    set_err(err, err_cap, "foreign ELF machine");
    return NULL;
  }
  uint16_t phentsize = rd16(e + 54);
  uint16_t phnum = rd16(e + 56);
  uint64_t phoff = rd64(e + 32);
  if (phentsize != ELF64_PHDR_SIZE || phnum == 0 || phnum > ELFLOAD_MAX_PHNUM ||
      phoff > len || (uint64_t)phnum * ELF64_PHDR_SIZE > len - phoff) {
    set_err(err, err_cap, "invalid program header table");
    return NULL;
  }

  load_seg segs[ELFLOAD_MAX_SEGS];
  size_t nsegs = 0;
  uint64_t max_vaddr = 0;
  uint64_t dyn_vaddr = 0;
  uint64_t dyn_memsz = 0;
  int have_dyn = 0;
  for (uint16_t i = 0; i < phnum; i++) {
    const uint8_t *p = image + phoff + (size_t)i * ELF64_PHDR_SIZE;
    uint32_t type = rd32(p);
    if (type == PT_LOAD) {
      if (nsegs == ELFLOAD_MAX_SEGS) {
        set_err(err, err_cap, "too many loadable segments");
        return NULL;
      }
      uint64_t offset = rd64(p + 8);
      uint64_t vaddr = rd64(p + 16);
      uint64_t filesz = rd64(p + 32);
      uint64_t memsz = rd64(p + 40);
      uint32_t flags = rd32(p + 4);
      if (filesz > memsz || offset > len || filesz > len - offset ||
          vaddr > UINT64_MAX - memsz) {
        set_err(err, err_cap, "malformed loadable segment");
        return NULL;
      }
      /* A segment with no access flags would mprotect its range PROT_NONE;
       * one covering the image (ELF header included) would make the mapped
       * module unreadable for every later symbol lookup. Reject it. */
      if (prot_from_flags(flags) == 0) {
        set_err(err, err_cap, "loadable segment has no access permissions");
        return NULL;
      }
      if (vaddr + memsz > max_vaddr)
        max_vaddr = vaddr + memsz;
      segs[nsegs].offset = offset;
      segs[nsegs].vaddr = vaddr;
      segs[nsegs].filesz = filesz;
      segs[nsegs].memsz = memsz;
      segs[nsegs].flags = flags;
      nsegs++;
    } else if (type == PT_DYNAMIC && !have_dyn) {
      dyn_vaddr = rd64(p + 16);
      dyn_memsz = rd64(p + 40);
      have_dyn = 1;
    }
  }
  if (nsegs == 0 || max_vaddr == 0 || !have_dyn) {
    set_err(err, err_cap, "no loadable segments or dynamic section");
    return NULL;
  }

  long page_l = sysconf(_SC_PAGESIZE);
  if (page_l <= 0) {
    set_err(err, err_cap, "cannot determine page size");
    return NULL;
  }
  size_t page = (size_t)page_l;
  if (max_vaddr > ELFLOAD_MAX_MAP - page) {
    set_err(err, err_cap, "module image too large");
    return NULL;
  }
  size_t map_len = align_down((size_t)max_vaddr + page - 1, page);

  uint8_t *map = (uint8_t *)mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (map == MAP_FAILED) {
    set_err(err, err_cap, "mmap failed");
    return NULL;
  }

  /* Copy the file-backed bytes of every segment and zero its BSS tail. */
  for (size_t i = 0; i < nsegs; i++) {
    memcpy(map + segs[i].vaddr, image + segs[i].offset, (size_t)segs[i].filesz);
    if (segs[i].memsz > segs[i].filesz)
      memset(map + segs[i].vaddr + segs[i].filesz, 0,
             (size_t)(segs[i].memsz - segs[i].filesz));
  }

  uint64_t symtab_v = 0;
  uint64_t strtab_v = 0;
  uint64_t strsz = 0;
  uint64_t rela_v = 0;
  uint64_t rela_sz = 0;
  uint64_t jmprel_v = 0;
  uint64_t pltrel_sz = 0;
  uint64_t pltrel = 0;
  init_info init = {0, 0, 0};

  if (dyn_vaddr > map_len || dyn_memsz > map_len - dyn_vaddr) {
    set_err(err, err_cap, "dynamic section out of range");
    munmap(map, map_len);
    return NULL;
  }
  const uint8_t *dyn = map + dyn_vaddr;
  size_t ndyn = (size_t)(dyn_memsz / ELF64_DYN_SIZE);
  for (size_t i = 0; i < ndyn; i++) {
    int64_t tag = (int64_t)rd64(dyn + i * ELF64_DYN_SIZE);
    uint64_t val = rd64(dyn + i * ELF64_DYN_SIZE + 8);
    if (tag == DT_NULL)
      break;
    switch (tag) {
    case DT_SYMTAB:
      symtab_v = val;
      break;
    case DT_STRTAB:
      strtab_v = val;
      break;
    case DT_STRSZ:
      strsz = val;
      break;
    case DT_RELA:
      rela_v = val;
      break;
    case DT_RELASZ:
      rela_sz = val;
      break;
    case DT_JMPREL:
      jmprel_v = val;
      break;
    case DT_PLTRELSZ:
      pltrel_sz = val;
      break;
    case DT_PLTREL:
      pltrel = val;
      break;
    case DT_INIT:
      init.init = val;
      break;
    case DT_INIT_ARRAY:
      init.init_array = val;
      break;
    case DT_INIT_ARRAYSZ:
      init.init_array_sz = val;
      break;
    default:
      break;
    }
  }
  if (symtab_v == 0 || strtab_v == 0 || symtab_v > map_len ||
      strtab_v > map_len) {
    set_err(err, err_cap, "missing or out-of-range symbol tables");
    munmap(map, map_len);
    return NULL;
  }
  size_t symtab_off = (size_t)symtab_v;
  size_t strtab_off = (size_t)strtab_v;
  size_t strsz_s = strsz > map_len - strtab_off ? (size_t)(map_len - strtab_off)
                                                : (size_t)strsz;

  /* Relocations must run before the segments are made read-only/executable. */
  int rel_ok = 1;
  if (rela_sz != 0) {
    elfload_module tmp = {map, map_len, machine};
    rel_ok = apply_rela(&tmp, rela_v, rela_sz, symtab_off, strtab_off, strsz_s);
  }
  if (rel_ok && jmprel_v != 0 && pltrel_sz != 0) {
    if (pltrel != DT_PLTREL_RELA) {
      set_err(err, err_cap, "unsupported PLT relocation format");
      munmap(map, map_len);
      return NULL;
    }
    elfload_module tmp = {map, map_len, machine};
    rel_ok =
        apply_rela(&tmp, jmprel_v, pltrel_sz, symtab_off, strtab_off, strsz_s);
  }
  if (!rel_ok) {
    set_err(err, err_cap,
            "relocation failed (unsupported type or unresolved symbol)");
    munmap(map, map_len);
    return NULL;
  }

  /* Apply per-segment W^X, then run constructors. */
  for (size_t i = 0; i < nsegs; i++) {
    size_t start = align_down((size_t)segs[i].vaddr, page);
    size_t end = align_down(
        (size_t)segs[i].vaddr + (size_t)segs[i].memsz + page - 1, page);
    if (end > map_len)
      end = map_len;
    if (end > start && mprotect(map + start, end - start,
                                prot_from_flags(segs[i].flags)) != 0) {
      set_err(err, err_cap, "mprotect failed");
      munmap(map, map_len);
      return NULL;
    }
    if (segs[i].flags & PF_X)
      flush_icache(map + start, map + end);
  }

  elfload_module *m = (elfload_module *)malloc(sizeof(*m));
  if (m == NULL) {
    munmap(map, map_len);
    set_err(err, err_cap, "out of memory");
    return NULL;
  }
  m->map = map;
  m->map_len = map_len;
  m->machine = machine;

  if (!run_init(m, &init)) {
    munmap(map, map_len);
    free(m);
    set_err(err, err_cap, "constructor crashed");
    return NULL;
  }
  return m;
}

void *elfload_sym(const elfload_module *m, const char *name) {
  if (m == NULL || name == NULL)
    return NULL;
#ifdef ELFLOAD_NO_EXEC
  /* Fuzz builds let ASan/UBSan see the fault instead of swallowing it. */
  return dynload_resolve_module(m->map, m->map_len, name);
#else
  void *sym = NULL;
  guard_install();
  if (sigsetjmp(g_guard_env, 1) == 0) {
    g_guard_active = 1;
    sym = dynload_resolve_module(m->map, m->map_len, name);
    g_guard_active = 0;
  } else {
    g_guard_active = 0;
    guard_restore();
    return NULL;
  }
  guard_restore();
  return sym;
#endif
}

void elfload_free(elfload_module *m) {
  if (m == NULL)
    return;
  if (m->map != NULL)
    munmap(m->map, m->map_len);
  free(m);
}
