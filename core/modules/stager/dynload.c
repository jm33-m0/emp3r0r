#include "dynload.h"
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

typedef void *(*dlopen_fn)(const char *, int);
typedef void *(*dlsym_fn)(void *, const char *);
typedef int (*dlclose_fn)(void *);

/* Cached dl* entry points. The non-zero `ready` field forces this into .data
 * (raw shellcode extraction drops .bss), mirroring _cached_syscall_gadget. */
static struct {
  long ready;
  dlopen_fn dlopen_;
  dlsym_fn dlsym_;
  dlclose_fn dlclose_;
} g_dl = {1, 0, 0, 0};

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
  unsigned long nchain = 0;
  for (; dyn->d_tag != DT_NULL; dyn++) {
    /* Pointer-type DT_* entries hold absolute runtime addresses (the loader
     * relocates them); only st_value below needs the module base added. */
    if (dyn->d_tag == DT_SYMTAB)
      symtab = (Elf64_Sym *)dyn->d_val;
    else if (dyn->d_tag == DT_STRTAB)
      strtab = (const char *)dyn->d_val;
    else if (dyn->d_tag == DT_HASH)
      nchain = ((const uint32_t *)dyn->d_val)[1];
  }
  if (!symtab || !strtab || nchain == 0)
    return 0;

  for (unsigned long i = 0; i < nchain; i++) {
    const Elf64_Sym *sym = &symtab[i];
    if (sym->st_name != 0 && sym->st_shndx != 0 &&
        strcmp(strtab + sym->st_name, name) == 0)
      return (void *)((char *)base + sym->st_value);
  }
  return 0;
}

/* Resolve dlopen/dlsym/dlclose from libc once. Returns 0 on success. */
static int resolve_dl(void) {
  if (g_dl.ready == 0)
    return (g_dl.dlopen_ && g_dl.dlsym_ && g_dl.dlclose_) ? 0 : -1;

  unsigned long libc = find_libc_base();
  if (libc) {
    g_dl.dlopen_ = (dlopen_fn)resolve_sym((void *)libc, "dlopen");
    g_dl.dlsym_ = (dlsym_fn)resolve_sym((void *)libc, "dlsym");
    g_dl.dlclose_ = (dlclose_fn)resolve_sym((void *)libc, "dlclose");
  }
  g_dl.ready = 0;
  return (g_dl.dlopen_ && g_dl.dlsym_ && g_dl.dlclose_) ? 0 : -1;
}

void *dynload_open(const char *soname, int flags) {
  if (resolve_dl() != 0)
    return NULL;
  return g_dl.dlopen_(soname, flags);
}

void *dynload_sym(void *handle, const char *name) {
  if (resolve_dl() != 0)
    return NULL;
  return g_dl.dlsym_(handle, name);
}

int dynload_close(void *handle) {
  if (resolve_dl() != 0)
    return -1;
  return g_dl.dlclose_(handle);
}

unsigned long dynload_find_libc(void) { return find_libc_base(); }

void *dynload_resolve_module(void *base, const char *name) {
  return resolve_sym(base, name);
}
