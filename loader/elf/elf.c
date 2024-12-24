#if defined(NAKED)
#include "utils.h"
#include <system/syscall.h>
#else
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>
#endif

#include "arch.h"
#include "elf.h"

// Default function called upon exit() in the ELF. Depends on the architecture,
// as some archs don't call it at all.
static void _exit_func(int code) { exit(code); }

static void _get_rand(char *buf, int size) {
  int fd = open("/dev/urandom", O_RDONLY, 0);

  read(fd, (unsigned char *)buf, size);
  close(fd);
}

static char *_get_interp(char *buf) {
  int x;

  // Check for the existence of a dynamic loader
  Elf_Ehdr *hdr = (Elf_Ehdr *)buf;
  Elf_Phdr *phdr = (Elf_Phdr *)(buf + hdr->e_phoff);

  for (x = 0; x < hdr->e_phnum; x++) {
    if (phdr[x].p_type == PT_INTERP) {
      // There is a dynamic loader present, so load it
      return buf + phdr[x].p_offset;
    }
  }

  return NULL;
}

static Elf_Shdr *_get_section(char *name, void *elf_start) {
  int x;
  Elf_Ehdr *ehdr = NULL;
  Elf_Shdr *shdr;

  ehdr = (Elf_Ehdr *)elf_start;
  shdr = (Elf_Shdr *)(elf_start + ehdr->e_shoff);

  Elf_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
  char *sh_strtab_p = elf_start + sh_strtab->sh_offset;

  for (x = 0; x < ehdr->e_shnum; x++) {
    // printf("%p %s\n", shdr[x].sh_addr, sh_strtab_p + shdr[x].sh_name);

    if (!strcmp(name, sh_strtab_p + shdr[x].sh_name))
      return &shdr[x];
  }

  return NULL;
}

void *elf_sym(void *elf_start, char *sym_name) {
  int x, y;

  Elf_Ehdr *hdr = (Elf_Ehdr *)elf_start;
  Elf_Shdr *shdr = (Elf_Shdr *)(elf_start + hdr->e_shoff);

  for (x = 0; x < hdr->e_shnum; x++) {
    if (shdr[x].sh_type == SHT_SYMTAB) {
      const char *strings = elf_start + shdr[shdr[x].sh_link].sh_offset;
      Elf_Sym *syms = (Elf_Sym *)(elf_start + shdr[x].sh_offset);

      for (y = 0; y < shdr[x].sh_size / sizeof(Elf_Sym); y++) {
        // printf("@name:%s\n", strings + syms[y].st_name);

        if (strcmp(sym_name, strings + syms[y].st_name) == 0)
          return (void *)syms[y].st_value;
      }
    }
  }

  return NULL;
}

int elf_load(char *elf_start, void *stack, int stack_size, size_t *base_addr,
             size_t *entry) {
  Elf_Ehdr *hdr;
  Elf_Phdr *phdr;

  int x;
  int elf_prot = 0;
  int stack_prot = 0;
  size_t base;

  hdr = (Elf_Ehdr *)elf_start;
  phdr = (Elf_Phdr *)(elf_start + hdr->e_phoff);

  if (hdr->e_type == ET_DYN) {
    // If this is a DYNAMIC ELF (can be loaded anywhere), set a random base
    // address
    base = (size_t)mmap(0, 100 * PAGE_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
    munmap((void *)base, 100 * PAGE_SIZE);
  } else
    base = 0;

  if (base_addr != NULL)
    *base_addr = -1;

  if (entry != NULL)
    *entry = base + hdr->e_entry;

  for (x = 0; x < hdr->e_phnum; x++) {
#if !defined(OS_FREEBSD)
    // Get flags for the stack
    if (stack != NULL && phdr[x].p_type == PT_GNU_STACK) {
      if (phdr[x].p_flags & PF_R)
        stack_prot = PROT_READ;

      if (phdr[x].p_flags & PF_W)
        stack_prot |= PROT_WRITE;

      if (phdr[x].p_flags & PF_X)
        stack_prot |= PROT_EXEC;

      // Set stack protection
      mprotect((unsigned char *)stack, stack_size, stack_prot);
    }
#endif

    if (phdr[x].p_type != PT_LOAD)
      continue;

    if (!phdr[x].p_filesz)
      continue;

    void *map_start = (void *)ROUND_DOWN(phdr[x].p_vaddr, PAGE_SIZE);
    int round_down_size = (void *)phdr[x].p_vaddr - map_start;

    int map_size = ROUND_UP(phdr[x].p_memsz + round_down_size, PAGE_SIZE);

    void *m = mmap(base + map_start, map_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (m == NULL)
      return -1;
    memcpy((void *)base + phdr[x].p_vaddr, elf_start + phdr[x].p_offset,
           phdr[x].p_filesz);

    // Zero-out BSS, if it exists
    if (phdr[x].p_memsz > phdr[x].p_filesz)
      memset((void *)(base + phdr[x].p_vaddr + phdr[x].p_filesz), 0,
             phdr[x].p_memsz - phdr[x].p_filesz);

    // Set proper protection on the area
    if (phdr[x].p_flags & PF_R)
      elf_prot = PROT_READ;

    if (phdr[x].p_flags & PF_W)
      elf_prot |= PROT_WRITE;

    if (phdr[x].p_flags & PF_X)
      elf_prot |= PROT_EXEC;

    mprotect((unsigned char *)(base + map_start), map_size, elf_prot);

    // Clear cache on this area
    cacheflush(base + map_start, (size_t)(map_start + map_size), 0);

    // Is this the lowest memory area we saw. That is, is this the ELF base
    // address?
    if (base_addr != NULL &&
        (*base_addr == -1 || *base_addr > (size_t)(base + map_start)))
      *base_addr = (size_t)(base + map_start);
  }

  return 0;
}

int elf_run(void *buf, char **argv, char **env) {
  int x;
  int str_len;
  int str_ptr = 0;
  int stack_ptr = 1;
  int cnt = 0;
  int argc = 0;
  int envc = 0;

  Elf_Ehdr *hdr = (Elf_Ehdr *)buf;

  size_t elf_base, elf_entry;
  size_t interp_base = 0;
  size_t interp_entry = 0;

  char rand_bytes[16];

  // Fill in 16 random bytes for the loader below
  _get_rand(rand_bytes, 16);

  int (*ptr)(int, char **, char **);

  // First, let's count arguments...
  while (argv[argc])
    argc++;

  // ...and envs
  while (env[envc])
    envc++;

  // Allocate some stack space
  void *stack = mmap(0, STACK_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANON, -1, 0);

  // Map the ELF in memory
  if (elf_load(buf, stack, STACK_SIZE, &elf_base, &elf_entry) < 0)
    return -1;

  // Check for the existence of a dynamic loader
  char *interp_name = _get_interp(buf);

  if (interp_name) {
    int f = open(interp_name, O_RDONLY, 0);

    // Find out the size of the file
    int size = lseek(f, 0, SEEK_END);
    lseek(f, 0, SEEK_SET);

    void *elf_ld = mmap(0, ROUND_UP(size, PAGE_SIZE), PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);

    read(f, elf_ld, size);
    elf_load(elf_ld, stack, STACK_SIZE, &interp_base, &interp_entry);

    munmap(elf_ld, ROUND_UP(size, PAGE_SIZE));
  }

  // Zero out the whole stack, Justin Case
  memset(stack, 0, STACK_STORAGE_SIZE);

  unsigned long *stack_storage =
      stack + STACK_SIZE - STACK_STORAGE_SIZE - STACK_STRING_SIZE;
  char *string_storage = stack + STACK_SIZE - STACK_STRING_SIZE;

  unsigned long *s_argc = stack_storage;
  unsigned long *s_argv = &stack_storage[1];

  // Setup argc
  *s_argc = argc;

  // Setup argv
  for (x = 0; x < argc; x++) {
    str_len = strlen(argv[x]) + 1;

    // Copy the string on to the stack inside the string storage area
    memcpy(&string_storage[str_ptr], argv[x], str_len);

    // Make the startup struct point to the string
    s_argv[x] = (unsigned long)&string_storage[str_ptr];

    str_ptr += str_len;
    stack_ptr++;
  }

  // End-of-argv NULL
  stack_storage[stack_ptr++] = 0;

  unsigned long *s_env = &stack_storage[stack_ptr];

  for (x = 0; x < envc; x++) {
    str_len = strlen(env[x]) + 1;

    // Copy the string on to the stack inside the string storage area
    memcpy(&string_storage[str_ptr], env[x], str_len);

    // Make the startup struct point to the string
    s_env[x] = (unsigned long)&string_storage[str_ptr];

    str_ptr += str_len;
    stack_ptr++;
  }

  // End-of-env NULL
  stack_storage[stack_ptr++] = 0;

  // Let's run the constructors
  Elf_Shdr *init = _get_section(".init", buf);
  Elf_Shdr *init_array = _get_section(".init_array", buf);

  size_t base = 0;
  if (hdr->e_type == ET_DYN) {
    // It's a PIC file, so make sure we add the base when we call the
    // constructors
    base = elf_base;
  }

  if (init) {
    ptr = (int (*)(int, char **, char **))base + init->sh_addr;
    ptr(argc, argv, env);
  }

  if (init_array) {
    for (x = 0; x < init_array->sh_size / sizeof(void *); x++) {
      ptr = (int (*)(int, char **, char **))base +
            *((long *)(base + init_array->sh_addr + (x * sizeof(void *))));
      ptr(argc, argv, env);
    }
  }

  struct ATENTRY *at = (struct ATENTRY *)&stack_storage[stack_ptr];

  // AT_PHDR
  at[cnt].id = AT_PHDR;
  at[cnt++].value = (size_t)(elf_base + hdr->e_phoff);
  // AT_PHENT
  at[cnt].id = AT_PHENT;
  at[cnt++].value = sizeof(Elf_Phdr);
  // AT_PHNUM
  at[cnt].id = AT_PHNUM;
  at[cnt++].value = hdr->e_phnum;
  // AT_PGSIZE
  at[cnt].id = AT_PAGESZ;
  at[cnt++].value = PAGE_SIZE;
  // AT_BASE (base address where the interpreter is loaded at)
  at[cnt].id = AT_BASE;
  at[cnt++].value = interp_base;
  // AT_FLAGS
  at[cnt].id = AT_FLAGS;
  at[cnt++].value = 0;
  // AT_ENTRY
  at[cnt].id = AT_ENTRY;
  at[cnt++].value = elf_entry;
  // AT_UID
  at[cnt].id = AT_UID;
  at[cnt++].value = getuid();
  // AT_EUID
  at[cnt].id = AT_EUID;
  at[cnt++].value = geteuid();
  // AT_GID
  at[cnt].id = AT_GID;
  at[cnt++].value = getgid();
  // AT_EGID
  at[cnt].id = AT_EGID;
  at[cnt++].value = getegid();
  // AT_RANDOM (address of 16 random bytes)
  at[cnt].id = AT_RANDOM;
  at[cnt++].value = (size_t)rand_bytes;
  // AT_NULL
  at[cnt].id = AT_NULL;
  at[cnt++].value = 0;

  //
  // Architecture and OS dependant init-reg-and-jump-to-start trampoline
  //
  if (interp_entry)
    jump_start(stack_storage, (void *)_exit_func, (void *)interp_entry);
  else
    jump_start(stack_storage, (void *)_exit_func, (void *)elf_entry);

  // Shouldn't be reached, but just in case
  return -1;
}
