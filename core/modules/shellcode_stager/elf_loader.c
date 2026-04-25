/*
 * adapted from https://github.com/malisal/loaders
 * */
#ifdef __linux__

#include "elf_loader.h"
#include "utils.h"
#include <elf.h>

// Declare the jump_start function for all architectures
void jump_start(void *init, void *exit_func, void *entry);

// Define RELATIVE constant based on arch
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#define REL_TYPE_RELATIVE 8
#elif defined(__aarch64__)
#define REL_TYPE_RELATIVE 1027
#else
#define REL_TYPE_RELATIVE 8 // Fallback
#endif

#if defined(GOARCH_amd64)
void jump_start(void *init, void *exit_func, void *entry) {
  register long rsp __asm__("rsp") = (long)init;
  register long rdx __asm__("rdx") = (long)exit_func;
  register long rax __asm__("rax") = (long)entry;

  __asm__ __volatile__("jmp *%0\n" : : "r"(rax), "r"(rsp), "r"(rdx) :);
}
#elif defined(GOARCH_386)
void jump_start(void *init, void *exit_func, void *entry) {
  register long esp __asm__("esp") = (long)init;
  register long edx __asm__("edx") = (long)exit_func;

  __asm__ __volatile__("jmp *%0\n" : : "r"(entry), "r"(esp), "r"(edx) :);
}
#elif defined(GOARCH_arm64)
void jump_start(void *init, void *exit_func, void *entry) {
  register long sp __asm__("sp") = (long)init;
  register long x0 __asm__("x0") = (long)exit_func;

  __asm__ __volatile__("blr %0;\n" : : "r"(entry), "r"(sp), "r"(x0) :);
}
#elif defined(GOARCH_ppc64)
void jump_start(void *init, void *exit_func, void *entry) {
  register long r3 __asm__("3") = (long)0;
  register long r4 __asm__("4") = (long)entry;
  register long sp __asm__("sp") = (long)init;
  __asm__ __volatile__("mtlr %0;\n"
                       "blr;\n"
                       :
                       : "r"(r4), "r"(sp), "r"(r3)
                       :);
}
#elif defined(GOARCH_arm)
void jump_start(void *init, void *exit_func, void *entry) {
  register long sp __asm__("sp") = (long)init;
  register long r0 __asm__("r0") = (long)exit_func;

  __asm__ __volatile__("mov lr, %0;\n"
                       "bx %1;\n"
                       :
                       : "r"(entry), "r"(sp), "r"(r0)
                       :);
}
#elif defined(GOARCH_riscv64)
void jump_start(void *init, void *exit_func, void *entry) {
  register long a0 __asm__("a0") = (long)init;
  register long a1 __asm__("a1") = (long)exit_func;

  __asm__ __volatile__("jalr %0, 0(%1)\n" : : "r"(entry), "r"(a0), "r"(a1) :);
}
#else
void jump_start(void *init, void *exit_func, void *entry) {
  register long rsp __asm__("rsp") = (long)init;
  register long rdx __asm__("rdx") = (long)exit_func;
  register long rax __asm__("rax") = (long)entry;

  __asm__ __volatile__("jmp *%0\n" : : "r"(rax), "r"(rsp), "r"(rdx) :);
}
#endif

// Default function called upon exit() in the ELF. Depends on the architecture,
// as some archs don't call it at all.
static void _exit_func(int code) {
  // fprintf(stderr, "ELF exited with code: %d\n", code);
  exit(code);
}

static void _get_rand(char *buf, int size) {
  // Use getrandom() syscall instead of opening /dev/urandom
  long result = getrandom(buf, size, 0);
  (void)result; // Suppress unused result warning
}

// Returns the required memory size and bounds for the ELF
// min_vaddr: lowest virtual address
// max_vaddr: highest virtual address (exclusive)
int elf_get_memory_bounds(char *elf_start, size_t *min_vaddr,
                          size_t *max_vaddr) {
  Elf_Ehdr *hdr = (Elf_Ehdr *)elf_start;
  Elf_Phdr *phdr = (Elf_Phdr *)(elf_start + hdr->e_phoff);
  size_t min = (size_t)-1;
  size_t max = 0;

  for (int x = 0; x < hdr->e_phnum; x++) {
    if (phdr[x].p_type != PT_LOAD || !phdr[x].p_memsz)
      continue;

    void *map_start = (void *)ROUND_DOWN(phdr[x].p_vaddr, PAGE_SIZE);
    int round_down_size = (void *)phdr[x].p_vaddr - map_start;
    int map_size = ROUND_UP(phdr[x].p_memsz + round_down_size, PAGE_SIZE);

    size_t start = (size_t)map_start;
    size_t end = start + map_size;

    if (start < min)
      min = start;
    if (end > max)
      max = end;
  }

  if (min_vaddr)
    *min_vaddr = min;
  if (max_vaddr)
    *max_vaddr = max;

  return 0;
}

// Handle relocations for ET_DYN (PIE) binaries using PT_DYNAMIC
static int elf_relocate(char *elf_start, size_t base_addr) {
  Elf_Ehdr *hdr = (Elf_Ehdr *)elf_start;
  Elf_Phdr *phdr = (Elf_Phdr *)(elf_start + hdr->e_phoff);
  Elf_Dyn *dyn = NULL;
  size_t dyn_size = 0;

  // Find PT_DYNAMIC
  for (int i = 0; i < hdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_DYNAMIC) {
      dyn = (Elf_Dyn *)(base_addr + phdr[i].p_vaddr);
      dyn_size = phdr[i].p_memsz;
      break;
    }
  }

  if (!dyn)
    return 0; // Not dynamic

  size_t rela = 0, relasz = 0, relaent = 0;
  size_t rel = 0, relsz = 0, relent = 0;
  size_t jmprel = 0, pltrelsz = 0;
  int plt_is_rela = 0;

  for (size_t i = 0; i < dyn_size / sizeof(Elf_Dyn); i++) {
    if (dyn[i].d_tag == DT_NULL)
      break;
    switch (dyn[i].d_tag) {
    case DT_RELA:
      rela = dyn[i].d_un.d_ptr;
      break;
    case DT_RELASZ:
      relasz = dyn[i].d_un.d_val;
      break;
    case DT_RELAENT:
      relaent = dyn[i].d_un.d_val;
      break;
    case DT_REL:
      rel = dyn[i].d_un.d_ptr;
      break;
    case DT_RELSZ:
      relsz = dyn[i].d_un.d_val;
      break;
    case DT_RELENT:
      relent = dyn[i].d_un.d_val;
      break;
    case DT_JMPREL:
      jmprel = dyn[i].d_un.d_ptr;
      break;
    case DT_PLTRELSZ:
      pltrelsz = dyn[i].d_un.d_val;
      break;
    case DT_PLTREL:
      plt_is_rela = (dyn[i].d_un.d_val == DT_RELA);
      break;
    }
  }

  // Apply RELA relocations
  if (rela && relasz && relaent) {
    for (size_t i = 0; i < relasz / relaent; i++) {
      Elf_Rela *r = (Elf_Rela *)(base_addr + rela + i * relaent);
      if (ELF_R_TYPE(r->r_info) == REL_TYPE_RELATIVE) {
        size_t *target = (size_t *)(base_addr + r->r_offset);
        *target = base_addr + r->r_addend;
      }
    }
  }

  // Apply REL relocations
  if (rel && relsz && relent) {
    for (size_t i = 0; i < relsz / relent; i++) {
      Elf_Rel *r = (Elf_Rel *)(base_addr + rel + i * relent);
      if (ELF_R_TYPE(r->r_info) == REL_TYPE_RELATIVE) {
        size_t *target = (size_t *)(base_addr + r->r_offset);
        *target = base_addr + *target;
      }
    }
  }

  // Apply PLT relocations
  if (jmprel && pltrelsz) {
    size_t ent = plt_is_rela ? (relaent ? relaent : sizeof(Elf_Rela))
                             : (relent ? relent : sizeof(Elf_Rel));
    for (size_t i = 0; i < pltrelsz / ent; i++) {
      if (plt_is_rela) {
        Elf_Rela *r = (Elf_Rela *)(base_addr + jmprel + i * ent);
        if (ELF_R_TYPE(r->r_info) == 8) {
          size_t *target = (size_t *)(base_addr + r->r_offset);
          *target = base_addr + r->r_addend;
        }
      } else {
        Elf_Rel *r = (Elf_Rel *)(base_addr + jmprel + i * ent);
        if (ELF_R_TYPE(r->r_info) == 8) {
          size_t *target = (size_t *)(base_addr + r->r_offset);
          *target = base_addr + *target;
        }
      }
    }
  }

  return 0;
}

// pre_mapped: if true, assume memory at base_addr is already mapped and
// writable
int elf_load(char *elf_start, void *stack, int stack_size, size_t *base_addr,
             size_t *entry, size_t *mapped_size, int pre_mapped,
             const char *module_path) {
  debug_print("elf_load started\n");
  (void)stack;
  (void)stack_size;
  (void)entry;
  Elf_Ehdr *hdr;
  Elf_Phdr *phdr;

  size_t x;
  size_t base = 0;
  size_t total_mapped_size = 0;

  hdr = (Elf_Ehdr *)elf_start;
  phdr = (Elf_Phdr *)(elf_start + hdr->e_phoff);

  void *mapped_mem = NULL;

  if (hdr->e_type == ET_DYN) {
    debug_print("ET_DYN (PIE) detected.\n");
    if (pre_mapped && base_addr && *base_addr != 0) {
      base = *base_addr;
      mapped_mem = (void *)base;
    } else if (module_path && module_path[0] != '\0') {
      debug_print("Attempting module stomping on %s\n", module_path);
      int fd = open(module_path, O_RDONLY, 0);
      if (fd >= 0) {
        // Get file size using lseek
        long size = lseek(fd, 0, SEEK_END);
        if (size > 0) {
          size_t st_size = (size_t)size;
          // Seek back to start
          lseek(fd, 0, SEEK_SET);

          // Calculate required size for our payload
          size_t required_size = 0;
          // We need to iterate PHDRs to find the total span
          size_t min_v = (size_t)-1, max_v = 0;
          for (int i = 0; i < hdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD && phdr[i].p_memsz > 0) {
              size_t vstart = phdr[i].p_vaddr;
              size_t vend = vstart + phdr[i].p_memsz;
              if (vstart < min_v)
                min_v = vstart;
              if (vend > max_v)
                max_v = vend;
            }
          }
          required_size = max_v - min_v; // Assuming base 0 for calculation

          if (st_size >= required_size) {
            // Map the legitimate file Copy-On-Write
            mapped_mem =
                (void *)mmap(NULL, st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            if (mapped_mem != MAP_FAILED) {
              debug_print("Mapped %s at %p\n", module_path, mapped_mem);

              // We need it writable to stomp
              if (mprotect(mapped_mem, st_size, PROT_READ | PROT_WRITE) == 0) {
                debug_print("Stomping memory...\n");
                // We will use this as base
                base = (size_t)mapped_mem;
                total_mapped_size = st_size;
              } else {
                debug_print("mprotect RW failed\n");
                munmap(mapped_mem, st_size);
                mapped_mem = NULL;
              }
            }
          } else {
            debug_print("Module file too small (%ld vs %ld)\n", (long)st_size,
                        (long)required_size);
          }
        }
        close(fd);
      } else {
        debug_print("Failed to open module path\n");
      }
    }

    if (!mapped_mem) {
      debug_print("Falling back to anonymous memory\n");
      // Let's just calculate total size and mmap a region
      size_t min_v = (size_t)-1, max_v = 0;
      for (int i = 0; i < hdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_memsz > 0) {
          size_t vstart = phdr[i].p_vaddr;
          size_t vend = vstart + phdr[i].p_memsz;
          if (vstart < min_v)
            min_v = vstart;
          if (vend > max_v)
            max_v = vend;
        }
      }
      size_t total_size = max_v - min_v;
      mapped_mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (mapped_mem == MAP_FAILED) {
        debug_print("Failed to allocate anonymous memory\n");
        return -1;
      }
      base = (size_t)mapped_mem;
      total_mapped_size = total_size;
    }

  } else {
    base = 0;
    debug_print("Static ELF, base set to 0\n");
  }

  if (base_addr != NULL)
    *base_addr = base; // Set base addr

  if (mapped_size != NULL) {
    *mapped_size = total_mapped_size;
  }

  // Use a fixed size array to avoid VLA issues
  struct {
    void *m;
    size_t size;
    int prot;
  } segments[64];
  int seg_count = 0;

  for (x = 0; x < hdr->e_phnum && seg_count < 64; x++) {
    if (phdr[x].p_type != PT_LOAD || !phdr[x].p_memsz)
      continue;

    void *map_start = (void *)ROUND_DOWN(phdr[x].p_vaddr, PAGE_SIZE);
    int round_down_size = (void *)phdr[x].p_vaddr - map_start;
    int map_size = ROUND_UP(phdr[x].p_memsz + round_down_size, PAGE_SIZE);
    int elf_prot = 0;

    if (phdr[x].p_flags & PF_R)
      elf_prot |= PROT_READ;
    if (phdr[x].p_flags & PF_W)
      elf_prot |= PROT_WRITE;
    if (phdr[x].p_flags & PF_X)
      elf_prot |= PROT_EXEC;

    debug_print("Mapping segment %d: vaddr 0x%lx, map_size %d, flags=%u\n", x,
                phdr[x].p_vaddr, map_size, phdr[x].p_flags);

    void *m = NULL;
    if (hdr->e_type == ET_DYN) {
      // For PIE, we copy into our pre-allocated/mapped region
      m = (void *)(base + (size_t)map_start);

      // If we are stomping (mapped_mem is set and it was mmapped from file),
      // OR if we are using anonymous memory (mapped_mem is set),
      // we already have the underlying memory.

      // However, we need to ensure permissions are RW for now.
      // For partial stomping (if we used mmap with file), the whole region is
      // RW.

      // Copy segment data
      memcpy((void *)base + phdr[x].p_vaddr, elf_start + phdr[x].p_offset,
             phdr[x].p_filesz);

      // Zero-out BSS
      if (phdr[x].p_memsz > phdr[x].p_filesz)
        memset((void *)(base + phdr[x].p_vaddr + phdr[x].p_filesz), 0,
               phdr[x].p_memsz - phdr[x].p_filesz);

    } else {
      // Static executable (ET_EXEC) - classic behavior
      if (!pre_mapped) {
        m = (void *)mmap((void *)(base + (size_t)map_start), map_size,
                         PROT_READ |
                             PROT_WRITE, // Map RW for loading/relocation
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if ((long)m < 0) {
          debug_print("mmap failed for segment %d at %p\n", x,
                      (void *)(base + (size_t)map_start));
          return -1;
        }
      } else {
        m = (void *)(base + (size_t)map_start);
      }

      memcpy((void *)base + phdr[x].p_vaddr, elf_start + phdr[x].p_offset,
             phdr[x].p_filesz);

      // Zero-out BSS
      if (phdr[x].p_memsz > phdr[x].p_filesz)
        memset((void *)(base + phdr[x].p_vaddr + phdr[x].p_filesz), 0,
               phdr[x].p_memsz - phdr[x].p_filesz);
    }

    segments[seg_count].m = m;
    segments[seg_count].size = map_size;
    segments[seg_count].prot = elf_prot;
    seg_count++;
  }

  // Perform relocations if PIE
  if (hdr->e_type == ET_DYN) {
    debug_print("Relocating...\n");
    elf_relocate(elf_start, base);

    // Seal the memory before applying segment permissions.
    // This ensures the "tail" (unused part of the stomped module) is not left
    // RW.
    if (mapped_mem) {
      mprotect(mapped_mem, total_mapped_size, PROT_READ);
    }
  }

  // Set proper protection on all sections
  for (int i = 0; i < seg_count; i++) {
    // For PIE, m is absolute address. For static, it is also absolute.
    if (mprotect(segments[i].m, segments[i].size, segments[i].prot) < 0) {
      debug_print("mprotect failed for segment %d\n", i);
    }
  }

  debug_print("elf_load finished\n");
  return 0;
}

int elf_run(void *buf, char **argv, char **env, int pre_mapped,
            const char *module_path, size_t base_addr) {
  debug_print("elf_run started\n");
  size_t x;
  int str_len;
  int str_ptr = 0;
  int stack_ptr = 1;
  int cnt = 0;
  size_t argc = 0;
  size_t envc = 0;

  Elf_Ehdr *hdr = (Elf_Ehdr *)buf;

  size_t elf_base = base_addr;
  size_t elf_entry = 0;

  char rand_bytes[16];

  // Fill in 16 random bytes for the loader below
  _get_rand(rand_bytes, 16);

  // First, let's count arguments...
  debug_print("Counting arguments, argv=%p, env=%p\n", argv, env);
  if (argv != NULL) {
    while (argv[argc])
      argc++;
  }
  debug_print("argc=%d\n", (int)argc);

  // ...and envs
  if (env != NULL) {
    while (env[envc])
      envc++;
  }
  debug_print("envc=%d\n", (int)envc);

  // Allocate some stack space
  debug_print("Allocating stack...\n");
  size_t setup_size = STACK_STORAGE_SIZE + STACK_STRING_SIZE;
  void *stack = __builtin_alloca(setup_size);
  if ((long)stack < 0) {
    debug_print("Failed to allocate stack\n");
    return -1;
  }
  debug_print("Stack allocated at %p\n", stack);

  // Map the ELF in memory
  if (elf_load(buf, stack, setup_size /* used to be STACK_SIZE */, &elf_base,
               &elf_entry, NULL, pre_mapped, module_path) < 0) {
    debug_print("elf_load failed\n");
    return -1;
  }
  elf_entry = elf_base + hdr->e_entry;
  debug_print("ELF loaded at 0x%lx, entry 0x%lx\n", elf_base, elf_entry);

  // Ensure 16-byte alignment as required by ABI
  unsigned long *stack_storage =
      (unsigned long *)(((unsigned long)stack + 15) & ~0xFl);
  char *string_storage = (char *)stack_storage + STACK_STORAGE_SIZE;

  // Zero out the whole stack storage area
  memset(stack_storage, 0, STACK_STORAGE_SIZE);

  unsigned long *s_argc = stack_storage;
  unsigned long *s_argv = &stack_storage[1];

  // Setup argc
  debug_print("Setting up stackargc=%d at %p\n", (int)argc, s_argc);
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
  at[cnt++].value = 0;
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
  // AT_HWCAP
  at[cnt].id = AT_HWCAP;
  at[cnt++].value = 0;
  // AT_HWCAP2
  at[cnt].id = AT_HWCAP2;
  at[cnt++].value = 0;
  // AT_CLKTCK
  at[cnt].id = AT_CLKTCK;
  at[cnt++].value = 100;

  // Try to find AT_SYSINFO_EHDR from our own environment
  // This is passed to us by the loader
  unsigned long *sp_ptr = (unsigned long *)argv;
  // Walk past argc, argv, envp to find auxv
  unsigned int p_argc = *--sp_ptr;
  sp_ptr++;             // argc
  sp_ptr += p_argc + 1; // skip argv
  while (*sp_ptr++)
    ; // skip envp

  // Now we are at auxv
  struct ATENTRY *p_at = (struct ATENTRY *)sp_ptr;
  for (; p_at->id != AT_NULL; p_at++) {
    if (p_at->id == 33) { // AT_SYSINFO_EHDR
      at[cnt].id = 33;
      at[cnt++].value = p_at->value;
      debug_print("Found and forwarded VDSO (AT_SYSINFO_EHDR) at 0x%lx\n",
                  p_at->value);
      break;
    }
  }

  // AT_SECURE (0 = not setuid/setgid)
  at[cnt].id = AT_SECURE;
  at[cnt++].value = 0;
  // AT_PLATFORM (architecture string)
  const char *platform = "x86_64";
  memcpy(&string_storage[str_ptr], platform, 7);
  at[cnt].id = AT_PLATFORM;
  at[cnt++].value = (size_t)&string_storage[str_ptr];
  str_ptr += 7;
  // AT_RANDOM (address of 16 random bytes)
  // Store random bytes in string storage so they persist
  memcpy(&string_storage[str_ptr], rand_bytes, 16);
  at[cnt].id = AT_RANDOM;
  at[cnt++].value = (size_t)&string_storage[str_ptr];
  str_ptr += 16;
  // AT_NULL
  at[cnt].id = AT_NULL;
  at[cnt++].value = 0;

  // Run constructors (Disabled again as they cause SIGSEGV with dynamic
  // payloads)
  /*
  if (init || init_array) {
    ...
  }
  */

  debug_print("Stack setup complete, jumping to entry point\n");
  debug_print("Stack storage: 0x%lx\n", (unsigned long)stack_storage);
  debug_print("Entry point: 0x%lx\n", (unsigned long)elf_entry);

  jump_start(stack_storage, (void *)_exit_func, (void *)elf_entry);

  // Shouldn't be reached, but just in case
  return -1;
}

#endif // __linux__
