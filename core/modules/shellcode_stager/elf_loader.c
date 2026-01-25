/*
 * adapted from https://github.com/malisal/loaders
 * */
#ifdef __linux__

#include "elf_loader.h"
#include "utils.h"
#include <elf.h>

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) debug_print("ELF: " fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...)
#endif

// Declare the jump_start function for all architectures
void jump_start(void *init, void *exit_func, void *entry);

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

#ifndef R_X86_64_RELATIVE
#define R_X86_64_RELATIVE 8
#endif

static void _relocate(size_t base, Elf_Ehdr *hdr, Elf_Phdr *phdr) {
  Elf_Dyn *dyn = NULL;
  size_t x;

  for (x = 0; x < hdr->e_phnum; x++) {
    if (phdr[x].p_type == PT_DYNAMIC) {
      dyn = (Elf_Dyn *)(base + phdr[x].p_vaddr);
      break;
    }
  }

  if (!dyn)
    return;

  Elf_Rela *rela = NULL;
  size_t relasz = 0;
  size_t relaent = 0;

  for (x = 0; dyn[x].d_tag != DT_NULL; x++) {
    if (dyn[x].d_tag == DT_RELA)
      rela = (Elf_Rela *)(base + dyn[x].d_un.d_ptr);
    if (dyn[x].d_tag == DT_RELASZ)
      relasz = dyn[x].d_un.d_val;
    if (dyn[x].d_tag == DT_RELAENT)
      relaent = dyn[x].d_un.d_val;
  }

  if (rela && relaent) {
    DEBUG_PRINT("Applying %d RELATIVE relocations\n", (int)(relasz / relaent));
    for (x = 0; x < relasz / relaent; x++) {
      if (ELF_R_TYPE(rela[x].r_info) == R_X86_64_RELATIVE) {
        size_t *ptr = (size_t *)(base + rela[x].r_offset);
        *ptr = base + rela[x].r_addend;
      } else {
        // Try to find symbol name
        size_t sym_idx = ELF_R_SYM(rela[x].r_info);
        const char *name = "unknown";
        
        // Find .dynsym/SHT_DYNSYM section to resolve sym_idx
        Elf_Ehdr *ehdr = (Elf_Ehdr *)hdr;
        Elf_Shdr *shdr = (Elf_Shdr *)((char *)ehdr + ehdr->e_shoff);
        for (int i = 0; i < ehdr->e_shnum; i++) {
            if (shdr[i].sh_type == SHT_DYNSYM) {
                Elf_Sym *syms = (Elf_Sym *)((char *)ehdr + shdr[i].sh_offset);
                const char *strings = (char *)ehdr + shdr[shdr[i].sh_link].sh_offset;
                name = strings + syms[sym_idx].st_name;
                break;
            }
        }

        DEBUG_PRINT("Unhandled relocation type %d at offset 0x%lx (sym: %s)\n", 
                    (int)ELF_R_TYPE(rela[x].r_info), (unsigned long)rela[x].r_offset, name);
      }
    }
  }
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
  size_t x, y;

  Elf_Ehdr *hdr = (Elf_Ehdr *)elf_start;
  Elf_Shdr *shdr = (Elf_Shdr *)(elf_start + hdr->e_shoff);

  // Try both SHT_SYMTAB and SHT_DYNSYM
  for (x = 0; x < hdr->e_shnum; x++) {
    if (shdr[x].sh_type == SHT_SYMTAB || shdr[x].sh_type == SHT_DYNSYM) {
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
  DEBUG_PRINT("elf_load started\n");
  Elf_Ehdr *hdr;
  Elf_Phdr *phdr;

  size_t x;
  int elf_prot = 0;
  int stack_prot = 0;
  size_t base;

  hdr = (Elf_Ehdr *)elf_start;
  phdr = (Elf_Phdr *)(elf_start + hdr->e_phoff);

  if (hdr->e_type == ET_DYN) {
    // If this is a DYNAMIC ELF (can be loaded anywhere), calculate total span
    size_t min_vaddr = (size_t)-1;
    size_t max_vaddr = 0;
    for (x = 0; x < hdr->e_phnum; x++) {
      if (phdr[x].p_type == PT_LOAD && phdr[x].p_memsz > 0) {
        if (phdr[x].p_vaddr < min_vaddr)
          min_vaddr = phdr[x].p_vaddr;
        if (phdr[x].p_vaddr + phdr[x].p_memsz > max_vaddr)
          max_vaddr = phdr[x].p_vaddr + phdr[x].p_memsz;
      }
    }

    if (min_vaddr == (size_t)-1) {
      DEBUG_PRINT("No loadable segments found\n");
      return -1;
    }

    size_t total_span = ROUND_UP(max_vaddr, PAGE_SIZE) - ROUND_DOWN(min_vaddr, PAGE_SIZE);
    DEBUG_PRINT("Calculating total ELF span: min=0x%lx, max=0x%lx, span=%d\n", min_vaddr, max_vaddr, (int)total_span);

    // Reserve the entire range to find a suitable base
    base = (size_t)mmap(0, total_span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)base < 0) {
        DEBUG_PRINT("Failed to reserve memory for ELF span\n");
        return -1;
    }
    // Optimization: we don't strictly need to munmap if we use MAP_FIXED later, 
    // but it's cleaner to know it's a hole. Actually, keeping it mapped PROT_NONE 
    // and using MAP_FIXED overwrite is safer on some systems.
    munmap((void *)base, total_span);
    
    // adjust base relative to min_vaddr if min_vaddr is not 0
    base -= ROUND_DOWN(min_vaddr, PAGE_SIZE);

    DEBUG_PRINT("Dynamic ELF, base set to 0x%lx (reserved span)\n", base);
  } else {
    base = 0;
    DEBUG_PRINT("Static ELF, base set to 0\n");
  }

  if (base_addr != NULL)
    *base_addr = -1;

  if (entry != NULL) {
    *entry = base + hdr->e_entry;
    DEBUG_PRINT("Entry point set to 0x%lx\n", *entry);
  }

  struct {
    void *m;
    size_t size;
    int prot;
  } segments[hdr->e_phnum];
  int seg_count = 0;

  for (x = 0; x < hdr->e_phnum; x++) {
    if (phdr[x].p_type != PT_LOAD || !phdr[x].p_memsz)
      continue;

    void *map_start = (void *)ROUND_DOWN(phdr[x].p_vaddr, PAGE_SIZE);
    int round_down_size = (void *)phdr[x].p_vaddr - map_start;
    int map_size = ROUND_UP(phdr[x].p_memsz + round_down_size, PAGE_SIZE);
    int elf_prot = 0;

    if (phdr[x].p_flags & PF_R) elf_prot |= PROT_READ;
    if (phdr[x].p_flags & PF_W) elf_prot |= PROT_WRITE;
    if (phdr[x].p_flags & PF_X) elf_prot |= PROT_EXEC;

    DEBUG_PRINT("Mapping segment %d: vaddr 0x%lx, map_size %d, flags=%u\n", x,
                phdr[x].p_vaddr, map_size, phdr[x].p_flags);

    void *m = (void *)mmap((void *)(base + (size_t)map_start), map_size,
                           PROT_READ | PROT_WRITE, // Map RW for loading/relocation
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if ((long)m < 0) {
      DEBUG_PRINT("mmap failed for segment %d at %p\n", x, (void*)(base + (size_t)map_start));
      return -1;
    }

    memcpy((void *)base + phdr[x].p_vaddr, elf_start + phdr[x].p_offset, phdr[x].p_filesz);

    // Zero-out BSS
    if (phdr[x].p_memsz > phdr[x].p_filesz)
      memset((void *)(base + phdr[x].p_vaddr + phdr[x].p_filesz), 0,
             phdr[x].p_memsz - phdr[x].p_filesz);

    segments[seg_count].m = m;
    segments[seg_count].size = map_size;
    segments[seg_count].prot = elf_prot;
    seg_count++;

    if (base_addr != NULL && (*base_addr == (size_t)-1 || *base_addr > (size_t)m))
      *base_addr = (size_t)m;
  }

  // Apply relocations while memory is still RW
  if (hdr->e_type == ET_DYN) {
    _relocate(base, hdr, phdr);
  }

  // Set proper protection on all sections
  for (int i = 0; i < seg_count; i++) {
    if (mprotect(segments[i].m, segments[i].size, segments[i].prot) < 0) {
      DEBUG_PRINT("mprotect failed for segment %d\n", i);
    }
  }

  DEBUG_PRINT("elf_load finished\n");
  return 0;
}

int elf_run(void *buf, char **argv, char **env) {
  DEBUG_PRINT("elf_run started\n");
  size_t x;
  int str_len;
  int str_ptr = 0;
  int stack_ptr = 1;
  int cnt = 0;
  size_t argc = 0;
  size_t envc = 0;

  Elf_Ehdr *hdr = (Elf_Ehdr *)buf;

  size_t elf_base, elf_entry;
  size_t interp_base = 0;
  size_t interp_entry = 0;

  char rand_bytes[16];

  // Fill in 16 random bytes for the loader below
  _get_rand(rand_bytes, 16);

  int (*ptr)(int, char **, char **);

  // First, let's count arguments...
  DEBUG_PRINT("Counting arguments, argv=%p, env=%p\n", argv, env);
  if (argv != NULL) {
    while (argv[argc])
      argc++;
  }
  DEBUG_PRINT("argc=%d\n", (int)argc);

  // ...and envs
  if (env != NULL) {
    while (env[envc])
      envc++;
  }
  DEBUG_PRINT("envc=%d\n", (int)envc);

  // Allocate some stack space
  DEBUG_PRINT("Allocating stack...\n");
  void *stack = (void *)mmap(0, STACK_SIZE, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if ((long)stack < 0) {
    DEBUG_PRINT("Failed to allocate stack\n");
    return -1;
  }
  DEBUG_PRINT("Stack allocated at %p\n", stack);

  // Map the ELF in memory
  if (elf_load(buf, stack, STACK_SIZE, &elf_base, &elf_entry) < 0) {
    DEBUG_PRINT("elf_load failed\n");
    return -1;
  }
  DEBUG_PRINT("ELF loaded at 0x%lx, entry 0x%lx\n", elf_base, elf_entry);

  // Check if this is a shared object and find main symbol
  int is_shared_object = 0;
  size_t main_addr = 0;
  
  if (hdr->e_type == ET_DYN) {
    // For shared objects, try to find the main symbol
    void *main_sym = elf_sym(buf, "main");
    if (main_sym != NULL) {
      is_shared_object = 1;
      main_addr = elf_base + (size_t)main_sym;
      DEBUG_PRINT("Found main symbol at 0x%lx (base + 0x%lx)\n", 
                  main_addr, (size_t)main_sym);
    }
  }

  // Zero out the whole stack, Justin Case
  memset(stack, 0, STACK_STORAGE_SIZE);

  unsigned long *stack_storage =
      stack + STACK_SIZE - STACK_STORAGE_SIZE - STACK_STRING_SIZE;
  char *string_storage = stack + STACK_SIZE - STACK_STRING_SIZE;

  unsigned long *s_argc = stack_storage;
  unsigned long *s_argv = &stack_storage[1];

  // Setup argc
  DEBUG_PRINT("Setting up stackargc=%d at %p\n", (int)argc, s_argc);
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
    DEBUG_PRINT("Running .init constructor at 0x%lx\n", base + init->sh_addr);
    ptr = (int (*)(int, char **, char **))(base + init->sh_addr);
    ptr(argc, argv, env);
    DEBUG_PRINT(".init constructor finished\n");
  }

  if (init_array) {
    DEBUG_PRINT("Running %d .init_array constructors\n", (int)(init_array->sh_size / sizeof(void *)));
    for (x = 0; x < init_array->sh_size / sizeof(void *); x++) {
      size_t func_addr = *((size_t *)(base + init_array->sh_addr + (x * sizeof(void *))));
      DEBUG_PRINT("Running .init_array[%d] at 0x%lx\n", (int)x, func_addr);
      ptr = (int (*)(int, char **, char **))func_addr;
      ptr(argc, argv, env);
    }
    DEBUG_PRINT(".init_array constructors finished\n");
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

  DEBUG_PRINT("Stack setup complete, jumping to entry point\n");
  DEBUG_PRINT("Stack storage: 0x%lx\n", (unsigned long)stack_storage);
  DEBUG_PRINT("Entry point: 0x%lx\n", (unsigned long)(interp_entry ? interp_entry : elf_entry));
  DEBUG_PRINT("Is shared object: %d, Main addr: 0x%lx\n", is_shared_object, main_addr);

  // For shared objects with main symbol, call main() directly
  if (is_shared_object && main_addr != 0) {
    DEBUG_PRINT("Calling main() at 0x%lx for shared object\n", main_addr);
    
    // Switch to our prepared stack before calling main
    // This is crucial for Go runtime to find AuxV
    int ret;
    __asm__ __volatile__(
        "mov %%rsp, %%r15\n" // Save current sp
        "mov %1, %%rsp\n"    // Switch to new sp
        "mov %2, %%rdi\n"    // argc
        "mov %3, %%rsi\n"    // argv
        "mov %4, %%rdx\n"    // envp
        "call *%5\n"         // Call main
        "mov %%r15, %%rsp\n" // Restore sp
        "mov %%eax, %0\n"    // Get return value
        : "=r"(ret)
        : "r"(stack_storage), "r"((long)argc), "r"(argv), "r"(env), "r"(main_addr)
        : "r15", "rax", "rdi", "rsi", "rdx", "memory"
    );
    
    DEBUG_PRINT("main() returned %d\n", ret);
    exit(ret);
  }

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

#endif // __linux__
