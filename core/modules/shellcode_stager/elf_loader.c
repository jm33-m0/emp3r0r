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
    // We do NOT support ET_DYN (Shared Objects / PIE) anymore in this stager
    // because providing a correct environment (libc, loader) is too complex.
    DEBUG_PRINT("Error: ET_DYN not supported. Please use static ELF executable.\n");
    return -1;
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


  if (hdr->e_type == ET_DYN) {
      DEBUG_PRINT("Error: Shared Objects not supported.\n");
      return -1;
  }

  unsigned long *stack_storage =
      stack + STACK_SIZE - STACK_STORAGE_SIZE - STACK_STRING_SIZE;

  // Zero out the whole stack storage area
  memset(stack_storage, 0, STACK_STORAGE_SIZE);
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


  size_t base = 0;




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
  sp_ptr++; // argc
  sp_ptr += p_argc + 1; // skip argv
  while (*sp_ptr++) ; // skip envp
  
  // Now we are at auxv
  struct ATENTRY *p_at = (struct ATENTRY *)sp_ptr;
  for (; p_at->id != AT_NULL; p_at++) {
      if (p_at->id == 33) { // AT_SYSINFO_EHDR
          at[cnt].id = 33;
          at[cnt++].value = p_at->value;
          DEBUG_PRINT("Found and forwarded VDSO (AT_SYSINFO_EHDR) at 0x%lx\n", p_at->value);
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

  // Run constructors (Disabled again as they cause SIGSEGV with dynamic payloads)
  /*
  if (init || init_array) {
    ...
  }
  */

  DEBUG_PRINT("Stack setup complete, jumping to entry point\n");
  DEBUG_PRINT("Stack storage: 0x%lx\n", (unsigned long)stack_storage);
  DEBUG_PRINT("Entry point: 0x%lx\n", (unsigned long)(interp_entry ? interp_entry : elf_entry));




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
