#include "syscalls.h"

/* ---- vDSO gadget resolution (called once from init) ---- */

/*
 * All resolution functions are noinline and called only from
 * init_indirect_syscalls(). They never run inside a syscall wrapper
 * context, so there are no register-clobbering concerns.
 */

static __attribute__((noinline)) void *
_scan_for_syscall_ret(const unsigned char *base, unsigned long len) {
  if (len < 3)
    return (void *)0;
  for (unsigned long i = 0; i <= len - 3; i++) {
    if (base[i] == 0x0F && base[i + 1] == 0x05 && base[i + 2] == 0xC3) {
      return (void *)(base + i);
    }
  }
  return (void *)0;
}

static __attribute__((noinline)) void *_scan_vdso(unsigned long vdso_base) {
  Syscall_Elf64_Ehdr *ehdr = (Syscall_Elf64_Ehdr *)vdso_base;

  /* Validate ELF magic */
  if (ehdr->e_ident[0] != ELFMAG0 || ehdr->e_ident[1] != ELFMAG1 ||
      ehdr->e_ident[2] != ELFMAG2 || ehdr->e_ident[3] != ELFMAG3) {
    return (void *)0;
  }

  Syscall_Elf64_Phdr *phdr = (Syscall_Elf64_Phdr *)(vdso_base + ehdr->e_phoff);

  /* Scan executable segments for the gadget */
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD_TYPE && (phdr[i].p_flags & PF_X_FLAG)) {
      const unsigned char *seg_base =
          (const unsigned char *)(vdso_base + phdr[i].p_offset);
      void *gadget = _scan_for_syscall_ret(seg_base, phdr[i].p_filesz);
      if (gadget)
        return gadget;
    }
  }
  return (void *)0;
}

/* Use the embedded gadget for bootstrap syscalls */
__attribute__((noinline)) void init_indirect_syscalls(void) {
  /* Use the embedded gadget for bootstrap syscalls */
  void *boot_gadget = get_embedded_syscall_gadget();

  unsigned long ret;
  long fd;
  long bytes_read;
  unsigned long buf[64]; /* 32 entries, each is {type, value} */

  /* Open /proc/self/auxv */
  char auxv_path[] = {'/', 'p', 'r', 'o', 'c', '/', 's', 'e',
                      'l', 'f', '/', 'a', 'u', 'x', 'v', '\0'};
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(boot_gadget), "a"((long)SYS_open),
                         "D"((long)auxv_path), "S"((long)0), "d"((long)0)
                       : "rcx", "r11", "memory");
  fd = (long)ret;
  if (fd < 0)
    goto fallback;

  /* Read auxv entries */
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(boot_gadget), "a"((long)SYS_read), "D"((long)fd),
                         "S"((long)buf), "d"((long)sizeof(buf))
                       : "rcx", "r11", "memory");
  bytes_read = (long)ret;

  /* Close fd */
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(boot_gadget), "a"((long)SYS_close), "D"((long)fd)
                       : "rcx", "r11", "memory");

  if (bytes_read <= 0)
    goto fallback;

  /* Parse auxv for AT_SYSINFO_EHDR */
  {
    unsigned long num_longs = (unsigned long)bytes_read / sizeof(unsigned long);
    for (unsigned long i = 0; i + 1 < num_longs; i += 2) {
      if (buf[i] == AT_SYSINFO_EHDR) {
        void *gadget = _scan_vdso(buf[i + 1]);
        if (gadget) {
          _cached_syscall_gadget = gadget;
          return;
        }
        break;
      }
      if (buf[i] == AT_NULL_TYPE)
        break;
    }
  }

fallback:
  _cached_syscall_gadget = boot_gadget;
}
