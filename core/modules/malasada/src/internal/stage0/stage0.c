// malasada stage0 loader
//
// This is a small freestanding ELF runner used as "shellcode". It expects the
// output format produced by the malasada CLI:
//   [stage0 .text blob (this file)] [msda header] [ELF payload bytes]
//
// At runtime it:
//  1) maps the embedded ELF payload into memory
//  2) maps the system dynamic loader (ld-linux) from disk
//  3) builds a new initial stack + auxv
//  4) jumps to the dynamic loader entrypoint with the new stack
//
// It intentionally avoids memfd.

#include <stddef.h>
#include <stdint.h>

// -----------------------------
// Minimal Linux constants/types
// -----------------------------

#define EI_NIDENT 16

// ELF constants (subset)
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

#define ELFCLASS32 1
#define ELFCLASS64 2
#define ELFDATA2LSB 1

#define ET_DYN 3

#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3

#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

// auxv tags (subset)
#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_ENTRY 9

// openat(2)
#define AT_FDCWD -100

// mmap(2)
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20
#define MAP_GROWSDOWN 0x0100

// lseek(2)
#define SEEK_SET 0
#define SEEK_END 2

// fcntl(2)
#define O_RDONLY 0

// Hardcode the page size to keep stage0 small.
#define PAGE_SIZE 0x1000u

static inline int is_syscall_err_ptr(const void *p);

#if defined(__i386__)
typedef uint32_t Elf_Addr;
typedef uint32_t Elf_Off;
typedef uint16_t Elf_Half;
typedef uint32_t Elf_Word;

typedef struct {
  unsigned char e_ident[EI_NIDENT];
  Elf_Half e_type;
  Elf_Half e_machine;
  Elf_Word e_version;
  Elf_Addr e_entry;
  Elf_Off e_phoff;
  Elf_Off e_shoff;
  Elf_Word e_flags;
  Elf_Half e_ehsize;
  Elf_Half e_phentsize;
  Elf_Half e_phnum;
  Elf_Half e_shentsize;
  Elf_Half e_shnum;
  Elf_Half e_shstrndx;
} Elf_Ehdr;

typedef struct {
  Elf_Word p_type;
  Elf_Off p_offset;
  Elf_Addr p_vaddr;
  Elf_Addr p_paddr;
  Elf_Word p_filesz;
  Elf_Word p_memsz;
  Elf_Word p_flags;
  Elf_Word p_align;
} Elf_Phdr;

#define ELFCLASS_NATIVE ELFCLASS32

#else

typedef uint64_t Elf_Addr;
typedef uint64_t Elf_Off;
typedef uint16_t Elf_Half;
typedef uint32_t Elf_Word;
typedef uint64_t Elf_Xword;

typedef struct {
  unsigned char e_ident[EI_NIDENT];
  Elf_Half e_type;
  Elf_Half e_machine;
  Elf_Word e_version;
  Elf_Addr e_entry;
  Elf_Off e_phoff;
  Elf_Off e_shoff;
  Elf_Word e_flags;
  Elf_Half e_ehsize;
  Elf_Half e_phentsize;
  Elf_Half e_phnum;
  Elf_Half e_shentsize;
  Elf_Half e_shnum;
  Elf_Half e_shstrndx;
} Elf_Ehdr;

typedef struct {
  Elf_Word p_type;
  Elf_Word p_flags;
  Elf_Off p_offset;
  Elf_Addr p_vaddr;
  Elf_Addr p_paddr;
  Elf_Xword p_filesz;
  Elf_Xword p_memsz;
  Elf_Xword p_align;
} Elf_Phdr;

#define ELFCLASS_NATIVE ELFCLASS64

#endif

// -----------------------------
// arch-specific syscall glue
// -----------------------------

#if defined(__x86_64__)
#define MSDA_ARCH_ID 1u

static inline long sys_call6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
  long ret;
  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;
  __asm__ volatile(
      "syscall"
      : "=a"(ret)
      : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
      : "rcx", "r11", "memory");
  return ret;
}

static inline long sys_call4(long n, long a1, long a2, long a3, long a4) {
  return sys_call6(n, a1, a2, a3, a4, 0, 0);
}

static inline long sys_call3(long n, long a1, long a2, long a3) {
  return sys_call6(n, a1, a2, a3, 0, 0, 0);
}

static inline long sys_call2(long n, long a1, long a2) { return sys_call6(n, a1, a2, 0, 0, 0, 0); }
static inline long sys_call1(long n, long a1) { return sys_call6(n, a1, 0, 0, 0, 0, 0); }

// syscall numbers (x86_64)
#define __NR_read       0
#define __NR_write      1
#define __NR_close      3
#define __NR_lseek      8
#define __NR_mmap       9
#define __NR_mprotect   10
#define __NR_munmap     11
#define __NR_openat     257
#define __NR_exit_group 231

static inline void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, uint64_t off) {
  return (void *)sys_call6(__NR_mmap, (long)addr, (long)len, prot, flags, fd, (long)off);
}

static inline long sys_mprotect(void *addr, size_t len, int prot) {
  return sys_call3(__NR_mprotect, (long)addr, (long)len, prot);
}

static inline long sys_munmap(void *addr, size_t len) { return sys_call2(__NR_munmap, (long)addr, (long)len); }

static inline long sys_openat(int dirfd, const char *path, int flags, int mode) {
  return sys_call4(__NR_openat, (long)dirfd, (long)path, flags, mode);
}

static inline long sys_read(int fd, void *buf, size_t len) { return sys_call3(__NR_read, fd, (long)buf, (long)len); }
static inline long sys_write(int fd, const void *buf, size_t len) { return sys_call3(__NR_write, fd, (long)buf, (long)len); }
static inline long sys_close(int fd) { return sys_call1(__NR_close, fd); }
static inline long sys_lseek(int fd, long off, int whence) { return sys_call3(__NR_lseek, fd, off, whence); }

__attribute__((noreturn)) static inline void sys_exit_group(int code) {
  (void)sys_call1(__NR_exit_group, code);
  for (;;) {
  }
}

static inline void jump_with_stack(uintptr_t dest, uintptr_t *new_stack) {
  __asm__ volatile(
      "movq %[stack], %%rsp\n"
      "movq %[stack], %%rdi\n"
      "xor %%rdx, %%rdx\n"
      "jmp *%[entry]\n"
      :
      : [stack] "r"(new_stack), [entry] "r"(dest)
      : "rdi", "rdx", "memory");
}

#elif defined(__i386__)
#define MSDA_ARCH_ID 3u

static inline long sys_call1(long n, long a1) {
  long ret;
  __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "b"(a1) : "cc", "memory");
  return ret;
}

static inline long sys_call2(long n, long a1, long a2) {
  long ret;
  __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "b"(a1), "c"(a2) : "cc", "memory");
  return ret;
}

static inline long sys_call3(long n, long a1, long a2, long a3) {
  long ret;
  __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3) : "cc", "memory");
  return ret;
}

static inline long sys_call4(long n, long a1, long a2, long a3, long a4) {
  long ret;
  __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4) : "cc", "memory");
  return ret;
}

// syscall numbers (i386)
#define __NR_read       3
#define __NR_write      4
#define __NR_close      6
#define __NR_lseek      19
#define __NR_mmap       90
#define __NR_mprotect   125
#define __NR_munmap     91
#define __NR_openat     295
#define __NR_exit_group 252

struct mmap_arg_struct {
  unsigned long addr;
  unsigned long len;
  unsigned long prot;
  unsigned long flags;
  unsigned long fd;
  unsigned long offset;
};

static inline void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, uint64_t off) {
  // i386 __NR_mmap takes a pointer to mmap_arg_struct.
  if (off > 0xffffffffull) {
    return (void *)(long)-22; // -EINVAL
  }
  struct mmap_arg_struct args = {
      .addr = (unsigned long)addr,
      .len = (unsigned long)len,
      .prot = (unsigned long)prot,
      .flags = (unsigned long)flags,
      .fd = (unsigned long)fd,
      .offset = (unsigned long)off,
  };
  return (void *)sys_call1(__NR_mmap, (long)&args);
}

static inline long sys_mprotect(void *addr, size_t len, int prot) { return sys_call3(__NR_mprotect, (long)addr, (long)len, prot); }
static inline long sys_munmap(void *addr, size_t len) { return sys_call2(__NR_munmap, (long)addr, (long)len); }
static inline long sys_openat(int dirfd, const char *path, int flags, int mode) {
  return sys_call4(__NR_openat, (long)dirfd, (long)path, flags, mode);
}
static inline long sys_read(int fd, void *buf, size_t len) { return sys_call3(__NR_read, fd, (long)buf, (long)len); }
static inline long sys_write(int fd, const void *buf, size_t len) { return sys_call3(__NR_write, fd, (long)buf, (long)len); }
static inline long sys_close(int fd) { return sys_call1(__NR_close, fd); }
static inline long sys_lseek(int fd, long off, int whence) { return sys_call3(__NR_lseek, fd, off, whence); }

__attribute__((noreturn)) static inline void sys_exit_group(int code) {
  (void)sys_call1(__NR_exit_group, code);
  for (;;) {
  }
}

static inline void jump_with_stack(uintptr_t dest, uintptr_t *new_stack) {
  __asm__ volatile(
      "movl %[stack], %%esp\n"
      "xorl %%edx, %%edx\n"
      "jmp *%[entry]\n"
      :
      : [stack] "r"(new_stack), [entry] "r"(dest)
      : "edx", "memory");
}

#elif defined(__aarch64__)
#define MSDA_ARCH_ID 2u

static inline long sys_call6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
  register long x8 __asm__("x8") = n;
  register long x0 __asm__("x0") = a1;
  register long x1 __asm__("x1") = a2;
  register long x2 __asm__("x2") = a3;
  register long x3 __asm__("x3") = a4;
  register long x4 __asm__("x4") = a5;
  register long x5 __asm__("x5") = a6;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
  return x0;
}

static inline long sys_call4(long n, long a1, long a2, long a3, long a4) {
  return sys_call6(n, a1, a2, a3, a4, 0, 0);
}

static inline long sys_call3(long n, long a1, long a2, long a3) { return sys_call6(n, a1, a2, a3, 0, 0, 0); }
static inline long sys_call2(long n, long a1, long a2) { return sys_call6(n, a1, a2, 0, 0, 0, 0); }
static inline long sys_call1(long n, long a1) { return sys_call6(n, a1, 0, 0, 0, 0, 0); }

// syscall numbers (aarch64)
#define __NR_read       63
#define __NR_write      64
#define __NR_close      57
#define __NR_lseek      62
#define __NR_mmap       222
#define __NR_mprotect   226
#define __NR_munmap     215
#define __NR_openat     56
#define __NR_exit_group 94

static inline void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, uint64_t off) {
  return (void *)sys_call6(__NR_mmap, (long)addr, (long)len, prot, flags, fd, (long)off);
}
static inline long sys_mprotect(void *addr, size_t len, int prot) { return sys_call3(__NR_mprotect, (long)addr, (long)len, prot); }
static inline long sys_munmap(void *addr, size_t len) { return sys_call2(__NR_munmap, (long)addr, (long)len); }
static inline long sys_openat(int dirfd, const char *path, int flags, int mode) {
  return sys_call4(__NR_openat, (long)dirfd, (long)path, flags, mode);
}
static inline long sys_read(int fd, void *buf, size_t len) { return sys_call3(__NR_read, fd, (long)buf, (long)len); }
static inline long sys_write(int fd, const void *buf, size_t len) { return sys_call3(__NR_write, fd, (long)buf, (long)len); }
static inline long sys_close(int fd) { return sys_call1(__NR_close, fd); }
static inline long sys_lseek(int fd, long off, int whence) { return sys_call3(__NR_lseek, fd, off, whence); }

__attribute__((noreturn)) static inline void sys_exit_group(int code) {
  (void)sys_call1(__NR_exit_group, code);
  for (;;) {
  }
}

static inline void jump_with_stack(uintptr_t dest, uintptr_t *new_stack) {
  __asm__ volatile(
      "mov sp, %[stack]\n"
      "mov x0, %[stack]\n"
      "br %[entry]\n"
      :
      : [stack] "r"(new_stack), [entry] "r"(dest)
      : "x0", "memory");
}

static inline void clear_cache(void *start, void *end) {
  __builtin___clear_cache((char *)start, (char *)end);
}

#else
#error "Unsupported architecture (stage0 supports linux amd64, arm64, and 386 only)"
#endif

// -----------------------------
// Tiny debug print helper
// -----------------------------

#if defined(MALASADA_STAGE0_DEBUG)
static inline size_t cstrlen(const char *s) {
  size_t n = 0;
  while (s[n]) n++;
  return n;
}

static inline void dbg(const char *s) {
  (void)sys_write(2, s, cstrlen(s));
}

#define DBG(msg) dbg(msg)
#else
#define DBG(msg) ((void)0)
#endif

// -----------------------------
// Embedded constants (.text)
// -----------------------------

static inline void keep_ptr(const volatile void *p) { __asm__ volatile("" ::"r"(p)); }

__attribute__((section(".text"), aligned(1))) static const char path_auxv[] = "/proc/self/auxv";

#if defined(__x86_64__)
__attribute__((section(".text"), aligned(1))) static const char path_ld_linux[] = "/lib64/ld-linux-x86-64.so.2";
__attribute__((section(".text"), aligned(1))) static const char path_ld_linux_alt[] = "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";
#elif defined(__aarch64__)
__attribute__((section(".text"), aligned(1))) static const char path_ld_linux[] = "/lib/ld-linux-aarch64.so.1";
__attribute__((section(".text"), aligned(1))) static const char path_ld_linux_alt[] = "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1";
#elif defined(__i386__)
__attribute__((section(".text"), aligned(1))) static const char path_ld_linux[] = "/lib/ld-linux.so.2";
__attribute__((section(".text"), aligned(1))) static const char path_ld_linux_alt[] = "/lib/i386-linux-gnu/ld-linux.so.2";
#endif

// -----------------------------
// MSDA header (must be last)
// -----------------------------

struct msda_header {
  char magic[8]; // "MALASADA"
  uint32_t version;
  uint32_t arch;
  uint64_t payload_len; // patched by the Go CLI
};

// Place in its own input section so the linker script can force it last.
//
// NOTE: This header is patched by the Go CLI before execution, so it must not
// be treated as a compile-time constant. Marking it volatile prevents the
// compiler from constant-folding checks like `payload_len == 0` (which would
// otherwise dead-code-eliminate the actual loader).
__attribute__((section(".msda"), used, aligned(1))) static volatile struct msda_header g_msda = {
    .magic = {'M', 'A', 'L', 'A', 'S', 'A', 'D', 'A'},
    .version = 1,
    .arch = MSDA_ARCH_ID,
    .payload_len = 0,
};

// -----------------------------
// Optional aPLib depacker (AP32 safe header)
// -----------------------------

#define AP32_SAFE_TAG0 'A'
#define AP32_SAFE_TAG1 'P'
#define AP32_SAFE_TAG2 '3'
#define AP32_SAFE_TAG3 '2'
#define AP32_SAFE_HEADER_SIZE 24u

#ifndef APLIB_ERROR
#define APLIB_ERROR ((unsigned int)(-1))
#endif

static inline uint32_t u32le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline int is_ap32_safe(const uint8_t *p, uint64_t n) {
  if (n < 4) return 0;
  return p[0] == AP32_SAFE_TAG0 && p[1] == AP32_SAFE_TAG1 && p[2] == AP32_SAFE_TAG2 && p[3] == AP32_SAFE_TAG3;
}

/* aPLib "safe" depacker (bounds-checked), adapted from Joergen Ibsen's depacks.c. */
struct APDSSTATE {
  const unsigned char *source;
  unsigned int srclen;
  unsigned char *destination;
  unsigned int dstlen;
  unsigned int tag;
  unsigned int bitcount;
};

static int aP_getbit_safe(struct APDSSTATE *ud, unsigned int *result) {
  unsigned int bit;
  if (!ud->bitcount--) {
    if (!ud->srclen--) {
      return 0;
    }
    ud->tag = *ud->source++;
    ud->bitcount = 7;
  }
  bit = (ud->tag >> 7) & 0x01;
  ud->tag <<= 1;
  *result = bit;
  return 1;
}

static int aP_getgamma_safe(struct APDSSTATE *ud, unsigned int *result) {
  unsigned int bit;
  unsigned int v = 1;
  do {
    if (!aP_getbit_safe(ud, &bit)) {
      return 0;
    }
    if (v & 0x80000000) {
      return 0;
    }
    v = (v << 1) + bit;
    if (!aP_getbit_safe(ud, &bit)) {
      return 0;
    }
  } while (bit);
  *result = v;
  return 1;
}

static unsigned int aP_depack_safe(const void *source, unsigned int srclen, void *destination, unsigned int dstlen) {
  struct APDSSTATE ud;
  unsigned int offs, len, R0, LWM, bit;
  int done;
  int i;

  if (!source || !destination) {
    return APLIB_ERROR;
  }

  ud.source = (const unsigned char *)source;
  ud.srclen = srclen;
  ud.destination = (unsigned char *)destination;
  ud.dstlen = dstlen;
  ud.bitcount = 0;

  R0 = (unsigned int)-1;
  LWM = 0;
  done = 0;

  if (!ud.srclen-- || !ud.dstlen--) {
    return APLIB_ERROR;
  }
  *ud.destination++ = *ud.source++;

  while (!done) {
    if (!aP_getbit_safe(&ud, &bit)) {
      return APLIB_ERROR;
    }

    if (bit) {
      if (!aP_getbit_safe(&ud, &bit)) {
        return APLIB_ERROR;
      }

      if (bit) {
        if (!aP_getbit_safe(&ud, &bit)) {
          return APLIB_ERROR;
        }

        if (bit) {
          offs = 0;

          for (i = 4; i; i--) {
            if (!aP_getbit_safe(&ud, &bit)) {
              return APLIB_ERROR;
            }
            offs = (offs << 1) + bit;
          }

          if (offs) {
            if (offs > (dstlen - ud.dstlen)) {
              return APLIB_ERROR;
            }

            if (!ud.dstlen--) {
              return APLIB_ERROR;
            }

            *ud.destination = *(ud.destination - offs);
            ud.destination++;
          } else {
            if (!ud.dstlen--) {
              return APLIB_ERROR;
            }

            *ud.destination++ = 0x00;
          }

          LWM = 0;
        } else {
          if (!ud.srclen--) {
            return APLIB_ERROR;
          }

          offs = *ud.source++;

          len = 2 + (offs & 0x0001);

          offs >>= 1;

          if (offs) {
            if (offs > (dstlen - ud.dstlen)) {
              return APLIB_ERROR;
            }

            if (len > ud.dstlen) {
              return APLIB_ERROR;
            }

            ud.dstlen -= len;

            for (; len; len--) {
              *ud.destination = *(ud.destination - offs);
              ud.destination++;
            }
          } else {
            done = 1;
          }

          R0 = offs;
          LWM = 1;
        }
      } else {
        if (!aP_getgamma_safe(&ud, &offs)) {
          return APLIB_ERROR;
        }

        if ((LWM == 0) && (offs == 2)) {
          offs = R0;

          if (!aP_getgamma_safe(&ud, &len)) {
            return APLIB_ERROR;
          }

          if (offs > (dstlen - ud.dstlen)) {
            return APLIB_ERROR;
          }

          if (len > ud.dstlen) {
            return APLIB_ERROR;
          }

          ud.dstlen -= len;

          for (; len; len--) {
            *ud.destination = *(ud.destination - offs);
            ud.destination++;
          }
        } else {
          if (LWM == 0) {
            offs -= 3;
          } else {
            offs -= 2;
          }

          if (offs > 0x00fffffe) {
            return APLIB_ERROR;
          }

          if (!ud.srclen--) {
            return APLIB_ERROR;
          }

          offs <<= 8;
          offs += *ud.source++;

          if (!aP_getgamma_safe(&ud, &len)) {
            return APLIB_ERROR;
          }

          if (offs >= 32000) {
            len++;
          }
          if (offs >= 1280) {
            len++;
          }
          if (offs < 128) {
            len += 2;
          }

          if (offs > (dstlen - ud.dstlen)) {
            return APLIB_ERROR;
          }

          if (len > ud.dstlen) {
            return APLIB_ERROR;
          }

          ud.dstlen -= len;

          for (; len; len--) {
            *ud.destination = *(ud.destination - offs);
            ud.destination++;
          }

          R0 = offs;
        }

        LWM = 1;
      }
    } else {
      if (!ud.srclen-- || !ud.dstlen--) {
        return APLIB_ERROR;
      }
      *ud.destination++ = *ud.source++;
      LWM = 0;
    }
  }

  return (unsigned int)(ud.destination - (unsigned char *)destination);
}

static int depack_ap32_safe(const uint8_t *src, uint64_t src_len, uint8_t **out_buf, uint64_t *out_len) {
  if (src_len < AP32_SAFE_HEADER_SIZE) {
    return 0;
  }

  uint32_t header_size = u32le(src + 4);
  uint32_t packed_size = u32le(src + 8);
  uint32_t orig_size = u32le(src + 16);

  if (header_size < AP32_SAFE_HEADER_SIZE || (uint64_t)header_size > src_len) {
    return 0;
  }
  if ((uint64_t)header_size + (uint64_t)packed_size > src_len) {
    return 0;
  }
  if (orig_size == 0 || orig_size > (256u * 1024u * 1024u)) {
    return 0;
  }

  uint8_t *dst = (uint8_t *)sys_mmap(NULL, (size_t)orig_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (is_syscall_err_ptr(dst)) {
    return 0;
  }

  const uint8_t *body = src + header_size;
  unsigned int dec_sz = aP_depack_safe(body, packed_size, dst, orig_size);
  if (dec_sz == APLIB_ERROR || dec_sz != orig_size) {
    (void)sys_munmap(dst, (size_t)orig_size);
    return 0;
  }

  *out_buf = dst;
  *out_len = (uint64_t)orig_size;
  return 1;
}

// -----------------------------
// tiny libc replacements
// -----------------------------

static void *memcpy8(void *dst, const void *src, size_t n) {
  uint8_t *d = (uint8_t *)dst;
  const uint8_t *s = (const uint8_t *)src;
  for (size_t i = 0; i < n; i++) {
    d[i] = s[i];
  }
  return dst;
}

static void *memset8(void *dst, int c, size_t n) {
  uint8_t *d = (uint8_t *)dst;
  uint8_t v = (uint8_t)c;
  for (size_t i = 0; i < n; i++) {
    d[i] = v;
  }
  return dst;
}

static inline uint64_t page_floor(uint64_t x) { return x & ~(uint64_t)(PAGE_SIZE - 1); }
static inline uint64_t page_ceil(uint64_t x) { return (x + (PAGE_SIZE - 1)) & ~(uint64_t)(PAGE_SIZE - 1); }
static inline int is_syscall_err_ptr(const void *p) { return (uintptr_t)p >= (uintptr_t)-4095; }

static int is_compatible_elf(const uint8_t *data, uint16_t want_machine) {
  const Elf_Ehdr *eh = (const Elf_Ehdr *)data;
  if (eh->e_ident[0] != ELFMAG0 || eh->e_ident[1] != ELFMAG1 || eh->e_ident[2] != ELFMAG2 || eh->e_ident[3] != ELFMAG3) {
    return 0;
  }
  if (eh->e_ident[4] != ELFCLASS_NATIVE || eh->e_ident[5] != ELFDATA2LSB) {
    return 0;
  }
  // Only ET_DYN payloads are supported here.
  if (eh->e_type != ET_DYN) {
    return 0;
  }
  if (want_machine != 0 && eh->e_machine != want_machine) {
    return 0;
  }
  return 1;
}

struct mapped_elf {
  uint8_t *base;
  uint16_t machine;
  uint16_t phentsize;
  uint16_t phnum;
  uintptr_t phdr;  // runtime address of the program header table
  uintptr_t entry; // runtime entry address (base + e_entry)
};

static int map_elf(const uint8_t *data, uint64_t data_len, struct mapped_elf *out) {
  const Elf_Ehdr *eh = (const Elf_Ehdr *)data;
  if (eh->e_phoff == 0 || eh->e_phentsize != sizeof(Elf_Phdr) || eh->e_phnum == 0) {
    return 0;
  }
  if ((uint64_t)eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(Elf_Phdr) > data_len) {
    return 0;
  }

  const Elf_Phdr *ph = (const Elf_Phdr *)(data + (size_t)eh->e_phoff);
  uint64_t min_vaddr = UINT64_MAX;
  uint64_t max_vaddr_end = 0;
  const Elf_Phdr *ph_off0 = NULL;

  for (uint16_t i = 0; i < eh->e_phnum; i++) {
    if (ph[i].p_type != PT_LOAD) {
      continue;
    }
    if (ph[i].p_offset == 0) {
      ph_off0 = &ph[i];
    }
    if (ph[i].p_vaddr < min_vaddr) {
      min_vaddr = ph[i].p_vaddr;
    }
    uint64_t end = (uint64_t)ph[i].p_vaddr + (uint64_t)ph[i].p_memsz;
    if (end > max_vaddr_end) {
      max_vaddr_end = end;
    }
  }
  if (min_vaddr == UINT64_MAX || max_vaddr_end == 0) {
    return 0;
  }

  uint64_t map_lo = page_floor(min_vaddr);
  uint64_t map_hi = page_ceil(max_vaddr_end);
  uint64_t map_sz = map_hi - map_lo;
  if (map_hi > (uint64_t)UINTPTR_MAX || map_sz > (uint64_t)SIZE_MAX) {
    return 0;
  }

  uint8_t *mapping = (uint8_t *)sys_mmap(NULL, (size_t)map_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (is_syscall_err_ptr(mapping)) {
    return 0;
  }
  memset8(mapping, 0, (size_t)map_sz);

  uint8_t *base = mapping - (uintptr_t)map_lo;

  for (uint16_t i = 0; i < eh->e_phnum; i++) {
    if (ph[i].p_type != PT_LOAD) {
      continue;
    }
    if ((uint64_t)ph[i].p_offset + (uint64_t)ph[i].p_filesz > data_len) {
      return 0;
    }
    uint8_t *dest = base + (uintptr_t)ph[i].p_vaddr;
    const uint8_t *src = data + (size_t)ph[i].p_offset;
    if (ph[i].p_filesz) {
      memcpy8(dest, src, (size_t)ph[i].p_filesz);
    }

    int prot = 0;
    if (ph[i].p_flags & PF_R) prot |= PROT_READ;
    if (ph[i].p_flags & PF_W) prot |= PROT_WRITE;
    if (ph[i].p_flags & PF_X) prot |= PROT_EXEC;

    uint64_t prot_addr = page_floor((uint64_t)(uintptr_t)dest);
    // p_vaddr is not guaranteed to be page-aligned (only congruent with
    // p_offset modulo the page size). mprotect needs a page-aligned address
    // and a length that covers the entire segment range.
    uint64_t prot_end = page_ceil((uint64_t)(uintptr_t)dest + (uint64_t)ph[i].p_memsz);
    uint64_t prot_len = prot_end - prot_addr;
    if (sys_mprotect((void *)prot_addr, (size_t)prot_len, prot) != 0) {
      return 0;
    }
  }

#if defined(__aarch64__)
  // We wrote instructions into memory; make sure I-cache sees it.
  clear_cache(mapping, mapping + map_sz);
#endif

  // We need to populate auxv with AT_PHDR/AT_PHENT/AT_PHNUM/AT_ENTRY. Those
  // values should describe the *mapped* image. The program headers live within
  // the PT_LOAD that maps file offset 0 (typically the first segment).
  if (!ph_off0) {
    return 0;
  }

  out->base = base;
  out->machine = eh->e_machine;
  out->phentsize = eh->e_phentsize;
  out->phnum = eh->e_phnum;
  out->phdr = (uintptr_t)(base + (uintptr_t)ph_off0->p_vaddr + (uintptr_t)eh->e_phoff);
  out->entry = (uintptr_t)(base + (uintptr_t)eh->e_entry);
  return 1;
}

static int mmap_file_ro(const char *path, uint8_t **data, uint64_t *data_len) {
  long fd = sys_openat(AT_FDCWD, path, O_RDONLY, 0);
  if (fd < 0) {
    return 0;
  }

  long sz = sys_lseek((int)fd, 0, SEEK_END);
  if (sz <= 0) {
    (void)sys_close((int)fd);
    return 0;
  }
  (void)sys_lseek((int)fd, 0, SEEK_SET);

  uint8_t *mapping = (uint8_t *)sys_mmap(NULL, (size_t)sz, PROT_READ, MAP_PRIVATE, (int)fd, 0);
  (void)sys_close((int)fd);

  if (is_syscall_err_ptr(mapping)) {
    return 0;
  }

  *data = mapping;
  *data_len = (uint64_t)sz;
  return 1;
}

static int read_auxv(uint8_t *buf, size_t buf_len, size_t *out_len) {
  long fd = sys_openat(AT_FDCWD, path_auxv, O_RDONLY, 0);
  if (fd < 0) {
    return 0;
  }
  long n = sys_read((int)fd, buf, buf_len);
  (void)sys_close((int)fd);
  if (n <= 0) {
    return 0;
  }
  *out_len = (size_t)n;
  return 1;
}

static uintptr_t *build_stack(uintptr_t stack_top, const struct mapped_elf *exe, const struct mapped_elf *interp, const uint8_t *auxv_buf,
                              size_t auxv_len) {
  // Place the initial stack words at stack_top. The stack grows down; we only
  // need a single page above the pivot for argv/env/auxv.
  uintptr_t *sp = (uintptr_t *)stack_top;

  // argv[0] can be any readable string. Use a pointer into stage0's .text.
  __attribute__((section(".text"), aligned(1))) static const char argv0[] = "payload";
  keep_ptr(argv0);

  // argc
  sp[0] = 1;
  // argv
  sp[1] = (uintptr_t)argv0;
  sp[2] = 0;
  // envp (empty)
  sp[3] = 0;

  // auxv starts after: argc + argv pointers + NULL + envp NULL
  uintptr_t *auxv_out = &sp[4];

  // Copy auxv from /proc/self/auxv but override the program-info entries.
  // Format is pairs of (tag, val) terminated by AT_NULL.
  const uintptr_t *auxv_in = (const uintptr_t *)(const void *)auxv_buf;
  size_t pairs = auxv_len / (sizeof(uintptr_t) * 2);
  size_t out_i = 0;
  int have_base = 0, have_phdr = 0, have_phent = 0, have_phnum = 0, have_entry = 0, have_pagesz = 0;
  for (size_t i = 0; i < pairs; i++) {
    uintptr_t tag = auxv_in[i * 2 + 0];
    uintptr_t val = auxv_in[i * 2 + 1];
    if (tag == AT_NULL) {
      break;
    }
    switch (tag) {
      case AT_BASE:
        have_base = 1;
        val = (uintptr_t)interp->base;
        break;
      case AT_PHDR:
        have_phdr = 1;
        val = exe->phdr;
        break;
      case AT_PHENT:
        have_phent = 1;
        val = (uintptr_t)exe->phentsize;
        break;
      case AT_PHNUM:
        have_phnum = 1;
        val = (uintptr_t)exe->phnum;
        break;
      case AT_ENTRY:
        have_entry = 1;
        val = exe->entry;
        break;
      case AT_PAGESZ:
        have_pagesz = 1;
        // Keep the host page size, but fall back to our constant if it is 0.
        if (val == 0) val = PAGE_SIZE;
        break;
      default:
        break;
    }
    auxv_out[out_i++] = tag;
    auxv_out[out_i++] = val;
  }

  // Ensure required entries exist even if the process auxv didn't have them.
  // Keep this small; the dynamic loader needs these at minimum.
  if (!have_base) {
    auxv_out[out_i++] = AT_BASE;
    auxv_out[out_i++] = (uintptr_t)interp->base;
  }
  if (!have_phdr) {
    auxv_out[out_i++] = AT_PHDR;
    auxv_out[out_i++] = exe->phdr;
  }
  if (!have_phent) {
    auxv_out[out_i++] = AT_PHENT;
    auxv_out[out_i++] = (uintptr_t)exe->phentsize;
  }
  if (!have_phnum) {
    auxv_out[out_i++] = AT_PHNUM;
    auxv_out[out_i++] = (uintptr_t)exe->phnum;
  }
  if (!have_entry) {
    auxv_out[out_i++] = AT_ENTRY;
    auxv_out[out_i++] = exe->entry;
  }
  if (!have_pagesz) {
    auxv_out[out_i++] = AT_PAGESZ;
    auxv_out[out_i++] = PAGE_SIZE;
  }

  auxv_out[out_i++] = AT_NULL;
  auxv_out[out_i++] = 0;

  return sp;
}

__attribute__((section(".text._start"), noreturn)) void _start(void) {
  // Ensure the embedded header and string constants are kept.
  keep_ptr(&g_msda);
  keep_ptr(path_auxv);
  keep_ptr(path_ld_linux);
  keep_ptr(path_ld_linux_alt);

  DBG("stage0: enter\n");

  if (g_msda.arch != MSDA_ARCH_ID || g_msda.version != 1) {
    sys_exit_group(121);
  }
  if (g_msda.payload_len == 0 || g_msda.payload_len > (uint64_t)(256ull * 1024ull * 1024ull)) {
    sys_exit_group(122);
  }

  const uint8_t *payload = (const uint8_t *)(&g_msda + 1);
  uint64_t payload_len = g_msda.payload_len;
  uint8_t *depacked = NULL;
  uint64_t depacked_len = 0;

  // If the payload starts with an AP32 safe header, depack it before mapping as an ELF.
  if (is_ap32_safe(payload, payload_len)) {
    if (!depack_ap32_safe(payload, payload_len, &depacked, &depacked_len)) {
      sys_exit_group(123);
    }
    payload = depacked;
    payload_len = depacked_len;
  }

  // Sanity: payload must start with an ELF header.
  if (!is_compatible_elf(payload, 0)) {
    sys_exit_group(123);
  }

  DBG("stage0: payload ok\n");

  struct mapped_elf exe = {0};
  if (!map_elf(payload, payload_len, &exe)) {
    sys_exit_group(124);
  }

  if (depacked) {
    (void)sys_munmap(depacked, (size_t)depacked_len);
  }

  DBG("stage0: exe mapped\n");

  // Map the system dynamic loader into memory.
  uint8_t *ld_file = NULL;
  uint64_t ld_file_len = 0;
  if (!mmap_file_ro(path_ld_linux, &ld_file, &ld_file_len)) {
    if (!mmap_file_ro(path_ld_linux_alt, &ld_file, &ld_file_len)) {
      sys_exit_group(125);
    }
  }

  if (!is_compatible_elf(ld_file, exe.machine)) {
    sys_exit_group(126);
  }

  struct mapped_elf interp = {0};
  if (!map_elf(ld_file, ld_file_len, &interp)) {
    sys_exit_group(127);
  }
  (void)sys_munmap(ld_file, (size_t)ld_file_len);

  DBG("stage0: ld mapped\n");

  // Read auxv from /proc/self/auxv.
  uint8_t auxv_buf[4096];
  size_t auxv_len = 0;
  if (!read_auxv(auxv_buf, sizeof(auxv_buf), &auxv_len)) {
    sys_exit_group(128);
  }

  DBG("stage0: auxv ok\n");

  // Allocate a fresh stack with plenty of room to grow.
  size_t stack_sz = 2048u * PAGE_SIZE;
  uint8_t *stack_mapping = (uint8_t *)sys_mmap(NULL, stack_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
  if (is_syscall_err_ptr(stack_mapping)) {
    sys_exit_group(129);
  }

  uintptr_t stack_top = (uintptr_t)stack_mapping + (uintptr_t)stack_sz - PAGE_SIZE;
  // ABI alignment at program entry differs by arch.
#if defined(__x86_64__)
  // The kernel enters the program/loader with a 16-byte aligned stack. Keep
  // that invariant so ld-linux and later calls see ABI-correct alignment.
  stack_top &= ~0xfull; // rsp % 16 == 0
#else
  stack_top &= ~0xfull; // sp % 16 == 0
#endif

  uintptr_t *new_sp = build_stack(stack_top, &exe, &interp, auxv_buf, auxv_len);

  DBG("stage0: jumping to ld\n");
  jump_with_stack(interp.entry, new_sp);
  sys_exit_group(130);
}
