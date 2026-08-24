// unpack_stub_rc4.c — RC4 self-unpacker stub.
//
// Decrypts the packed payload (RC4, key from the header) into a fresh RWX
// mapping and jumps to it. See unpack.h for the stub/packer contract.

#include "rc4.h"
#include "unpack.h"

/* In .data; pack_rc4.py patches unpacked_size/packed_size/key. */
static struct unpack_header hdr = {1, 1, {0}};

static void do_unpack_rc4(const uint8_t *src, const struct unpack_header *h,
                          uint8_t *dst) {
  for (uint32_t i = 0; i < h->packed_size; i++)
    dst[i] = src[i];
  rc4_ctx ctx;
  rc4_init(&ctx, h->key, 16);
  rc4_crypt(&ctx, dst, h->packed_size);
}

__attribute__((noreturn, used)) void unpack_and_run(void) {
  unpack_run_stub(&hdr, do_unpack_rc4);
}

UNPACK_ENTRY();
