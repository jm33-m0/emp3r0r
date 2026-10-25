#include "transport.h"

#include "fuzz_common.h"
#include "stub_crypto.h"

#include "cbor.h"

#include <stdlib.h>
#include <string.h>

/*
 * The embedded build config is an AES-GCM container whose key is derived with
 * PBKDF2. The real KDF is deliberately expensive, so this target uses the
 * deterministic stub backend: arbitrary input is encrypted into a valid
 * container first (so the CBOR decoder is always reached), and the raw input is
 * also fed to c2_config_decrypt to exercise hostile container parsing.
 */

#define FUZZ_CONFIG_MAX (64u * 1024u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint32_t rng = 0x71c0ffeeu ^ (uint32_t)size;
  c2_crypto_backend be;
  stub_crypto_init(&be, &rng);

  c2_str password = c2_str_lit("fuzz-config-password");
  uint8_t *enc = (uint8_t *)malloc(FUZZ_CONFIG_MAX + 64);
  uint8_t *plain = (uint8_t *)malloc(FUZZ_CONFIG_MAX);
  if (enc == NULL || plain == NULL) {
    free(enc);
    free(plain);
    return 0;
  }

  size_t enc_len = 0;
  if (c2_aes_gcm_encrypt_password(&be, password, data, size, enc,
                                  FUZZ_CONFIG_MAX + 64, &enc_len) == C2_OK) {
    size_t plain_len = 0;
    if (c2_config_decrypt(&be, password, enc, enc_len, plain, FUZZ_CONFIG_MAX,
                          &plain_len) == C2_OK) {
      CborParser parser;
      CborValue it;
      if (cbor_parser_init(plain, plain_len, 0, &parser, &it) == CborNoError) {
        c2_str keys[8], values[8];
        c2_agent_config cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.http.header_keys = keys;
        cfg.http.header_values = values;
        cfg.http.header_cap = size % 9;
        (void)c2_agent_config_decode(&it, &cfg);
      }
    }
  }

  /* Raw input as the container: salt/nonce/tag bounds and authentication
   * failures. */
  size_t out_len = 0;
  (void)c2_config_decrypt(&be, password, data, size, plain, FUZZ_CONFIG_MAX,
                          &out_len);

  free(enc);
  free(plain);
  return 0;
}
