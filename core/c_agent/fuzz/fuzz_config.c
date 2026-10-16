#include "transport.h"

#include "cbor.h"

#include "fuzz_common.h"

/*
 * Decode arbitrary bytes as the build config. The decoder walks nested route
 * and malleable-HTTP maps and a text-keyed custom-header map, and skips every
 * unknown key, so the property under test is memory safety and bounded
 * recursion (ASan/UBSan), not acceptance. The header array size varies with
 * the input so the capacity-exhausted path is exercised too.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  CborParser parser;
  CborValue it;
  if (cbor_parser_init(data, size, 0, &parser, &it) != CborNoError)
    return 0;

  c2_str keys[8], values[8];
  c2_agent_config cfg = {0};
  cfg.http.header_keys = keys;
  cfg.http.header_values = values;
  cfg.http.header_cap = size % 9;
  (void)c2_agent_config_decode(&it, &cfg);
  return 0;
}
