#include "module.h"

#include "fuzz_common.h"

#include <string.h>

/*
 * c2_coff_invocation_parse decodes a base64 CBOR def.ResolvedInvocation that
 * the C2 sends with `!custom_module`. Both the base64 decoder and the CBOR
 * walk run on attacker-influenced bytes, so the property under test is memory
 * safety of an arbitrary invocation: no over-read of the input, no write past
 * the caller's export/token/buffer storage, and bounded recursion.
 *
 * The CBOR path is reached by base64url-encoding the raw input, so libFuzzer's
 * byte mutations become structured CBOR. The raw input is also fed as base64
 * text to exercise the decoder's hostile-text path. The output capacities vary
 * with the input, including zero, so the exhaustion/edge paths are hit too.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char b64[16384];
  char export_name[64];
  c2_str tokens[16];
  char buf[8192];

  /* Encode the input so arbitrary bytes reach the CBOR decoder. */
  size_t b64len = c2_base64url_encode(data, size, b64, sizeof(b64));
  if (b64len > 0) {
    size_t tokenc = 0, buf_used = 0;
    size_t export_cap = size % (sizeof(export_name) + 1);
    size_t tokens_cap = size % (sizeof(tokens) / sizeof(tokens[0]) + 1);
    size_t buf_cap = size % (sizeof(buf) + 1);
    memset(export_name, 0xAA, sizeof(export_name));
    memset(buf, 0xBB, sizeof(buf));
    (void)c2_coff_invocation_parse(b64, b64len, export_name, export_cap, tokens,
                                   &tokenc, tokens_cap, buf, buf_cap,
                                   &buf_used);
  }

  /* The input as base64 text, with full capacities. */
  {
    size_t tokenc = 0, buf_used = 0;
    (void)c2_coff_invocation_parse((const char *)data, size, export_name,
                                   sizeof(export_name), tokens, &tokenc,
                                   sizeof(tokens) / sizeof(tokens[0]), buf,
                                   sizeof(buf), &buf_used);
  }

  return 0;
}
