#include "messages.h"

#include "cbor.h"

#include "fuzz_common.h"

/* Decode arbitrary bytes as the two envelopes. Errors are expected and
 * ignored; the property under test is that no input can over-read, recurse
 * without a bound, or otherwise violate memory safety (ASan/UBSan). */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  c2_str items[8];
  CborParser parser;
  CborValue it;
  /* Vary the list capacities, including zero, so the decoder's insufficient-
   * capacity path is exercised as well as the normal one. */
  size_t c1 = size % 9;

  if (cbor_parser_init(data, size, 0, &parser, &it) == CborNoError) {
    c2_msgtun t = {0};
    t.cmd_slice.items = items;
    t.cmd_slice.cap = c1;
    (void)c2_msgtun_decode(&it, &t);
  }

  if (cbor_parser_init(data, size, 0, &parser, &it) == CborNoError) {
    c2_msgauth a = {0};
    a.capabilities.items = items;
    a.capabilities.cap = c1;
    (void)c2_msgauth_decode(&it, &a);
  }

  return 0;
}
