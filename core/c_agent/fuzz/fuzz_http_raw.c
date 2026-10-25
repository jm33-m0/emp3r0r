#include "http_wire.h"

#include "fuzz_common.h"

/* The raw HTTP transport parses server responses and URLs from the network.
 * Both are attacker-controlled, so run the response/chunked parser and the URL
 * parser over arbitrary bytes under ASan/UBSan. */

int c2_http_raw_fuzz_parse(const uint8_t *data, size_t len);
int c2_http_raw_fuzz_url(const uint8_t *data, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  c2_http_raw_fuzz_parse(data, size);
  c2_http_raw_fuzz_url(data, size);
  return 0;
}
