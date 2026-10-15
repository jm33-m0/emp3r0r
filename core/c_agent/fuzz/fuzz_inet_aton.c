#include "util/net_utils.h"

#include "fuzz_common.h"

#include <stdint.h>
#include <string.h>

/* inet_aton must be a pure, deterministic function of its input: it must never
 * read past the string and must return the same result on repeat calls. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char host[64];
  size_t n = size < sizeof(host) - 1 ? size : sizeof(host) - 1;
  memcpy(host, data, n);
  host[n] = '\0';

  struct in_addr a, b;
  int r1 = inet_aton(host, &a);
  int r2 = inet_aton(host, &b);
  if (r1 != r2)
    c2_fuzz_fail("inet_aton is not deterministic");
  if (r1 && a.s_addr != b.s_addr)
    c2_fuzz_fail("inet_aton changed its result");

  return 0;
}
