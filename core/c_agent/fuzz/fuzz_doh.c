#include "util/doh.h"

#include "fuzz_common.h"

/* The DoH resolver parses attacker-controlled DNS wire data returned by the
 * resolver. Exercise the answer walker, compression-pointer skipper and
 * address extraction under ASan/UBSan without any network access. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  c2_doh_fuzz_parse(data, size);
  return 0;
}
