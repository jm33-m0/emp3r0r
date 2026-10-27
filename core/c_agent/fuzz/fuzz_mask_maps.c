#include "util/maps.h"

#include "fuzz_common.h"

#include <stdint.h>

/*
 * Fuzz the maps parser used by the sleep-mask provider. Arbitrary text may
 * yield no mappings, fewer mappings, or a full table, but every entry must be
 * well formed and the parser must never read outside the supplied buffer.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct c2_map maps[64];
  size_t n = c2_maps_parse((const char *)data, size, maps,
                           sizeof(maps) / sizeof(maps[0]));
  if (n > sizeof(maps) / sizeof(maps[0]))
    c2_fuzz_fail("parser returned more entries than capacity");

  for (size_t i = 0; i < n; i++) {
    if (maps[i].end <= maps[i].start)
      c2_fuzz_fail("inverted or empty mapping");
    if (maps[i].prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC))
      c2_fuzz_fail("unknown protection bit");
    if (maps[i].anonymous != 0 && maps[i].anonymous != 1)
      c2_fuzz_fail("anonymous flag is not boolean");
    if (maps[i].special < C2_MAP_SPECIAL_NONE ||
        maps[i].special > C2_MAP_SPECIAL_STACK)
      c2_fuzz_fail("special map class out of range");
  }

  /* A smaller capacity must produce the same prefix, not a different parse. */
  size_t small_n = n < 3 ? n : 3;
  struct c2_map small[3];
  size_t got = c2_maps_parse((const char *)data, size, small, small_n);
  if (got != small_n)
    c2_fuzz_fail("short parse changed the number of entries");
  for (size_t i = 0; i < small_n; i++) {
    if (small[i].start != maps[i].start || small[i].end != maps[i].end ||
        small[i].prot != maps[i].prot ||
        small[i].anonymous != maps[i].anonymous ||
        small[i].special != maps[i].special)
      c2_fuzz_fail("short parse differs from full parse");
  }

  (void)c2_maps_parse((const char *)data, size, NULL, 0);
  return 0;
}
