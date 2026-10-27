/*
 * test_maps.c — the shared /proc/self/maps parser used by the sleep mask.
 */

#include "util/maps.h"

#include "test.h"

#include <string.h>

int main(void) {
  const char text[] = "1000-2000 r-xp 00000000 00:00 0 /usr/bin/test\n"
                      "3000-4000 rw-p 00001000 00:00 0\n"
                      "5000-6000 ---p 00002000 00:00 0\n"
                      "7000-8000 r--p 00000000 00:00 0 [vdso]\n"
                      "not a maps line\n"
                      "9000-8000 rw-p 00000000 00:00 0\n"
                      "a000-b000 rwxp 00000000 00:00 0\n";

  struct c2_map maps[8];
  size_t n = c2_maps_parse(text, sizeof(text) - 1, maps, 8);
  CHECK_EQ_LONG(n, 5);
  if (n == 5) {
    CHECK_EQ_LONG(maps[0].start, 0x1000);
    CHECK_EQ_LONG(maps[0].end, 0x2000);
    CHECK_EQ_LONG(maps[0].prot, PROT_READ | PROT_EXEC);
    CHECK_EQ_LONG(maps[0].anonymous, 0);

    CHECK_EQ_LONG(maps[1].start, 0x3000);
    CHECK_EQ_LONG(maps[1].prot, PROT_READ | PROT_WRITE);
    CHECK_EQ_LONG(maps[1].anonymous, 1);

    CHECK_EQ_LONG(maps[2].prot, 0);
    CHECK_EQ_LONG(maps[2].anonymous, 1);

    CHECK_EQ_LONG(maps[3].prot, PROT_READ);
    CHECK_EQ_LONG(maps[3].anonymous, 0);
    CHECK_EQ_LONG(maps[3].special, C2_MAP_SPECIAL_NONE);

    CHECK_EQ_LONG(maps[4].prot, PROT_READ | PROT_WRITE | PROT_EXEC);
    CHECK_EQ_LONG(maps[4].anonymous, 1);
  }

  /* Capacity is a hard bound, and the parsed prefix is stable. */
  struct c2_map one;
  CHECK_EQ_LONG(c2_maps_parse(text, sizeof(text) - 1, &one, 1), 1);
  CHECK_EQ_LONG(one.start, maps[0].start);
  CHECK_EQ_LONG(c2_maps_parse(text, sizeof(text) - 1, NULL, 0), 0);
  CHECK_EQ_LONG(c2_maps_parse(NULL, 10, maps, 8), 0);

  /* Input is length-delimited and need not be NUL-terminated. */
  const char tail[] = "a000-b000 rw-p 00000000 00:00 0";
  CHECK_EQ_LONG(c2_maps_parse(tail, sizeof(tail) - 1, maps, 8), 1);
  CHECK_EQ_LONG(maps[0].start, 0xa000);
  CHECK_EQ_LONG(maps[0].end, 0xb000);
  CHECK_EQ_LONG(maps[0].anonymous, 1);

  /* Heap/stack are maskable. Runtime/kernel named mappings are not. */
  const char special[] = "1000-2000 rw-p 00000000 00:00 0 [heap]\n"
                         "2000-3000 rw-p 00000000 00:00 0 [stack]\n"
                         "3000-4000 rw-p 00000000 00:00 0 [stack:123]\n"
                         "4000-5000 rw-p 00000000 00:00 0 [anon:rseq]\n"
                         "5000-6000 r--p 00000000 00:00 0 [vvar]\n"
                         "6000-7000 r-xp 00000000 00:00 0 [vdso]\n";
  n = c2_maps_parse(special, sizeof(special) - 1, maps, 8);
  CHECK_EQ_LONG(n, 6);
  if (n == 6) {
    CHECK_EQ_LONG(maps[0].anonymous, 1);
    CHECK_EQ_LONG(maps[0].special, C2_MAP_SPECIAL_HEAP);
    CHECK_EQ_LONG(maps[1].special, C2_MAP_SPECIAL_STACK);
    CHECK_EQ_LONG(maps[2].special, C2_MAP_SPECIAL_STACK);
    for (size_t i = 3; i < 6; i++) {
      CHECK_EQ_LONG(maps[i].anonymous, 0);
      CHECK_EQ_LONG(maps[i].special, C2_MAP_SPECIAL_NONE);
    }
  }

  /* Truncations cannot walk past the supplied length. */
  for (size_t i = 0; i < sizeof(text) - 1; i++)
    (void)c2_maps_parse(text, i, maps, 8);

  TEST_DONE();
}
