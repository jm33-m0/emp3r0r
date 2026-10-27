#include "mask_ranges.h"

#include "fuzz_common.h"

#include <stdint.h>
#include <string.h>

struct range_input {
  uint64_t start;
  uint64_t end;
  uint64_t keep_start;
  uint64_t keep_end;
  uint64_t scratch_start;
  uint64_t scratch_end;
};

/*
 * Fuzz the mask range planner. Exclusions may split a mapping, but the result
 * must stay inside the input, exclude both protected ranges, and never contain
 * overlapping or inverted entries.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct range_input in;
  if (size < sizeof(in))
    return 0;
  memcpy(&in, data, sizeof(in));

  struct c2_map ranges[8];
  size_t n = mask_add_map((uintptr_t)in.start, (uintptr_t)in.end,
                          PROT_READ | PROT_WRITE, (uintptr_t)in.keep_start,
                          (uintptr_t)in.keep_end, (uintptr_t)in.scratch_start,
                          (uintptr_t)in.scratch_end, ranges,
                          sizeof(ranges) / sizeof(ranges[0]), 0);
  if (n > sizeof(ranges) / sizeof(ranges[0]))
    c2_fuzz_fail("range planner exceeded capacity");

  for (size_t i = 0; i < n; i++) {
    uintptr_t s = ranges[i].start;
    uintptr_t e = ranges[i].end;
    if (e <= s)
      c2_fuzz_fail("planner produced an inverted range");
    if (s < (uintptr_t)in.start || e > (uintptr_t)in.end)
      c2_fuzz_fail("planner produced a range outside the input");
    if ((uintptr_t)in.keep_end > (uintptr_t)in.keep_start &&
        s < (uintptr_t)in.keep_end && (uintptr_t)in.keep_start < e)
      c2_fuzz_fail("planner kept part of the state/stack range");
    if ((uintptr_t)in.scratch_end > (uintptr_t)in.scratch_start &&
        s < (uintptr_t)in.scratch_end && (uintptr_t)in.scratch_start < e)
      c2_fuzz_fail("planner kept part of the scratch range");
    if (i > 0 && s < ranges[i - 1].end)
      c2_fuzz_fail("planner produced overlapping or unsorted ranges");
  }
  return 0;
}
