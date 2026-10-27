#ifndef STAGER_MASK_RANGES_H
#define STAGER_MASK_RANGES_H

/*
 * Range planner shared by the XOR mask provider and its fuzzer.
 *
 * The planner turns one process mapping into maskable sub-ranges, excluding
 * the stub's state+stack mapping and the provider's scratch mapping. It may
 * split a mapping when the kernel merged adjacent VMAs. Pure and allocation
 * free, so users can reuse it in their own providers and fuzz it directly.
 */

#include "util/maps.h"

#include <stdint.h>

static inline void mask_push_range(uintptr_t start, uintptr_t end, int prot,
                                   struct c2_map *ranges, size_t cap,
                                   size_t *n) {
  if (end <= start || *n >= cap)
    return;
  ranges[*n].start = start;
  ranges[*n].end = end;
  ranges[*n].prot = prot;
  ranges[*n].anonymous = 1;
  ranges[*n].special = C2_MAP_SPECIAL_NONE;
  (*n)++;
}

/* Append `start..end` minus a list of exclusion ranges. Ranges are split into
 * at most 8 segments in total; callers that need more must increase the cap. */
static inline size_t mask_add_map_ex(uintptr_t start, uintptr_t end, int prot,
                                     const uintptr_t ex[][2], size_t nex,
                                     struct c2_map *ranges, size_t cap,
                                     size_t n) {
  uintptr_t segs[8][2];
  size_t ns = 1;
  segs[0][0] = start;
  segs[0][1] = end;
  for (size_t x = 0; x < nex; x++) {
    uintptr_t xs = ex[x][0];
    uintptr_t xe = ex[x][1];
    if (xe <= xs)
      continue;
    uintptr_t next[8][2];
    size_t out = 0;
    for (size_t i = 0; i < ns; i++) {
      uintptr_t ss = segs[i][0];
      uintptr_t se = segs[i][1];
      if (xe <= ss || xs >= se) {
        if (out < 8) {
          next[out][0] = ss;
          next[out][1] = se;
          out++;
        }
        continue;
      }
      if (ss < xs && out < 8) {
        next[out][0] = ss;
        next[out][1] = xs;
        out++;
      }
      if (xe < se && out < 8) {
        next[out][0] = xe;
        next[out][1] = se;
        out++;
      }
    }
    for (size_t i = 0; i < out; i++) {
      segs[i][0] = next[i][0];
      segs[i][1] = next[i][1];
    }
    ns = out;
  }
  for (size_t i = 0; i < ns; i++)
    mask_push_range(segs[i][0], segs[i][1], prot, ranges, cap, &n);
  return n;
}

/* Append `start..end` minus the state/stack and scratch mappings. */
static inline size_t mask_add_map(uintptr_t start, uintptr_t end, int prot,
                                  uintptr_t keep_start, uintptr_t keep_end,
                                  uintptr_t scratch_start,
                                  uintptr_t scratch_end,
                                  struct c2_map *ranges, size_t cap,
                                  size_t n) {
  const uintptr_t ex[2][2] = {{keep_start, keep_end},
                              {scratch_start, scratch_end}};
  return mask_add_map_ex(start, end, prot, ex, 2, ranges, cap, n);
}

#endif /* STAGER_MASK_RANGES_H */
