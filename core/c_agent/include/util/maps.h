#ifndef C2_UTIL_MAPS_H
#define C2_UTIL_MAPS_H

/*
 * maps.h — freestanding /proc/self/maps line parser.
 *
 * The parser copies the fields callers need (range, protections, whether the
 * mapping has no pathname) and never allocates. It is shared by the stager
 * sleep mask and the fuzz/unit tests; malformed text only produces fewer
 * entries, never an over-read.
 */

#include <stddef.h>
#include <stdint.h>

#include "util/utils.h"

#define C2_MAP_SPECIAL_NONE 0
#define C2_MAP_SPECIAL_HEAP 1
#define C2_MAP_SPECIAL_STACK 2

struct c2_map {
  uintptr_t start;
  uintptr_t end;
  int prot;      /* PROT_READ / PROT_WRITE / PROT_EXEC bits */
  int anonymous; /* 1 for process-private memory (pathless, heap, stack) */
  int special;   /* C2_MAP_SPECIAL_* for named heap/stack mappings */
};

/* Parse at most `cap` mappings from `text`. Returns the number written. */
size_t c2_maps_parse(const char *text, size_t len, struct c2_map *maps,
                     size_t cap);

#endif /* C2_UTIL_MAPS_H */
