#ifndef C2_FUZZ_COMMON_H
#define C2_FUZZ_COMMON_H

/*
 * fuzz_common.h — helpers shared by the LLVMFuzzerTestOneInput targets.
 *
 * Each fuzz target defines LLVMFuzzerTestOneInput and is linked either with
 * clang's libFuzzer (main supplied by the fuzzer) or with fuzz_runner.c, the
 * dependency-free fallback driver. Invariant violations abort via
 * c2_fuzz_fail() so a sanitizer/exit code catches them.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static inline void c2_fuzz_fail(const char *why) {
  (void)why;
  abort();
}

#endif /* C2_FUZZ_COMMON_H */
