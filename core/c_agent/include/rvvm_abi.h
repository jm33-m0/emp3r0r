#ifndef C2_RVVM_ABI_H
#define C2_RVVM_ABI_H

/*
 * rvvm_abi.h — argument layout between an RV32 guest image and the rvvm_linux
 * interpreter.
 *
 * The interpreter module (core/modules/rvvm/rvvm.c), both in-memory loaders
 * (core/c_agent/src/rvvm.c and the Go runner), the module tests, the fuzzer
 * and the rvvmrun tool all pass this block across the module boundary. The Go
 * mirror is bofArgs in core/lib/rvvm/rvvm.go.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rv_bof_args {
  const uint8_t *buf; /* packed BOF argument buffer */
  size_t len;
  const uint8_t *env; /* NUL-separated KEY=VALUE block, ... NUL */
  size_t env_len;
};

#ifdef __cplusplus
}
#endif

#endif /* C2_RVVM_ABI_H */
