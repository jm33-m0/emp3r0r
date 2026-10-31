#ifndef C2_RVVM_H
#define C2_RVVM_H

/*
 * rvvm.h — run an RV32IMA guest through the rvvm_linux dependency.
 *
 * The interpreter is not linked into the agent: it is the `rvvm_linux`
 * dependency module (rvvm_linux.so), the RISC-V counterpart of
 * coffloader_linux. c2_rv_run maps the interpreter from memory (anonymous
 * mmap + dynamic relocations), calls its `rv_run` export with the guest image
 * and argument block, and unmaps it again.
 *
 * Guests are RV32 ET_REL BOFs; see core/modules/rvvm/runtime for the guest
 * runtime and core/modules/rvvm/include/rv_hostcall.h for host calls.
 */

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One delivered RISC-V library image. */
typedef struct {
  const uint8_t *buf;
  size_t len;
} c2_rv_lib;

/*
 * Run an RV32 ET_REL BOF. `entry` is the export name (NULL/"" means "go") and
 * `bof_args`/`bof_len` is the packed COFF argument buffer passed to it as
 * (char *args, int len).
 *
 * On C2_OK *out is a NUL-terminated malloc'd string (possibly empty) that the
 * caller frees with free(); it is never NULL on C2_OK. On failure *out is set
 * to a malloc'd copy of the interpreter's error message when one is available
 * (otherwise NULL), and the caller should still free it.
 */
c2_status c2_rv_run(const uint8_t *loader_so, size_t loader_len,
                    const uint8_t *image, size_t image_len, const char *entry,
                    const uint8_t *bof_args, size_t bof_len,
                    const c2_rv_lib *libs, size_t nlibs, char **out);

#ifdef __cplusplus
}
#endif

#endif /* C2_RVVM_H */
