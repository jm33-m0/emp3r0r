#ifndef C2_RVVM_H
#define C2_RVVM_H

/*
 * rvvm.h — run an RV32IMA guest through the rvvm_linux dependency.
 *
 * The interpreter is not linked into the agent: it is the `rvvm_linux`
 * dependency module (rvvm_linux.so), the RISC-V counterpart of
 * coffloader_linux. c2_rv_run maps the interpreter from memory (anonymous
 * mmap + dynamic relocations), calls its `Run` export with the guest image
 * and argument block, and unmaps it again.
 *
 * The guest is a static RV32 musl executable: the interpreter starts at musl's
 * _start and the only host boundary is the syscall gate. rv modules therefore
 * run on Linux agents only.
 */

#include "bof.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Run an RV32 guest executable. `bof_args`/`bof_len` is the packed COFF
 * argument buffer passed to the guest entry shim as (char *args, int len).
 *
 * On C2_OK *out is a NUL-terminated malloc'd string (possibly empty) that the
 * caller frees with free(); it is never NULL on C2_OK. On failure *out is set
 * to a malloc'd copy of the interpreter's error message when one is available
 * (otherwise NULL), and the caller should still free it.
 */
c2_status c2_rv_run(const uint8_t *loader_so, size_t loader_len,
                    const uint8_t *image, size_t image_len,
                    const uint8_t *bof_args, size_t bof_len,
                    const c2_bof_host *host, char **out);

#ifdef __cplusplus
}
#endif

#endif /* C2_RVVM_H */
