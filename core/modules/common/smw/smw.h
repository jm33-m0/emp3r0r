/*
 * Common header for the vendored SilentMoonwalk (SMW) desync call-stack
 * spoofer used by Windows payload modules.
 *
 * The C/asm sources in this directory are copied verbatim from
 * core/lib/syscall/smw/csrc (the cgo variant) so payload modules that cannot
 * use cgo can still spoof their indirect syscalls. Keep them in sync when
 * the upstream spoofer changes.
 *
 * SMW is x64-only: DesyncSpoofer.asm is 64-bit and spoof_call() is only
 * compiled by NTSYS_SMW builds.
 */
#ifndef COMMON_SMW_H
#define COMMON_SMW_H

#include "Spoof.h"

/*
 * smw_ensure_init builds the process-wide SPOOFER template exactly once
 * (KernelBase frames, ROP gadgets, thread-root unwind sizes). Returns 1 on
 * success. Callers must check it before spoof_call(), which returns 0 both
 * on a failed init and on a syscall that legitimately returned 0.
 */
int smw_ensure_init(void);

#endif /* COMMON_SMW_H */
