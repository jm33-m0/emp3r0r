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
 * syscall. That mmap's a dedicated read/write page for the single mutable
 * state block and binds it to %r15. The whole stager is compiled with
 * -ffixed-r15 so no generated code ever clobbers that register, giving every
 * translation unit a stable pointer to the writable state block via
 * get_stager_state().
 */

typedef void *(*dlopen_fn)(const char *, int);
typedef void *(*dlsym_fn)(void *, const char *);
typedef int (*dlclose_fn)(void *);

struct stager_state {
  void *syscall_gadget; /* resolved vDSO `syscall; ret` gadget */
  long dl_ready;        /* 1 = dl* cache not yet resolved */
  dlopen_fn dlopen_;
  dlsym_fn dlsym_;
  dlclose_fn dlclose_;
};

/* Sentinel value for syscall_gadget before init_indirect_syscalls(). */
#define _SYSCALL_GADGET_UNRESOLVED ((void *)1)

/* Read the state block bound to %r15. */
static inline struct stager_state *get_stager_state(void) {
  struct stager_state *st;
  __asm__ __volatile__("mov %%r15, %0" : "=r"(st));
  return st;
}

/* mmap a dedicated RW state page, initialise it, and bind it to %r15.
 * Must be called once at the top of downloader_main, before any syscall. */
void stager_state_init(void);

#endif /* STAGER_STATE_H */
