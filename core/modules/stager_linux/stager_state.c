/*
 * stager_state.c — allocate and install the stager's mutable runtime state.
 *
 * The stager image is mapped RX (W^X), so mutable globals cannot live in .data.
 * This mmaps a dedicated RW page, initialises it, and installs it as the GS
 * base; get_stager_state() then finds it via %gs:0 without reserving a
 * general-purpose register. It must run before any other syscall.
 *
 * This file is stager-specific: a hosted agent does not need the GS state.
 */

#include "state.h"
#include "syscalls.h"
#include "utils.h"

void stager_state_init(void) {
  struct stager_state *st;
  long ret;
  void *gadget = get_embedded_syscall_gadget();
  register long r10 __asm__("r10") = MAP_PRIVATE | MAP_ANONYMOUS;
  register long r8 __asm__("r8") = -1;
  register long r9 __asm__("r9") = 0;

  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(gadget), "a"((long)SYS_mmap), "D"((long)0),
                         "S"((long)0x1000), "d"((long)(PROT_READ | PROT_WRITE)),
                         "r"(r10), "r"(r8), "r"(r9)
                       : "rcx", "r11", "memory");
  if (ret < 0)
    __builtin_trap();

  st = (struct stager_state *)ret;
  st->self = st;
  st->syscall_gadget = _SYSCALL_GADGET_UNRESOLVED;
  /* The mapping is zero-filled by the kernel; keep the dynload cache empty so
   * the next dynload_open resolves lazily. */
  st->dl.resolved = 0;
  st->dl.open = 0;
  st->dl.sym = 0;
  st->dl.close = 0;

  /* Install the block as the GS base so get_stager_state() can find it without
   * reserving a general-purpose register. */
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(gadget), "a"((long)SYS_arch_prctl),
                         "D"((long)ARCH_SET_GS), "S"((long)st)
                       : "rcx", "r11", "memory");
  if (ret < 0)
    __builtin_trap();
}
