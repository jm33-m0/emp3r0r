#ifndef RV_HOST_H
#define RV_HOST_H

/*
 * rv_host.h — host-call backend for the rvvm interpreter.
 *
 * The guest BOF runtime fills the mailbox and rings the doorbell; the module
 * hands the request to the platform backend. Linux uses libc, Windows uses
 * the Win32 API. Both implement the same opcodes from rv_hostcall.h.
 */

#include <stddef.h>
#include <stdint.h>

#include "rv_hostcall.h"

/* Guest-address helpers implemented by rvvm.c. */
uint8_t *rv_gptr(uint32_t addr, uint32_t len);
int rv_guest_cstr(uint32_t addr, char *out, size_t cap);

/* Output and error sinks implemented by rvvm.c. */
int rv_out_append(const void *data, size_t len);
void rv_set_err(const char *msg);

/* Platform backend. */
void rv_host_dispatch(struct rv_hc_req *req);
void rv_host_reset(void);

#endif /* RV_HOST_H */
