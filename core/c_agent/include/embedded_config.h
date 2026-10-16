#ifndef C2_EMBEDDED_CONFIG_H
#define C2_EMBEDDED_CONFIG_H

/*
 * embedded_config.h — build-time configuration symbols.
 *
 * The encrypted CBOR build config and the build-wide magic string are rendered
 * by lib/cagent and compiled via the Makefile's CONFIG_SRC, linked into the
 * agent as ordinary data. There is no patchable ELF placeholder: an on-demand
 * build produces exactly the bytes this target needs.
 *
 * agent.c provides weak zero-length defaults so an agent still links without
 * a generated config; such an agent fails decryption at startup.
 */

#include <stddef.h>
#include <stdint.h>

extern const uint8_t c2_embedded_config[];
extern const size_t c2_embedded_config_len;
extern const uint8_t c2_magic_string[];
extern const size_t c2_magic_string_len;
/* Build version reported as Emp3r0rAgent.Version, matching the Go agent. */
extern const char c2_build_version[];

#endif /* C2_EMBEDDED_CONFIG_H */
