#ifndef C2_PROTOCOL_H
#define C2_PROTOCOL_H

/*
 * c2_protocol.h — umbrella header for the emp3r0r C2 wire protocol.
 *
 * Include this single header to get the complete protocol surface:
 *
 *   c2_common.h     constants, limits, status, byte-order and text codecs
 *   c2_crypto.h     crypto backend contract (AES-GCM, SHA-256, HKDF, P-256)
 *   c2_messages.h   MsgAuth / MsgTunData / Emp3r0rAgent / AgentToken schemas
 *                   (CBOR via the vendored tinycbor, vendor/tinycbor/)
 *   c2_secureconn.h SecureConn framing and key lifecycle
 *   c2_transport.h  build config, channel contract, agent session flow
 *
 * Normative protocol text lives in PROTOCOL.md at the repository root. When
 * the Go implementation changes, PROTOCOL.md and these headers must change in
 * the same commit.
 *
 * Build notes:
 *   - C99, freestanding-friendly (only <stdint.h>/<stddef.h>).
 *   - The crypto and channel interfaces are deliberately abstract: a hosted
 *     agent can back them with libcrypto/libcurl resolved through dynload.h,
 *     a freestanding agent with a vendored implementation.
 *   - The message codecs never allocate; callers own every buffer and decode
 *     results are borrowed slices into the input.
 */

#include "c2_common.h"

#include "c2_crypto.h"
#include "c2_messages.h"
#include "c2_secureconn.h"
#include "c2_transport.h"

#endif /* C2_PROTOCOL_H */
