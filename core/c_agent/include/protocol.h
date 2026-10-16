#ifndef C2_PROTOCOL_H
#define C2_PROTOCOL_H

/*
 * protocol.h — umbrella header for the emp3r0r C2 wire protocol.
 *
 * Include this single header to get the complete protocol surface:
 *
 *   common.h     constants, limits, status, byte-order and text codecs
 *   crypto.h     crypto backend contract (AES-GCM, SHA-256, HKDF, P-256)
 *   messages.h   MsgAuth / MsgTunData / Emp3r0rAgent / AgentToken schemas
 *                   (CBOR via the vendored tinycbor, vendor/tinycbor/)
 *   secureconn.h SecureConn framing and key lifecycle
 *   transport.h  build config, channel contract, agent session flow
 *
 * Normative protocol text lives in README.md's "C2 protocol specification"
 * section. When the Go implementation changes, that section and these headers
 * must change in the same commit.
 *
 * Build notes:
 *   - C99, freestanding-friendly (only <stdint.h>/<stddef.h>).
 *   - The crypto and channel interfaces are deliberately abstract: a hosted
 *     agent can back them with libcrypto/libcurl resolved through dynload.h,
 *     a freestanding agent with a vendored implementation.
 *   - The message codecs never allocate; callers own every buffer and decode
 *     results are borrowed slices into the input.
 */

#include "common.h"

#include "crypto.h"
#include "messages.h"
#include "secureconn.h"
#include "transport.h"

#endif /* C2_PROTOCOL_H */
