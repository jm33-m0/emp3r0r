/*
 * c2_common.c — small shared helpers for the C2 protocol library.
 *
 * The byte-order, hex and base64url helpers live as static inline functions in
 * c2_common.h; only the status string table needs a translation unit.
 */

#include "c2_common.h"

const char *c2_status_str(c2_status st) {
  switch (st) {
  case C2_OK:
    return "ok";
  case C2_ERR_ARG:
    return "invalid argument";
  case C2_ERR_NOMEM:
    return "buffer too small";
  case C2_ERR_PROTO:
    return "malformed protocol data";
  case C2_ERR_CRYPTO:
    return "crypto failure";
  case C2_ERR_AUTH:
    return "authentication failure";
  case C2_ERR_IO:
    return "io failure";
  case C2_ERR_TIMEOUT:
    return "timeout";
  case C2_ERR_OVERFLOW:
    return "length out of range";
  case C2_ERR_UNSUPPORTED:
    return "unsupported";
  }
  return "unknown status";
}
