#ifndef C2_MODULE_H
#define C2_MODULE_H

/*
 * c2_module.h — decode a COFF module invocation (the `!custom_module` payload).
 *
 * The C2 renders def.ResolvedInvocation with concrete argument values and
 * base64-encodes it. c2_coff_invocation_parse extracts the COFF export and
 * arguments as the token strings the BOF loader packs, so the C agent runs a
 * module exactly like the Go agent's ModuleHandler does for `coff`.
 */

#include "c2_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Decode `b64` (standard or URL-safe base64 CBOR) and extract the COFF export
 * and arguments. `export_name` receives the entry point (empty when the
 * invocation does not set one; callers default to "go"). Each argument token is
 * appended to `buf` (the running offset is `*buf_used`) and recorded in
 * `tokens`; at most `tokens_cap` tokens are produced. Returns C2_OK, or
 * C2_ERR_PROTO/C2_ERR_NOMEM on malformed input / exhausted storage.
 */
c2_status c2_coff_invocation_parse(const char *b64, size_t b64len,
                                   char *export_name, size_t export_cap,
                                   c2_str *tokens, size_t *tokenc,
                                   size_t tokens_cap, char *buf, size_t buf_cap,
                                   size_t *buf_used);

#ifdef __cplusplus
}
#endif

#endif /* C2_MODULE_H */
