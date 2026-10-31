#ifndef C2_GZIP_H
#define C2_GZIP_H

/*
 * gzip.h — gzip container support.
 *
 * Two wire paths need gzip:
 *   - FTP upload: the agent must send a gzip stream (the operator gunzips it);
 *     an uncompressed stream is rejected.
 *   - module download: `!custom_module` hosts a .gz payload that the agent must
 *     decompress before dispatching.
 *
 * Both directions use a compression provider selected at build time with
 * `GZIP=<name>` (see the Makefile): src/gzip/c2_gzip_<name>.c. The default is
 * the vendored miniz (DEFLATE/INFLATE), so gzip is self-contained; `none`
 * stubs it out for builds that do not need it, and a provider can be added by
 * dropping src/gzip/c2_gzip_<name>.c into the tree. All providers are pure
 * in-memory byte transforms.
 */

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Worst-case output size of c2_gzip_compress for `in_len` bytes. */
size_t c2_gzip_bound(size_t in_len);

/* Wrap `in` in a gzip container. Returns C2_OK and sets *out_len, or
 * C2_ERR_NOMEM when it does not fit in `out_cap`. */
c2_status c2_gzip_compress(const uint8_t *in, size_t in_len, uint8_t *out,
                           size_t out_cap, size_t *out_len);

/* Inflate a gzip stream and verify its CRC-32/ISIZE. Returns C2_ERR_PROTO on a
 * malformed stream or C2_ERR_NOMEM when the result does not fit. */
c2_status c2_gzip_decompress(const uint8_t *in, size_t in_len, uint8_t *out,
                             size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* C2_GZIP_H */
