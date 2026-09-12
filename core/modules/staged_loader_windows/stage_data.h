/*
 * staged_loader embedded stage data.
 *
 * build.sh generates stage_data.S, which .incbin's the four packed artifacts
 * (RC4-encrypted stage DLL + its key, and the RC4-encrypted shellcode blob +
 * its key). The symbols below delimit each blob; lengths are (end - start).
 *
 * Unlike RCDATA resources these live in a plain data section, so they are
 * available to any host, including a DLL that is mapped in memory rather than
 * loaded with LoadLibrary.
 */
#ifndef STAGED_LOADER_STAGE_DATA_H
#define STAGED_LOADER_STAGE_DATA_H

extern const unsigned char staged_loader_stage_start[];
extern const unsigned char staged_loader_stage_end[];
extern const unsigned char staged_loader_stage_key_start[];
extern const unsigned char staged_loader_stage_key_end[];
extern const unsigned char staged_loader_payload_start[];
extern const unsigned char staged_loader_payload_end[];
extern const unsigned char staged_loader_key_start[];
extern const unsigned char staged_loader_key_end[];

#endif /* STAGED_LOADER_STAGE_DATA_H */
