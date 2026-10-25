/* Cobalt Strike Beacon compatibility API used by Linux BOFs. */
#ifndef BOF_BEACON_COMPAT_H
#define BOF_BEACON_COMPAT_H

#include <stdint.h>

typedef struct {
  char *original;
  char *buffer;
  int length;
  int size;
} datap;

typedef struct {
  char *original;
  char *buffer;
  int length;
  int size;
} formatp;

/* Resolve a Beacon API name to the loader's implementation. */
void *beacon_api_lookup(const char *name);

/* Captured BeaconPrintf/BeaconOutput data. take transfers ownership. */
void beacon_output_reset(void);
char *beacon_output_take(void);

#endif /* BOF_BEACON_COMPAT_H */
