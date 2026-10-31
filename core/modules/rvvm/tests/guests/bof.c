/* Test BOF: exercises the guest runtime's Beacon data parser and formatter. */
#include <string.h>

typedef struct {
  char *original;
  char *buffer;
  int length;
  int size;
} datap;

extern void BeaconDataParse(datap *parser, char *buffer, int size);
extern char *BeaconDataExtract(datap *parser, int *size);
extern void BeaconPrintf(int type, const char *fmt, ...);

int go(char *args, int len) {
  datap parser;
  BeaconDataParse(&parser, args, len);
  int n = 0;
  char *who = BeaconDataExtract(&parser, &n);
  if (who == NULL) {
    BeaconPrintf(0, "bof none");
    return 0;
  }
  BeaconPrintf(0, "bof %s (%d)", who, n);
  return 0;
}
