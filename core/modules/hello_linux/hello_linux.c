#include "beacon_helpers.h"
#include "syscall_helpers.h"

// Declare BeaconPrintf
extern void BeaconPrintf(int type, const char *fmt, ...);

void go(char *args, int len) {
  datap parser;
  BeaconDataParse(&parser, args, len);

  char *who = BeaconDataString(&parser);
  if (!who || !who[0]) {
    who = "World";
  }

  BeaconPrintf(0, "Hello %s!", who);
}
