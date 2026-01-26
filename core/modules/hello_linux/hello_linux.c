#include "syscall_helpers.h"
#include "beacon_helpers.h"

// Static buffer for output
static char output[4096];

char* go(char* args, int len) {
    output[0] = '\0';
    size_t current_len = 0;
    
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    char *who = BeaconDataString(&parser);
    if (!who || !who[0]) {
        who = "World";
    }
    
    append_str(output, &current_len, sizeof(output), "Hello ");
    append_str(output, &current_len, sizeof(output), who);
    append_str(output, &current_len, sizeof(output), "!\n");
    
    return output;
}
