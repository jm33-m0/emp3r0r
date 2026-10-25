#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "beacon_api.h"

int run_cat(char* filestr){
    FILE* fin = NULL;
    char readin[2049];
    size_t readsize = 1;
    
    memset(readin, 0, 2049);
    if (filestr == NULL){
        return 1;
    }

    fin = fopen(filestr, "r");
    if (fin == NULL){
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to open file: %s\n", filestr);
        return 1;
    }
    while (readsize != 0){
        readsize = fread(readin, 1, 2048, fin);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", readin);
        memset(readin, 0, 2049);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    (void)fclose(fin);
    return 0;
}


int go(char* indata, int inlen){
    datap parser;
    char* filepath = NULL;
    
    BeaconDataParse(&parser, indata, inlen);
    filepath = BeaconDataExtract(&parser, NULL);
        
    (void)run_cat(filepath);
    
    return 0;
}
#ifdef TEST_CAT
int main(int argc, char* argv[]){
    return run_cat(argv[1]);
}
#endif
    
