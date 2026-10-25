#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <dlfcn.h>

#include "beacon_api.h"


int run_env(void){
    int counter = 0;
    char** environ = getEnviron();
    if (environ == NULL){
        return 1;
    }
    while (environ[counter] != NULL){
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", environ[counter]);
        counter++;
    }
    return 0;
}

int go(char* indata, int inlen){
    
    (void)run_env();
    return 0;
}
#ifdef TEST_ENV
int main(void){
    return run_env();
}
#endif
