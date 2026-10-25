#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#include "beacon_api.h"

#define PATH_MAX 2048

int test3(void){
    printf("This is the test3 function\n");
    return 0;
}


int go(char* indata, int inlen){
    char* pwdOutput = NULL;
    char* testptr = NULL;
    pwdOutput = calloc(PATH_MAX+1, 1);
        
    BeaconPrintf(CALLBACK_OUTPUT, "UID: %d EUID: %d\n", getuid(), geteuid());
    if (pwdOutput != NULL){
        testptr = getcwd(pwdOutput, PATH_MAX);
        if (testptr != NULL){
            BeaconPrintf(CALLBACK_OUTPUT, "Current Working Directory: %s\n", testptr);
        }
    }
    if (getuid() == 0){
        BeaconPrintf(CALLBACK_OUTPUT, "Running as root!!!!\n");
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT, "Running as a standard user.\n");
    }
    if (pwdOutput){
        free(pwdOutput);
    }
    return 0;
}
