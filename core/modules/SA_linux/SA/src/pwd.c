#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "beacon_api.h"

int run_pwd(void){
    int retcode = 0;
    char workingdir[256] = {0};
    char* workdir = NULL;
    char* osversion = getOSName();
    workdir = getcwd(workingdir, 255);
    /* An example of working around BeaconPrintf failure for freebsd */
    if (strcmp("freebsd", osversion) == 0){
        if (workdir == NULL){
            BeaconOutput(CALLBACK_OUTPUT, "ERROR\n", 6);
        }
        else{
            BeaconOutput(CALLBACK_OUTPUT, workingdir, strlen(workingdir));
            BeaconOutput(CALLBACK_OUTPUT, "\n", 1);
        }
    }
    else{
        if (workdir == NULL){
            BeaconPrintf(CALLBACK_OUTPUT, "ERROR\n");
        }
        else{
            BeaconPrintf(CALLBACK_OUTPUT, "%s\n", workingdir);
        }
    }
    return 0;
}

int go(char* indata, int inlen){
    
    (void)run_pwd();
    return 0;
}

#ifdef TEST_PWD
int main(void){
    return run_pwd();
}
#endif
