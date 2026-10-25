#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/utsname.h>

#include "beacon_api.h"

struct mac_utsname{
    char    sysname[256];  /* [XSI] Name of OS */
    char    nodename[256]; /* [XSI] Name of this network node */
    char    release[256];  /* [XSI] Release level */
    char    version[256];  /* [XSI] Version level */
    char    machine[256];  /* [XSI] Hardware type */
};

int run_uname(void){
    struct utsname values;
    struct mac_utsname values_mac;
    int retcode = 0;
    char* osversion = getOSName();
    if (strcmp("lin", osversion)==0){
        retcode = uname(&values);
        BeaconPrintf(CALLBACK_OUTPUT, "%s %s %s %s %s\n", values.sysname, values.nodename, values.release, values.version, values.machine);
    }
    else if (strcmp("apple", osversion) == 0 || strcmp("freebsd", osversion) == 0|| strcmp("openbsd", osversion) == 0){
        retcode = uname((struct utsname*)&values_mac);
        BeaconPrintf(CALLBACK_OUTPUT, "%s %s %s %s %s\n", values_mac.sysname, values_mac.nodename, values_mac.release, values_mac.version, values_mac.machine);
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT, "Not supported\n");
    }
    return 0;
}

int go(char* indata, int inlen){
    
    (void)run_uname();
    return 0;
}

#ifdef TEST_UNAME
int main(void){
    return run_uname();
}
#endif
