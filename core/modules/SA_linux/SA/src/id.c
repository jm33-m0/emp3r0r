#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#include "beacon_api.h"

int run_id(void){
    uid_t uid = 0;
    gid_t gid = 0;
    gid_t gidList[25] = {0};
    char* username = NULL;
    char* groupname = NULL;
    struct passwd *pwd;
    struct group *groupval;
    int checkval = 0;
    int counter = 0;

    uid = getuid();
    pwd = getpwuid(uid);
    if (pwd == NULL){
        username = calloc(strlen("UNKNOWN")+1, 1);
        if (username) {
            memcpy(username, "UNKNOWN", strlen("UNKNOWN"));
        }
    }
    else{
        username = calloc(strlen(pwd->pw_name)+1, 1);
        if (username) {
            memcpy(username, pwd->pw_name, strlen(pwd->pw_name));
        }
    }
    gid = getgid();
    checkval = getgroups(25, gidList);
    groupval = getgrgid(gid);
    BeaconPrintf(CALLBACK_OUTPUT, "uid=%d(%s) gid=%d(%s), groups=%d(%s)", uid, username?username:"ERROR", gid, groupval?groupval->gr_name:"ERROR", gid, groupval?groupval->gr_name:"ERROR");
    if (checkval >0){
        for (counter=0; counter < checkval; counter++){
            groupval = getgrgid(gidList[counter]);
            BeaconPrintf(CALLBACK_OUTPUT, ",%d(%s)",gidList[counter], groupval?groupval->gr_name:"ERROR");
        }
    } 
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    if (username){
        free(username);
    }
    return 0;
}

int go(char* indata, int inlen){
    (void)run_id();
    return 0;
}


#ifdef TEST_ID
int main(void){
    return run_id();
}
#endif
