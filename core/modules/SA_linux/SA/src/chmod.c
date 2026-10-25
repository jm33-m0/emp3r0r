#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "beacon_api.h"

int run_chmod(char* permissionString, char* filepath){
    int arg1len = 0;
    mode_t permissions = 0;
    int tempvalue = 0;
    char temparg[2] = {0};
    int startvalue = 0;
    int counter = 0;
    /* NOTE: Yes this is gross, but I don't know of a better way to convert
     *  inputted ascii text to octal numbers, so this is how I'm doing it.
     *  It's a table of permission values that we can iterate over and use
     *  sort of as a state table. */
    int options[][6] = {{00, 01000, 02000, 00, 04000},
        {00, 00100, 00200, 00, 00400},
        {00, 00010, 00020, 00, 00040},
        {00, 00001, 00002, 00, 00004}};
    
   
    if (permissionString == NULL || filepath == NULL){
        return 1;
    }
    arg1len = strlen(permissionString);
    printf("Arg1Len: %d\n", arg1len);
    /* If len is 4, start at 0 */
    if (arg1len == 3){
        startvalue = 1;
    }
    
    if (arg1len < 3 || arg1len > 4){
        return 1;
    }
    for (counter = 0; counter <= arg1len; counter++){
        temparg[0] = permissionString[counter];
        tempvalue = atoi(temparg);
        printf("Tempvalue:%d\n", tempvalue);
        if (tempvalue & 1){
            permissions |= options[counter+startvalue][1];
        }
        if (tempvalue & 2){
            permissions |= options[counter+startvalue][2];
        }
        if (tempvalue & 4){
            permissions |= options[counter+startvalue][4];
        }
    }

    chmod(filepath, permissions);

    return 0;
}

int go(char* indata, int inlen){
    datap parser;
    char* filepath = NULL;
    char* permissions = NULL;
    int checkcode = 0;
    
    BeaconDataParse(&parser, indata, inlen);
    permissions = BeaconDataExtract(&parser, NULL);
    filepath = BeaconDataExtract(&parser, NULL);
        
    checkcode = run_chmod(permissions, filepath);
    if (checkcode == 0){
        BeaconPrintf(CALLBACK_OUTPUT, "Chmod Success\n");
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT, "Chmod Success\n");
    }
        
    
    return 0;
}



#ifdef TEST_CHMOD
int main(int argc, char* argv[]){
    if (argc < 2){
        printf("%s 777 ./path/to/file.txt\n", argv[0]);
        return 0;
    }
 
    return run_chmod(argv[1], argv[2]);
}
#endif
