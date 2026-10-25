#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "beacon_api.h"

extern int __xstat(int ver, const char *path, struct stat *buf);

/* Basic memory search that returns the offset */
char* memsearch(char* bytes, char* searchTerm, int size){
    int compareval = 0;
    int counter = 0;
    char* retcode = NULL;
    
    for (counter=0; counter < size; counter++){
        compareval = memcmp(bytes+counter, searchTerm, strlen(searchTerm));
        if (compareval == 0){
            retcode = bytes+counter;
            break;
        }
    }
    return retcode;
}

/* Read chunks, and then compare the memory to that it has a few problems
 * mostly that it will miss anything that happens to be in the overlap 
 * between readin chunks */
int search_contents(char* filestr, char* searchTerm){
    FILE* fin = NULL;
    char readin[2049];
    size_t readsize = 1;
    char* results = 0;
    int returncode = 0;

    memset(readin, 0, 2049);
    if (filestr == NULL){
        return 0;
    }

    fin = fopen(filestr, "r");
    if (fin == NULL){
        //printf("Failed to open file: %s\n", filestr);
        return 0;
    }
    while (readsize != 0){
        readsize = fread(readin, 1, 2048, fin);
        results = memsearch(readin, searchTerm, readsize);
        if (results != NULL){
            returncode = 1;
            break;
        }
        memset(readin, 0, 2049);
    }
    (void)fclose(fin);
    return returncode;
}



/* Type == 1 == Find 
 * Type == 2 == Grep
 * */
char* GrepAndFind(int type, int depth, int maxdepth, const char *sDir, char* searchTerm)
{
    char* buffer = NULL;
    char *p = NULL;
    DIR    *dir_ptr;    // the directory
    struct dirent    *direntp;    // each entry
    struct stat statval;
    int foundtext = 0;
    char* results = NULL;
    
    if (maxdepth != -1 && depth > maxdepth){
        return NULL;
    }
    
    if (type != 0 && searchTerm == NULL){
        return NULL;
    }
    
    if((dir_ptr = opendir(sDir)) == NULL){
        #ifdef DEBUG
        fprintf(stderr, "ls: cannot open %s\n", sDir);
        #endif
    }
    else
    {
        while((direntp=readdir(dir_ptr)) != NULL){
            p = (char *)malloc(strlen(sDir) + strlen(direntp->d_name) + 2);
            if (p == NULL){
                break;
            }
            strcpy(p, sDir);
            strcat(p, "/");
            strcat(p, direntp->d_name);
            __xstat(0, p, &statval);
            /* Skip the . or .. files */
            if (strcmp(".", direntp->d_name) != 0 && strcmp("..", direntp->d_name)){
                if ((statval.st_mode & S_IFMT) == S_IFDIR){
                    //printf("Its a folder\n");
                    GrepAndFind(type, depth+1, maxdepth, p, searchTerm);
                }
                if (type == 1){
                    results = strstr(direntp->d_name, searchTerm);
                    if (results != NULL){
                        BeaconPrintf(CALLBACK_OUTPUT, "Found: %s\n", p);
                    }
                }
                else if (type == 2){
                    foundtext = search_contents(p, searchTerm);
                    if (foundtext){
                        BeaconPrintf(CALLBACK_OUTPUT, "Found: %s\n", p);
                    }
                }
                else{
                    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", p);
                }
            }
            free(p);
        }
        closedir(dir_ptr);
    }
    return buffer;
}

int go(char* indata, int inlen){
    datap parser;
    char* folderpath = NULL;
    int maxdepth = 0;
    BeaconDataParse(&parser, indata, inlen);
    maxdepth = BeaconDataInt(&parser);
    folderpath = BeaconDataExtract(&parser, NULL);
    (void)GrepAndFind(0, 0, maxdepth, folderpath, NULL);
    return 0;
}


#ifdef TEST_WALK
int main(int argc, char* argv[]){
    GrepAndFind(0, 0, 2, argv[1], argv[2]);
    return 0;
}
#endif
