#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "beacon_api.h"

extern int __xstat(int ver, const char *path, struct stat *buf);

int cat_action(char* filestr){
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



int readlink_action(char* filepath){
    char outdata[255] = {0};
    ssize_t readsize = 0;
    readsize = readlink(filepath, outdata, 255);
    if (readsize == -1){
        BeaconPrintf(CALLBACK_OUTPUT, "%s: Failure\n", filepath);
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT, "%s: %s\n", filepath, outdata);
    }
    
    return 0;
}



/* Search section of bytes to see if searchTerm is there */
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

/* Search contents of a file, by reading everything in a loop and
 * then compare it to the searchTerm with memsearch */
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
 * findaction == 1 == cat
 * findaction == 2 == readlink
 * partOrWhole == 1 == part
 * */
char* GrepAndFind(int type, int depth, int maxdepth, const char *sDir, char* searchTerm, char* filename, int findaction, int partOrWhole)
{
    char* buffer = NULL;
    char *p = NULL;
    DIR    *dir_ptr;    // the directory
    struct dirent    *direntp;    // each entry
    struct stat statval;
    int foundtext = 0;
    char* results = NULL;
    int throttleCount = 0;
    
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
            throttleCount++;
            if (throttleCount%10 == 0){
                throttleCount = 0;
                usleep(1000);
            }
            /* Skip the . or .. files */
            if (strcmp(".", direntp->d_name) != 0 && strcmp("..", direntp->d_name)){
                if ((statval.st_mode & S_IFMT) == S_IFDIR){
                    //printf("Its a folder\n");
                    GrepAndFind(type, depth+1, maxdepth, p, searchTerm, filename, findaction, partOrWhole);
                }
                if (type == 1){
                    results = NULL;
                    if (partOrWhole == 1){
                        results = strstr(direntp->d_name, searchTerm);
                    }
                    else{
                        if (0 == strcmp(direntp->d_name, searchTerm)){
                            results = (void*)-1;
                        }
                    }
                    if (results != NULL && findaction == 0){
                        BeaconPrintf(CALLBACK_OUTPUT, "Found: %s\n", p);
                    }
                    else if (results != NULL && findaction == 2){
                        readlink_action(p);
                    }
                    else if (results != NULL && findaction == 1){
                        cat_action(p);
                    }
                }
                else if (type == 2){
                    if (filename == NULL){
                        foundtext = search_contents(p, searchTerm);
                        if (foundtext){
                            BeaconPrintf(CALLBACK_OUTPUT, "Found: %s\n", p);
                        }
                    }
                    else{
                        results = strstr(direntp->d_name, filename);
                        if (results){
                            foundtext = search_contents(p, searchTerm);
                            if (foundtext){
                                BeaconPrintf(CALLBACK_OUTPUT, "Found: %s\n", p);
                            }
                        }
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
    char* searchpath = NULL;
    char* filepath = NULL;
    int maxdepth = 0;
    int findaction = 0;
    int partOrWhole = 0;
    
    BeaconDataParse(&parser, indata, inlen);
    folderpath = BeaconDataExtract(&parser, NULL);
    searchpath = BeaconDataExtract(&parser, NULL);
    filepath = BeaconDataExtract(&parser, NULL);
    maxdepth = BeaconDataInt(&parser);
    findaction = BeaconDataInt(&parser);
    partOrWhole = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "Folder: %s\n", folderpath);
    BeaconPrintf(CALLBACK_OUTPUT, "Search: %s\n", searchpath);
    BeaconPrintf(CALLBACK_OUTPUT, "Filename: %s\n", filepath);
    if (filepath[0] == 0){
        BeaconPrintf(CALLBACK_OUTPUT, "Setting it to NULL\n");
        filepath = NULL;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Depth: %d\n", maxdepth);
    (void)GrepAndFind(2, 0, maxdepth, folderpath, searchpath, filepath, findaction, partOrWhole);
    
    return 0;
}

#ifdef TEST_GREP
int main(int argc, char* argv[]){
    GrepAndFind(2, 0, atoi(argv[1]), argv[4], argv[5], argv[6], atoi(argv[2]), atoi(argv[3]));
    return 0;
}
#endif
