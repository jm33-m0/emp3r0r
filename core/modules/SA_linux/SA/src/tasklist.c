#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#ifndef DEBUG
#include "beacon_api.h"
#else
#define BeaconOutput(x, y, z) write(1, y, z)
#endif

char* getContents(unsigned char* filepath, uint32_t* outsize){
    FILE *fin = NULL;
    uint32_t fsize = 0;
    uint32_t readsize = 0;
    unsigned char* buffer = NULL;
    unsigned char* tempbuffer = NULL;

    fin = fopen((char*)filepath, "rb");
    if (fin == NULL){
        return NULL;
    }
    //fseek(fin, 0, SEEK_END);
    //fsize = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    fsize = 0x10000;
    tempbuffer = calloc(fsize, 1);
    if (tempbuffer == NULL){
        return NULL;
    }
    memset(tempbuffer, 0, fsize);
    readsize = fread(tempbuffer, 1, fsize, fin);
    *outsize = readsize;
    fclose(fin);
    if (readsize == 0){
        free(tempbuffer);
        return NULL;
    }
    buffer = calloc(readsize, 1);
    if (buffer == NULL){
        return NULL;
    }
    memset(buffer, 0, readsize);
    memcpy(buffer, tempbuffer, readsize-1);
    free(tempbuffer);
    return (char*)buffer;
}


int go(char* indata, int inlen){
    char* results = NULL;
    char* tempresults = NULL;
    DIR* procdir = NULL;
    struct dirent *proc_entry;
    char* filepath = NULL;
    char proc_path[320];
    char* statusfile = NULL;
    char* cmdline = NULL;
    char* ptr = NULL;
    char* linename = NULL;
    char* linecontents = NULL;
    char* uid = NULL;
    char* ppid = NULL;
    char* state = NULL;
    char* fullline = NULL;
    int resultslen = 0;
    uint32_t filesize = 0;
    int i = 0;
    filepath = calloc(4096, 1);
    linename = calloc(256, 1);
    linecontents = calloc(2048, 1);
    uid = calloc(50, 1);
    ppid = calloc(50, 1);
    state = calloc(10, 1);
    
    if (!filepath || !linename || !linecontents || !uid || !ppid || !state){
        goto cleanup;
    }
    
    procdir = opendir( "/proc/" );
    while( NULL != (proc_entry = readdir(procdir))){
        if (strspn(proc_entry->d_name, "0123456789" ) == strlen(proc_entry->d_name)){
            memset(proc_path, 0, 320);
            memset(filepath, 0, 4096);
            memset(linecontents, 0, 2048);
            sprintf(proc_path, "/proc/%s/exe", proc_entry->d_name);
            readlink(proc_path, filepath, 4095);
            memset(proc_path, 0, 256);
            sprintf(proc_path, "/proc/%s/status", proc_entry->d_name);
            statusfile = getContents((unsigned char*)proc_path, &filesize);
            if (statusfile == NULL){
                continue;
            }
            sprintf(proc_path, "/proc/%s/cmdline", proc_entry->d_name);
            cmdline = getContents((unsigned char*)proc_path, &filesize);
            if (cmdline != NULL){
                for (i=0; i<filesize-1; i++){
                    if (cmdline[i] == 0){
                        cmdline[i] = ' ';
                    }
                }
            }
            ptr = strtok(statusfile, "\n");
            while (ptr){
                sscanf(ptr, "%s\t%s", linename, linecontents);
                if (strcmp(linename, "Uid:") == 0){
                    memcpy(uid, linecontents, 49);
                }
                else if (strcmp(linename, "PPid:") == 0){
                    memcpy(ppid, linecontents, 49);
                }
                else if (strcmp(linename, "State:") == 0){
                    memcpy(state, linecontents, 9);
                }
                else if (cmdline != NULL){
                    if (filepath[0] == 0 ||strlen(filepath) < strlen(cmdline)){
                        if (strlen(cmdline) < 4095){
                            memcpy(filepath, cmdline, strlen(cmdline));
                        }
                        else{
                            memcpy(filepath, cmdline, 4095);
                        }
                    }
                }
                else if (filepath[0] == 0 && strcmp(linename, "Name:") == 0){
                    memcpy(filepath, linecontents, strlen(linecontents));
                }
                ptr = strtok(NULL, "\n");
            }

            fullline = calloc(strlen(uid)+strlen(ppid)+strlen(state)+strlen(filepath)+strlen(proc_entry->d_name)+25, 1);
            if (fullline == NULL){
                if (statusfile){
                    free(statusfile);
                    statusfile = NULL;
                }
                if (cmdline){
                    free(cmdline);
                    cmdline = NULL;
                }
                break;
            }
            sprintf(fullline, "%s\t%s\t%s\t%s\t%s\n", uid, proc_entry->d_name, ppid, state, filepath);
            tempresults = realloc(results, resultslen+strlen(fullline)+1);
            if (tempresults == NULL){
                if (fullline){
                    free(fullline);
                    fullline = NULL;
                }
                if (statusfile){
                    free(statusfile);
                    statusfile = NULL;
                }
                if (cmdline){
                    free(cmdline);
                    cmdline = NULL;
                }
                goto error;
            }
            results = tempresults;
            memset(results+resultslen, 0, strlen(fullline)+1);
            memcpy(results+resultslen, fullline, strlen(fullline));
            resultslen += strlen(fullline);
            if (cmdline){
                free(cmdline);
                cmdline = NULL;
            }
            if (statusfile){
                free(statusfile);
                statusfile = NULL;
            }
            if (fullline){
                free(fullline);
                fullline = NULL;
            }
        }
    }
    BeaconOutput(CALLBACK_OUTPUT, results, strlen(results));
    
    if (results){
        free(results);
        results = NULL;
    }
    goto cleanup;
   
retlab:
    return 0;

error:

cleanup:
    if (procdir){
        closedir(procdir);
        procdir = NULL;
    }
    /* Free all temporary allocated buffers*/
    if (filepath){
        memset(filepath, 0, 4096);
        free(filepath);
        filepath = NULL;
    }
    if (linename){
        memset(linename, 0, 256);
        free(linename);
        linename = NULL;
    }
    if (linecontents){
        memset(linecontents, 0, 2048);
        free(linecontents);
        linecontents = NULL;
    }
    if (uid){
        memset(uid, 0, 50);
        free(uid);
        uid = NULL;
    }
    if (ppid){
        memset(ppid, 0, 50);
        free(ppid);
        ppid = NULL;
    }
    if (state){
        memset(state, 0, 10);
        free(state);
        state = NULL;
    }
    goto retlab;
}

#ifdef DEBUG

int main(void){
    (void)go(NULL, 0);
    return 0;
}
#endif
