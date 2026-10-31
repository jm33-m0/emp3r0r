#ifndef RV_HOSTCALL_H
#define RV_HOSTCALL_H

/*
 * rv_hostcall.h — guest/host service ABI for the rvvm_linux interpreter.
 *
 * The guest cannot make syscalls. It asks the module for a host service by
 * filling the mailbox at RV_HC_GUEST_ADDR and storing RV_HC_MAGIC to the
 * doorbell MMIO register. The module performs the operation and writes the
 * result back into the mailbox before the store returns.
 *
 * All fields are 32-bit so the layout is identical for the RV32 guest and a
 * 64-bit host; 64-bit values (file sizes, times) are split into low/high
 * words. Pointers are guest addresses inside RV_RAM_BASE..RV_RAM_END and are
 * validated by the module before every access.
 *
 * This header is shared by rvvm.c (host side) and the guest BOF runtime. It
 * must stay free of libc types.
 */

#include <stdint.h>

#define RV_RAM_BASE 0x80000000u
#define RV_RAM_SIZE_DEFAULT (8u << 20)
#define RV_RAM_END_DEFAULT (RV_RAM_BASE + RV_RAM_SIZE_DEFAULT)

/* Mailbox: one page reserved inside guest RAM, below the stack. */
#define RV_HC_OFFSET 0x001FF000u
#define RV_HC_GUEST_ADDR (RV_RAM_BASE + RV_HC_OFFSET)
#define RV_HC_DATA_CAP 2048u

/* MMIO doorbell. A store of RV_HC_MAGIC triggers one host call. */
#define RV_HC_DOORBELL 0x10004000u
#define RV_HC_MAGIC 0x48524331u /* "HRC1" */

/* Portable open flags, translated to host flags by the module. */
#define RV_O_RDONLY 0x0000u
#define RV_O_WRONLY 0x0001u
#define RV_O_RDWR 0x0002u
#define RV_O_CREAT 0x0040u
#define RV_O_EXCL 0x0080u
#define RV_O_TRUNC 0x0200u
#define RV_O_APPEND 0x0400u
#define RV_O_DIRECTORY 0x10000u

/* Portable lseek whence values (identical to Linux/musl). */
#define RV_SEEK_SET 0
#define RV_SEEK_CUR 1
#define RV_SEEK_END 2

enum rv_hc_op {
  RV_HC_GETCWD = 1,
  RV_HC_OPEN,
  RV_HC_READ,
  RV_HC_WRITE,
  RV_HC_CLOSE,
  RV_HC_LSEEK,
  RV_HC_UNAME,
  RV_HC_GETENV,
  RV_HC_ENVIRON,
  RV_HC_GETUID,
  RV_HC_GETEUID,
  RV_HC_GETGID,
  RV_HC_GETEGID,
  RV_HC_GETGROUPS,
  RV_HC_GETPWUID,
  RV_HC_GETGRGID,
  RV_HC_READLINK,
  RV_HC_CHMOD,
  RV_HC_STAT,
  RV_HC_LSTAT,
  RV_HC_OPENDIR,
  RV_HC_READDIR,
  RV_HC_CLOSEDIR,
  RV_HC_USLEEP,
  RV_HC_GETPID,
  RV_HC_ISATTY
};

struct rv_hc_req {
  uint32_t op;
  int32_t result;    /* host return value: >=0 or -errno */
  uint32_t data_len; /* bytes written to data for this call */
  uint32_t a0, a1, a2, a3;
  uint8_t data[RV_HC_DATA_CAP];
};

/* Neutral stat result. Times and sizes are 64-bit values split in two. */
struct rv_hc_stat {
  uint32_t mode;
  uint32_t nlink;
  uint32_t uid;
  uint32_t gid;
  uint32_t dev;
  uint32_t ino;
  uint32_t rdev;
  uint32_t size_lo, size_hi;
  uint32_t mtime_lo, mtime_hi;
  uint32_t atime_lo, atime_hi;
  uint32_t ctime_lo, ctime_hi;
};

/* Neutral directory entry written into the mailbox data area. */
struct rv_hc_dirent {
  uint32_t type; /* DT_* value */
  uint32_t name_len;
  char name[256];
};

/* Neutral passwd/group record: numeric ids in result/a0, strings in data. */
#define RV_HC_ID_CAP 256u

#endif /* RV_HOSTCALL_H */
