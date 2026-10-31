/*
 * rv_host_posix.c — Linux host-call backend for the rvvm interpreter.
 *
 * Serves the guest BOF runtime's file and process requests with libc. The
 * Windows build uses rv_host_win32.c instead.
 */

#define _GNU_SOURCE

#include "rv_host.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#define RV_FILES_MAX 32
#define RV_DIRS_MAX 16

struct rv_posix_file {
  int fd;
  int used;
};

static struct rv_posix_file rv_files[RV_FILES_MAX];
static DIR *rv_dirs[RV_DIRS_MAX];

static int rv_new_file(int fd) {
  if (fd < 0)
    return -errno;
  for (int i = 3; i < RV_FILES_MAX; i++) {
    if (!rv_files[i].used) {
      rv_files[i].fd = fd;
      rv_files[i].used = 1;
      return i;
    }
  }
  close(fd);
  return -EMFILE;
}

static struct rv_posix_file *rv_get_file(uint32_t slot) {
  if (slot < 3 || slot >= RV_FILES_MAX || !rv_files[slot].used)
    return NULL;
  return &rv_files[slot];
}

/* ---- host-call services -------------------------------------------------- */
/* The guest fills the mailbox and stores the doorbell. Everything below runs
 * on the interpreter thread, so the module can call libc directly. */

static uint32_t rv_hc_ret(int r) {
  return r < 0 ? (uint32_t)(-errno) : (uint32_t)r;
}

static int rv_hc_to_flags(uint32_t f) {
  int flags;
  switch (f & 3u) {
  case RV_O_WRONLY:
    flags = O_WRONLY;
    break;
  case RV_O_RDWR:
    flags = O_RDWR;
    break;
  default:
    flags = O_RDONLY;
    break;
  }
  if (f & RV_O_CREAT)
    flags |= O_CREAT;
  if (f & RV_O_EXCL)
    flags |= O_EXCL;
  if (f & RV_O_TRUNC)
    flags |= O_TRUNC;
  if (f & RV_O_APPEND)
    flags |= O_APPEND;
  if (f & RV_O_DIRECTORY)
    flags |= O_DIRECTORY;
  return flags;
}

static void rv_fill_stat(struct rv_hc_stat *raw, const struct stat *st) {
  memset(raw, 0, sizeof(*raw));
  raw->mode = (uint32_t)st->st_mode;
  raw->nlink = (uint32_t)st->st_nlink;
  raw->uid = (uint32_t)st->st_uid;
  raw->gid = (uint32_t)st->st_gid;
  raw->dev = (uint32_t)st->st_dev;
  raw->ino = (uint32_t)st->st_ino;
  raw->rdev = (uint32_t)st->st_rdev;
  raw->size_lo = (uint32_t)((uint64_t)st->st_size);
  raw->size_hi = (uint32_t)((uint64_t)st->st_size >> 32);
  raw->mtime_lo = (uint32_t)st->st_mtime;
  raw->mtime_hi = (uint32_t)((uint64_t)st->st_mtime >> 32);
  raw->atime_lo = (uint32_t)st->st_atime;
  raw->atime_hi = (uint32_t)((uint64_t)st->st_atime >> 32);
  raw->ctime_lo = (uint32_t)st->st_ctime;
  raw->ctime_hi = (uint32_t)((uint64_t)st->st_ctime >> 32);
}

void rv_host_dispatch(struct rv_hc_req *req) {
  char path[1024];
  int r = 0;

  req->data_len = 0;
  switch (req->op) {
  case RV_HC_GETCWD: {
    char *dst = (char *)rv_gptr(req->a0, req->a1);
    if (dst == NULL || req->a1 == 0) {
      req->result = (int32_t)-EINVAL;
      break;
    }
    if (getcwd(dst, req->a1) == NULL)
      r = -errno;
    break;
  }
  case RV_HC_OPEN:
    if (rv_guest_cstr(req->a0, path, sizeof(path)) != 0) {
      req->result = (int32_t)-EINVAL;
      break;
    }
    {
      int fd = open(path, rv_hc_to_flags(req->a1), (mode_t)req->a2);
      r = rv_new_file(fd);
    }
    break;
  case RV_HC_READ: {
    uint8_t *dst = rv_gptr(req->a1, req->a2);
    if (dst == NULL) {
      req->result = (int32_t)-EINVAL;
      break;
    }
    struct rv_posix_file *f = rv_get_file(req->a0);
    if (f == NULL) {
      req->result = (int32_t)-EBADF;
      break;
    }
    r = (int)read(f->fd, dst, req->a2);
    break;
  }
  case RV_HC_WRITE: {
    uint8_t *src = rv_gptr(req->a1, req->a2);
    if (src == NULL) {
      req->result = (int32_t)-EINVAL;
      break;
    }
    if (req->a0 == 1 || req->a0 == 2) {
      r = rv_out_append(src, req->a2) == 0 ? (int)req->a2 : -ENOSPC;
    } else {
      struct rv_posix_file *f = rv_get_file(req->a0);
      if (f == NULL) {
        req->result = (int32_t)-EBADF;
        break;
      }
      r = (int)write(f->fd, src, req->a2);
    }
    break;
  }
  case RV_HC_CLOSE: {
    struct rv_posix_file *f = rv_get_file(req->a0);
    if (f == NULL) {
      req->result = (int32_t)-EBADF;
      break;
    }
    r = close(f->fd);
    f->used = 0;
    f->fd = -1;
    break;
  }
  case RV_HC_LSEEK: {
    struct rv_posix_file *f = rv_get_file(req->a0);
    if (f == NULL) {
      req->result = (int32_t)-EBADF;
      break;
    }
    uint64_t off = ((uint64_t)req->a2 << 32) | req->a1;
    r = (int)lseek(f->fd, (off_t)off, (int)req->a3);
    break;
  }
  case RV_HC_UNAME: {
    struct utsname *u = (struct utsname *)rv_gptr(req->a0, sizeof(*u));
    if (u == NULL) {
      req->result = (int32_t)-EINVAL;
      break;
    }
    r = uname(u);
    break;
  }
  case RV_HC_GETENV: {
    if (rv_guest_cstr(req->a0, path, sizeof(path)) != 0) {
      req->result = (int32_t)-EINVAL;
      break;
    }
    const char *v = getenv(path);
    if (v == NULL) {
      r = -ENOENT;
      break;
    }
    size_t n = strlen(v);
    if (n >= sizeof(req->data))
      n = sizeof(req->data) - 1;
    memcpy(req->data, v, n);
    req->data[n] = '\0';
    req->data_len = (uint32_t)(n + 1);
    r = (int)n;
    break;
  }
  case RV_HC_ENVIRON: {
    /* Read /proc/self/environ instead of importing the `environ` data
     * symbol: the in-memory ELF loaders resolve function imports only. */
    uint8_t *dst = rv_gptr(req->a0, req->a1);
    if (dst == NULL) {
      req->result = (int32_t)-EINVAL;
      break;
    }
    int fd = open("/proc/self/environ", O_RDONLY);
    if (fd < 0) {
      r = -errno;
      break;
    }
    size_t used = 0;
    while (used < req->a1) {
      ssize_t n = read(fd, dst + used, req->a1 - used);
      if (n <= 0)
        break;
      used += (size_t)n;
    }
    close(fd);
    if (used < req->a1)
      dst[used++] = '\0';
    r = (int)used;
    break;
  }
  case RV_HC_GETUID:
    r = (int)getuid();
    break;
  case RV_HC_GETEUID:
    r = (int)geteuid();
    break;
  case RV_HC_GETGID:
    r = (int)getgid();
    break;
  case RV_HC_GETEGID:
    r = (int)getegid();
    break;
  case RV_HC_GETGROUPS: {
    if (req->a1 > 256)
      req->a1 = 256;
    gid_t *dst = (gid_t *)rv_gptr(req->a0, req->a1 * sizeof(gid_t));
    if (dst == NULL) {
      req->result = (int32_t)-EINVAL;
      break;
    }
    r = getgroups((int)req->a1, dst);
    break;
  }
  case RV_HC_GETPWUID: {
    struct passwd *pw = getpwuid((uid_t)req->a0);
    if (pw == NULL) {
      r = -ENOENT;
      break;
    }
    size_t n = 0;
    const char *fields[3] = {pw->pw_name ? pw->pw_name : "",
                             pw->pw_dir ? pw->pw_dir : "",
                             pw->pw_shell ? pw->pw_shell : ""};
    for (int i = 0; i < 3; i++) {
      size_t l = strlen(fields[i]) + 1;
      if (n + l > sizeof(req->data))
        break;
      memcpy(req->data + n, fields[i], l);
      n += l;
    }
    req->data_len = (uint32_t)n;
    req->a0 = (uint32_t)pw->pw_uid;
    req->a1 = (uint32_t)pw->pw_gid;
    r = 1;
    break;
  }
  case RV_HC_GETGRGID: {
    struct group *gr = getgrgid((gid_t)req->a0);
    if (gr == NULL) {
      r = -ENOENT;
      break;
    }
    size_t n = strlen(gr->gr_name) + 1;
    if (n > sizeof(req->data))
      n = sizeof(req->data);
    memcpy(req->data, gr->gr_name, n);
    req->data_len = (uint32_t)n;
    req->a0 = (uint32_t)gr->gr_gid;
    r = 1;
    break;
  }
  case RV_HC_READLINK: {
    uint8_t *dst = rv_gptr(req->a1, req->a2);
    if (dst == NULL || rv_guest_cstr(req->a0, path, sizeof(path)) != 0) {
      req->result = (int32_t)-EINVAL;
      break;
    }
    r = (int)readlink(path, (char *)dst, req->a2);
    break;
  }
  case RV_HC_CHMOD:
    if (rv_guest_cstr(req->a0, path, sizeof(path)) != 0) {
      req->result = (int32_t)-EINVAL;
      break;
    }
    r = chmod(path, (mode_t)req->a1);
    break;
  case RV_HC_STAT:
  case RV_HC_LSTAT: {
    struct stat st;
    struct rv_hc_stat *raw = (struct rv_hc_stat *)req->data;
    if (rv_guest_cstr(req->a0, path, sizeof(path)) != 0) {
      req->result = (int32_t)-EINVAL;
      break;
    }
    r = req->op == RV_HC_STAT ? stat(path, &st) : lstat(path, &st);
    if (r == 0) {
      rv_fill_stat(raw, &st);
      req->data_len = (uint32_t)sizeof(*raw);
    }
    break;
  }
  case RV_HC_OPENDIR: {
    int slot = -1;
    for (int i = 0; i < RV_DIRS_MAX; i++) {
      if (rv_dirs[i] == NULL) {
        slot = i;
        break;
      }
    }
    if (slot < 0) {
      r = -EMFILE;
      break;
    }
    if (rv_guest_cstr(req->a0, path, sizeof(path)) != 0) {
      req->result = (int32_t)-EINVAL;
      break;
    }
    rv_dirs[slot] = opendir(path);
    r = rv_dirs[slot] != NULL ? slot : -errno;
    break;
  }
  case RV_HC_READDIR: {
    int slot = (int)req->a0;
    if (slot < 0 || slot >= RV_DIRS_MAX || rv_dirs[slot] == NULL) {
      req->result = (int32_t)-EBADF;
      break;
    }
    struct dirent *e = readdir(rv_dirs[slot]);
    if (e == NULL) {
      r = 0;
      break;
    }
    struct rv_hc_dirent *out = (struct rv_hc_dirent *)req->data;
    memset(out, 0, sizeof(*out));
    out->type = e->d_type;
    size_t n = strlen(e->d_name);
    if (n >= sizeof(out->name))
      n = sizeof(out->name) - 1;
    memcpy(out->name, e->d_name, n);
    out->name[n] = '\0';
    out->name_len = (uint32_t)n;
    req->data_len = (uint32_t)sizeof(*out);
    r = 1;
    break;
  }
  case RV_HC_CLOSEDIR: {
    int slot = (int)req->a0;
    if (slot < 0 || slot >= RV_DIRS_MAX || rv_dirs[slot] == NULL) {
      req->result = (int32_t)-EBADF;
      break;
    }
    r = closedir(rv_dirs[slot]);
    rv_dirs[slot] = NULL;
    break;
  }
  case RV_HC_USLEEP:
    r = usleep(req->a0);
    break;
  case RV_HC_GETPID:
    r = (int)getpid();
    break;
  case RV_HC_ISATTY: {
    if (req->a0 == 0 || req->a0 == 1 || req->a0 == 2) {
      r = 0;
    } else {
      struct rv_posix_file *f = rv_get_file(req->a0);
      if (f == NULL) {
        req->result = (int32_t)-EBADF;
        break;
      }
      r = isatty(f->fd);
    }
    break;
  }
  default:
    req->result = (int32_t)-ENOSYS;
    return;
  }
  req->result = (int32_t)rv_hc_ret(r);
}

void rv_host_reset(void) {
  for (int i = 0; i < RV_FILES_MAX; i++) {
    if (rv_files[i].used) {
      if (rv_files[i].fd >= 0)
        close(rv_files[i].fd);
      rv_files[i].used = 0;
      rv_files[i].fd = -1;
    }
  }
  for (int i = 0; i < RV_DIRS_MAX; i++) {
    if (rv_dirs[i] != NULL) {
      closedir(rv_dirs[i]);
      rv_dirs[i] = NULL;
    }
  }
}
