/*
 * rv_host_win32.c — Windows host-call backend for the rvvm interpreter.
 *
 * Serves the guest BOF runtime's file and process requests with the Win32 API
 * (kernel32 only). Handles are exposed to the 32-bit guest as small slot
 * indices; struct layouts are the neutral rv_hostcall.h ones, so the guest
 * runtime does not depend on Windows headers.
 */

#include <windows.h>

#include "rv_host.h"

#define RV_FILES_MAX 32
#define RV_DIRS_MAX 16
#define RV_PATH_MAX 1024

struct rv_win_file {
  HANDLE h;
  int used;
};

struct rv_win_dir {
  HANDLE h;
  int used;
  int first;
  WIN32_FIND_DATAA data;
};

static struct rv_win_file rv_files[RV_FILES_MAX];
static struct rv_win_dir rv_dirs[RV_DIRS_MAX];

static void win_zero(void *p, size_t n) {
  unsigned char *b = (unsigned char *)p;
  for (size_t i = 0; i < n; i++)
    b[i] = 0;
}

static size_t win_strlen(const char *s) {
  size_t n = 0;
  while (s[n] != '\0')
    n++;
  return n;
}

static void win_strcpy(char *dst, const char *src, size_t cap) {
  size_t i = 0;
  while (i + 1 < cap && src[i] != '\0') {
    dst[i] = src[i];
    i++;
  }
  dst[i] = '\0';
}

static int win_error(void) {
  DWORD e = GetLastError();
  return e != 0 ? -(int)e : -1;
}

static int win_new_file(HANDLE h) {
  if (h == INVALID_HANDLE_VALUE)
    return win_error();
  for (int i = 0; i < RV_FILES_MAX; i++) {
    if (!rv_files[i].used) {
      rv_files[i].used = 1;
      rv_files[i].h = h;
      return i + 3; /* never collide with 0/1/2 */
    }
  }
  CloseHandle(h);
  return -1;
}

static HANDLE win_file(int fd) {
  int slot = fd - 3;
  if (slot < 0 || slot >= RV_FILES_MAX || !rv_files[slot].used)
    return INVALID_HANDLE_VALUE;
  return rv_files[slot].h;
}

static DWORD win_access(unsigned flags) {
  switch (flags & 3u) {
  case RV_O_WRONLY:
    return GENERIC_WRITE;
  case RV_O_RDWR:
    return GENERIC_READ | GENERIC_WRITE;
  default:
    return GENERIC_READ;
  }
}

static DWORD win_disposition(unsigned flags) {
  if (flags & RV_O_CREAT)
    return (flags & RV_O_EXCL) ? CREATE_NEW : OPEN_ALWAYS;
  if (flags & RV_O_TRUNC)
    return CREATE_ALWAYS;
  return OPEN_EXISTING;
}

static void win_fill_stat(struct rv_hc_stat *raw,
                          const WIN32_FILE_ATTRIBUTE_DATA *d) {
  win_zero(raw, sizeof(*raw));
  int isdir = (d->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  raw->mode = isdir ? 0040755u : 0100644u;
  raw->nlink = 1;
  raw->size_lo = d->nFileSizeLow;
  raw->size_hi = d->nFileSizeHigh;
  ULARGE_INTEGER ft;
  ft.LowPart = d->ftLastWriteTime.dwLowDateTime;
  ft.HighPart = d->ftLastWriteTime.dwHighDateTime;
  /* FILETIME is 100ns ticks since 1601; Unix seconds since 1970. */
  unsigned long long secs = (ft.QuadPart - 116444736000000000ULL) / 10000000ULL;
  raw->mtime_lo = (uint32_t)secs;
  raw->mtime_hi = (uint32_t)(secs >> 32);
  raw->atime_lo = raw->mtime_lo;
  raw->atime_hi = raw->mtime_hi;
  raw->ctime_lo = raw->mtime_lo;
  raw->ctime_hi = raw->mtime_hi;
}

static void win_uname(struct rv_hc_req *req) {
  /* Guest struct utsname is six 65-byte fields. */
  char *out = (char *)rv_gptr(req->a0, 6 * 65);
  if (out == NULL) {
    req->result = -1;
    return;
  }
  win_zero(out, 6 * 65);
  char computer[65];
  DWORD clen = sizeof(computer);
  if (!GetComputerNameA(computer, &clen))
    computer[0] = '\0';
  win_strcpy(out + 0, "Windows", 65);
  win_strcpy(out + 65, computer, 65);
  win_strcpy(out + 130, "10", 65);
  win_strcpy(out + 195, "Windows", 65);
  SYSTEM_INFO si;
  GetNativeSystemInfo(&si);
  const char *arch = "x86";
  if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
    arch = "AMD64";
  else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
    arch = "ARM64";
  win_strcpy(out + 260, arch, 65);
  win_strcpy(out + 325, computer, 65);
  req->result = 0;
}

static void win_environ(struct rv_hc_req *req) {
  char *dst = (char *)rv_gptr(req->a0, req->a1);
  if (dst == NULL) {
    req->result = -1;
    return;
  }
  char *block = GetEnvironmentStringsA();
  if (block == NULL) {
    req->result = win_error();
    return;
  }
  size_t used = 0;
  for (char *p = block; *p != '\0'; p += win_strlen(p) + 1) {
    /* Skip hidden entries such as "=C:=C:\...". */
    if (*p == '=')
      continue;
    size_t n = win_strlen(p) + 1;
    if (used + n >= req->a1)
      break;
    for (size_t k = 0; k < n; k++)
      dst[used + k] = p[k];
    used += n;
  }
  dst[used] = '\0';
  FreeEnvironmentStringsA(block);
  req->result = (int32_t)used;
}

void rv_host_dispatch(struct rv_hc_req *req) {
  char path[RV_PATH_MAX];
  int r = 0;

  req->data_len = 0;
  switch (req->op) {
  case RV_HC_GETCWD: {
    char *dst = (char *)rv_gptr(req->a0, req->a1);
    if (dst == NULL) {
      req->result = -1;
      break;
    }
    DWORD n = GetCurrentDirectoryA(req->a1, dst);
    r = n > 0 ? (int)n : win_error();
    break;
  }
  case RV_HC_OPEN: {
    if (rv_guest_cstr(req->a0, path, sizeof(path)) != 0) {
      req->result = -1;
      break;
    }
    HANDLE h = CreateFileA(
        path, win_access(req->a1), FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        win_disposition(req->a1), FILE_ATTRIBUTE_NORMAL, NULL);
    r = win_new_file(h);
    break;
  }
  case RV_HC_READ: {
    uint8_t *dst = rv_gptr(req->a1, req->a2);
    HANDLE h = win_file((int)req->a0);
    if (dst == NULL || h == INVALID_HANDLE_VALUE) {
      req->result = -1;
      break;
    }
    DWORD got = 0;
    if (ReadFile(h, dst, req->a2, &got, NULL))
      r = (int)got;
    else
      r = win_error();
    break;
  }
  case RV_HC_WRITE: {
    uint8_t *src = rv_gptr(req->a1, req->a2);
    if (src == NULL) {
      req->result = -1;
      break;
    }
    if (req->a0 == 1 || req->a0 == 2) {
      r = rv_out_append(src, req->a2) == 0 ? (int)req->a2 : -1;
    } else {
      HANDLE h = win_file((int)req->a0);
      DWORD wrote = 0;
      if (h != INVALID_HANDLE_VALUE && WriteFile(h, src, req->a2, &wrote, NULL))
        r = (int)wrote;
      else
        r = win_error();
    }
    break;
  }
  case RV_HC_CLOSE: {
    int slot = (int)req->a0 - 3;
    if (slot < 0 || slot >= RV_FILES_MAX || !rv_files[slot].used) {
      req->result = -1;
      break;
    }
    r = CloseHandle(rv_files[slot].h) ? 0 : win_error();
    rv_files[slot].used = 0;
    break;
  }
  case RV_HC_LSEEK: {
    HANDLE h = win_file((int)req->a0);
    LARGE_INTEGER off, newpos;
    off.QuadPart = (LONGLONG)(((uint64_t)req->a2 << 32) | req->a1);
    DWORD method = req->a3 == RV_SEEK_SET
                       ? FILE_BEGIN
                       : (req->a3 == RV_SEEK_END ? FILE_END : FILE_CURRENT);
    if (h == INVALID_HANDLE_VALUE || !SetFilePointerEx(h, off, &newpos, method))
      r = win_error();
    else
      r = (int)newpos.LowPart;
    break;
  }
  case RV_HC_UNAME:
    win_uname(req);
    return;
  case RV_HC_GETENV: {
    if (rv_guest_cstr(req->a0, path, sizeof(path)) != 0) {
      req->result = -1;
      break;
    }
    DWORD n = GetEnvironmentVariableA(path, (char *)req->data,
                                      (DWORD)sizeof(req->data));
    if (n == 0 || n > sizeof(req->data)) {
      r = -1;
      break;
    }
    req->data_len = n;
    r = (int)n;
    break;
  }
  case RV_HC_ENVIRON:
    win_environ(req);
    return;
  case RV_HC_GETUID:
  case RV_HC_GETEUID:
  case RV_HC_GETGID:
  case RV_HC_GETEGID:
    r = 0;
    break;
  case RV_HC_GETGROUPS:
    r = 0;
    break;
  case RV_HC_GETPWUID: {
    char user[RV_HC_ID_CAP];
    DWORD n = GetEnvironmentVariableA("USERNAME", user, sizeof(user));
    if (n == 0 || n >= sizeof(user)) {
      r = -1;
      break;
    }
    size_t at = 0;
    const char *fields[3] = {user, "", ""};
    DWORD m = GetEnvironmentVariableA("USERPROFILE", (char *)req->data,
                                      (DWORD)sizeof(req->data));
    if (m > 0 && m < sizeof(req->data))
      fields[1] = (const char *)req->data;
    char shell[RV_HC_ID_CAP];
    DWORD s = GetEnvironmentVariableA("COMSPEC", shell, sizeof(shell));
    if (s > 0)
      fields[2] = shell;
    for (int i = 0; i < 3; i++) {
      size_t l = win_strlen(fields[i]) + 1;
      if (i == 1 && at + l <= sizeof(req->data))
        at += l; /* already in req->data */
      if (i != 1) {
        if (at + l > sizeof(req->data))
          break;
        for (size_t k = 0; k < l; k++)
          req->data[at + k] = fields[i][k];
        at += l;
      }
    }
    req->data_len = (uint32_t)at;
    req->a0 = 0;
    req->a1 = 0;
    r = 1;
    break;
  }
  case RV_HC_GETGRGID: {
    const char *name = "Users";
    size_t n = win_strlen(name) + 1;
    for (size_t k = 0; k < n; k++)
      req->data[k] = name[k];
    req->data_len = (uint32_t)n;
    req->a0 = 0;
    r = 1;
    break;
  }
  case RV_HC_READLINK:
    r = -1;
    break;
  case RV_HC_CHMOD: {
    if (rv_guest_cstr(req->a0, path, sizeof(path)) != 0) {
      req->result = -1;
      break;
    }
    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
      r = win_error();
      break;
    }
    if (req->a1 & 0200)
      attrs &= ~FILE_ATTRIBUTE_READONLY;
    else
      attrs |= FILE_ATTRIBUTE_READONLY;
    r = SetFileAttributesA(path, attrs) ? 0 : win_error();
    break;
  }
  case RV_HC_STAT:
  case RV_HC_LSTAT: {
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (rv_guest_cstr(req->a0, path, sizeof(path)) != 0) {
      req->result = -1;
      break;
    }
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &d)) {
      r = win_error();
      break;
    }
    win_fill_stat((struct rv_hc_stat *)req->data, &d);
    req->data_len = (uint32_t)sizeof(struct rv_hc_stat);
    r = 0;
    break;
  }
  case RV_HC_OPENDIR: {
    int slot = -1;
    for (int i = 0; i < RV_DIRS_MAX; i++) {
      if (!rv_dirs[i].used) {
        slot = i;
        break;
      }
    }
    if (slot < 0) {
      r = -1;
      break;
    }
    if (rv_guest_cstr(req->a0, path, sizeof(path)) != 0) {
      req->result = -1;
      break;
    }
    size_t n = win_strlen(path);
    if (n + 3 >= sizeof(path)) {
      req->result = -1;
      break;
    }
    path[n] = '\\';
    path[n + 1] = '*';
    path[n + 2] = '\0';
    HANDLE h = FindFirstFileA(path, &rv_dirs[slot].data);
    if (h == INVALID_HANDLE_VALUE) {
      r = win_error();
      break;
    }
    rv_dirs[slot].used = 1;
    rv_dirs[slot].first = 1;
    rv_dirs[slot].h = h;
    r = slot;
    break;
  }
  case RV_HC_READDIR: {
    int slot = (int)req->a0;
    if (slot < 0 || slot >= RV_DIRS_MAX || !rv_dirs[slot].used) {
      req->result = -1;
      break;
    }
    int ok = rv_dirs[slot].first
                 ? 1
                 : FindNextFileA(rv_dirs[slot].h, &rv_dirs[slot].data);
    rv_dirs[slot].first = 0;
    if (!ok) {
      r = 0;
      break;
    }
    struct rv_hc_dirent *out = (struct rv_hc_dirent *)req->data;
    win_zero(out, sizeof(*out));
    out->type = (rv_dirs[slot].data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    ? 4
                    : 8;
    size_t n = win_strlen(rv_dirs[slot].data.cFileName);
    if (n >= sizeof(out->name))
      n = sizeof(out->name) - 1;
    for (size_t k = 0; k < n; k++)
      out->name[k] = rv_dirs[slot].data.cFileName[k];
    out->name[n] = '\0';
    out->name_len = (uint32_t)n;
    req->data_len = (uint32_t)sizeof(*out);
    r = 1;
    break;
  }
  case RV_HC_CLOSEDIR: {
    int slot = (int)req->a0;
    if (slot < 0 || slot >= RV_DIRS_MAX || !rv_dirs[slot].used) {
      req->result = -1;
      break;
    }
    FindClose(rv_dirs[slot].h);
    rv_dirs[slot].used = 0;
    r = 0;
    break;
  }
  case RV_HC_USLEEP:
    Sleep(req->a0 / 1000u);
    r = 0;
    break;
  case RV_HC_GETPID:
    r = (int)GetCurrentProcessId();
    break;
  case RV_HC_ISATTY:
    r = (req->a0 <= 2) ? 1 : 0;
    break;
  default:
    req->result = -1;
    return;
  }
  req->result = (int32_t)r;
}

void rv_host_reset(void) {
  for (int i = 0; i < RV_FILES_MAX; i++) {
    if (rv_files[i].used) {
      CloseHandle(rv_files[i].h);
      rv_files[i].used = 0;
    }
  }
  for (int i = 0; i < RV_DIRS_MAX; i++) {
    if (rv_dirs[i].used) {
      FindClose(rv_dirs[i].h);
      rv_dirs[i].used = 0;
    }
  }
}

/* Minimal DLL entry point: the module is mapped and its exports are called by
 * the agent's PE loader, so there is no CRT initialisation to run. */
__declspec(dllexport) int __stdcall DllMain(void *instance, unsigned reason,
                                            void *reserved) {
  (void)instance;
  (void)reason;
  (void)reserved;
  return 1;
}
