/*
 * rv_bof_runtime.c — guest-side runtime for RISC-V BOFs.
 *
 * Loaded by rvvm_linux into guest RAM before the BOF object and linked by
 * symbol: the BOF's undefined imports (Beacon API and libc) resolve here.
 * There is no libc in the guest; this file provides the subset the Linux BOF
 * collections need, implemented on top of the host-call mailbox.
 *
 * Compiled with the riscv32-linux-musl headers so every public type (struct
 * stat, struct dirent, FILE, DIR, ...) matches what a BOF built for the same
 * target expects. Nothing from musl is linked: every symbol used by a BOF is
 * defined below.
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "rv_hostcall.h"

/* ------------------------------------------------------------------------- */
/* Host calls                                                                */
/* ------------------------------------------------------------------------- */

#define RV_UART_THR 0x10000000u
#define RV_HC_EXIT 0x10001000u

static volatile struct rv_hc_req *const rv_hc =
    (volatile struct rv_hc_req *)RV_HC_GUEST_ADDR;

static int rv_hc_calls;

static int rv_hostcall(uint32_t op, uint32_t a0, uint32_t a1, uint32_t a2,
                       uint32_t a3) {
  rv_hc->op = op;
  rv_hc->a0 = a0;
  rv_hc->a1 = a1;
  rv_hc->a2 = a2;
  rv_hc->a3 = a3;
  rv_hc->result = 0;
  rv_hc->data_len = 0;
  *(volatile uint32_t *)RV_HC_DOORBELL = RV_HC_MAGIC;
  rv_hc_calls++;
  return rv_hc->result;
}

static void rv_guest_exit(int code) __attribute__((noreturn));
static void rv_guest_exit(int code) {
  *(volatile uint32_t *)RV_HC_EXIT = (uint32_t)code;
  for (;;) {
  }
}

/* ------------------------------------------------------------------------- */
/* Compiler runtime helpers                                                  */
/*                                                                           */
/* RV32I has no multiply/divide instructions, so clang emits calls to these. */
/* The BOF and this runtime are built for -mcpu=generic_rv32 and resolve the */
/* helpers here.                                                             */
/* ------------------------------------------------------------------------- */

uint32_t __mulsi3(uint32_t a, uint32_t b) {
  uint32_t r = 0;
  while (b != 0) {
    if (b & 1u)
      r += a;
    a <<= 1;
    b >>= 1;
  }
  return r;
}

uint32_t __udivsi3(uint32_t n, uint32_t d) {
  uint32_t q = 0, r = 0;
  if (d == 0) {
    rv_guest_exit(136);
  }
  for (int i = 31; i >= 0; i--) {
    r = (r << 1) | ((n >> i) & 1u);
    if (r >= d) {
      r -= d;
      q |= (uint32_t)1 << i;
    }
  }
  return q;
}

uint32_t __umodsi3(uint32_t n, uint32_t d) {
  uint32_t r = 0;
  if (d == 0) {
    rv_guest_exit(136);
  }
  for (int i = 31; i >= 0; i--) {
    r = (r << 1) | ((n >> i) & 1u);
    if (r >= d)
      r -= d;
  }
  return r;
}

int32_t __divsi3(int32_t a, int32_t b) {
  int neg = (a < 0) != (b < 0);
  uint32_t ua = a < 0 ? (uint32_t)(-a) : (uint32_t)a;
  uint32_t ub = b < 0 ? (uint32_t)(-b) : (uint32_t)b;
  uint32_t q = __udivsi3(ua, ub);
  return neg ? -(int32_t)q : (int32_t)q;
}

int32_t __modsi3(int32_t a, int32_t b) {
  int neg = a < 0;
  uint32_t ua = a < 0 ? (uint32_t)(-a) : (uint32_t)a;
  uint32_t ub = b < 0 ? (uint32_t)(-b) : (uint32_t)b;
  uint32_t r = __umodsi3(ua, ub);
  return neg ? -(int32_t)r : (int32_t)r;
}

uint64_t __muldi3(uint64_t a, uint64_t b) {
  uint64_t r = 0;
  while (b != 0) {
    if (b & 1u)
      r += a;
    a <<= 1;
    b >>= 1;
  }
  return r;
}

uint64_t __udivdi3(uint64_t n, uint64_t d) {
  uint64_t q = 0, r = 0;
  if (d == 0) {
    rv_guest_exit(136);
  }
  for (int i = 63; i >= 0; i--) {
    r = (r << 1) | ((n >> i) & 1u);
    if (r >= d) {
      r -= d;
      q |= (uint64_t)1 << i;
    }
  }
  return q;
}

uint64_t __umoddi3(uint64_t n, uint64_t d) {
  uint64_t r = 0;
  if (d == 0) {
    rv_guest_exit(136);
  }
  for (int i = 63; i >= 0; i--) {
    r = (r << 1) | ((n >> i) & 1u);
    if (r >= d)
      r -= d;
  }
  return r;
}

int64_t __divdi3(int64_t a, int64_t b) {
  int neg = (a < 0) != (b < 0);
  uint64_t ua = a < 0 ? (uint64_t)(-a) : (uint64_t)a;
  uint64_t ub = b < 0 ? (uint64_t)(-b) : (uint64_t)b;
  uint64_t q = __udivdi3(ua, ub);
  return neg ? -(int64_t)q : (int64_t)q;
}

int64_t __moddi3(int64_t a, int64_t b) {
  int neg = a < 0;
  uint64_t ua = a < 0 ? (uint64_t)(-a) : (uint64_t)a;
  uint64_t ub = b < 0 ? (uint64_t)(-b) : (uint64_t)b;
  uint64_t r = __umoddi3(ua, ub);
  return neg ? -(int64_t)r : (int64_t)r;
}

/* ------------------------------------------------------------------------- */
/* Numeric conversion                                                        */
/* ------------------------------------------------------------------------- */

long strtol(const char *s, char **end, int base) {
  const char *p = s;
  int neg = 0;
  long v = 0;
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
    p++;
  if (*p == '-' || *p == '+') {
    neg = *p == '-';
    p++;
  }
  if ((base == 0 || base == 16) && p[0] == '0' &&
      (p[1] == 'x' || p[1] == 'X')) {
    base = 16;
    p += 2;
  } else if (base == 0 && p[0] == '0') {
    base = 8;
  } else if (base == 0) {
    base = 10;
  }
  for (;;) {
    int d;
    if (*p >= '0' && *p <= '9')
      d = *p - '0';
    else if (*p >= 'a' && *p <= 'z')
      d = *p - 'a' + 10;
    else if (*p >= 'A' && *p <= 'Z')
      d = *p - 'A' + 10;
    else
      break;
    if (d >= base)
      break;
    v = v * base + d;
    p++;
  }
  if (end != NULL)
    *end = (char *)p;
  return neg ? -v : v;
}

unsigned long strtoul(const char *s, char **end, int base) {
  return (unsigned long)strtol(s, end, base);
}

int atoi(const char *s) { return (int)strtol(s, NULL, 10); }
long atol(const char *s) { return strtol(s, NULL, 10); }

/* ------------------------------------------------------------------------- */
/* errno / process                                                           */
/* ------------------------------------------------------------------------- */

int *__errno_location(void) {
  static int host_errno;
  return &host_errno;
}

void exit(int code) { rv_guest_exit(code); }
void _Exit(int code) { rv_guest_exit(code); }

void abort(void) { rv_guest_exit(134); }

/* ------------------------------------------------------------------------- */
/* Memory / strings                                                          */
/* ------------------------------------------------------------------------- */

void *memcpy(void *dst, const void *src, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  const unsigned char *s = (const unsigned char *)src;
  for (size_t i = 0; i < n; i++)
    d[i] = s[i];
  return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  const unsigned char *s = (const unsigned char *)src;
  if (d < s) {
    for (size_t i = 0; i < n; i++)
      d[i] = s[i];
  } else {
    for (size_t i = n; i > 0; i--)
      d[i - 1] = s[i - 1];
  }
  return dst;
}

void *memset(void *dst, int c, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  for (size_t i = 0; i < n; i++)
    d[i] = (unsigned char)c;
  return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
  const unsigned char *x = (const unsigned char *)a;
  const unsigned char *y = (const unsigned char *)b;
  for (size_t i = 0; i < n; i++) {
    if (x[i] != y[i])
      return x[i] < y[i] ? -1 : 1;
  }
  return 0;
}

int bcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }

size_t strlen(const char *s) {
  size_t n = 0;
  while (s[n] != '\0')
    n++;
  return n;
}

int strcmp(const char *a, const char *b) {
  while (*a != '\0' && *a == *b) {
    a++;
    b++;
  }
  return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (a[i] != b[i])
      return (unsigned char)a[i] - (unsigned char)b[i];
    if (a[i] == '\0')
      return 0;
  }
  return 0;
}

char *strcpy(char *dst, const char *src) {
  char *d = dst;
  while ((*d++ = *src++) != '\0') {
  }
  return dst;
}

char *strncpy(char *dst, const char *src, size_t n) {
  size_t i = 0;
  for (; i < n && src[i] != '\0'; i++)
    dst[i] = src[i];
  for (; i < n; i++)
    dst[i] = '\0';
  return dst;
}

char *strcat(char *dst, const char *src) {
  char *d = dst + strlen(dst);
  while ((*d++ = *src++) != '\0') {
  }
  return dst;
}

char *strncat(char *dst, const char *src, size_t n) {
  char *d = dst + strlen(dst);
  size_t i = 0;
  for (; i < n && src[i] != '\0'; i++)
    d[i] = src[i];
  d[i] = '\0';
  return dst;
}

char *strchr(const char *s, int c) {
  for (;; s++) {
    if (*s == (char)c)
      return (char *)s;
    if (*s == '\0')
      return NULL;
  }
}

char *strrchr(const char *s, int c) {
  const char *last = NULL;
  for (;; s++) {
    if (*s == (char)c)
      last = s;
    if (*s == '\0')
      return (char *)last;
  }
}

char *strstr(const char *hay, const char *needle) {
  size_t n = strlen(needle);
  if (n == 0)
    return (char *)hay;
  for (; *hay != '\0'; hay++) {
    if (*hay == *needle && strncmp(hay, needle, n) == 0)
      return (char *)hay;
  }
  return NULL;
}

size_t strspn(const char *s, const char *accept) {
  size_t n = 0;
  while (s[n] != '\0' && strchr(accept, s[n]) != NULL)
    n++;
  return n;
}

size_t strcspn(const char *s, const char *reject) {
  size_t n = 0;
  while (s[n] != '\0' && strchr(reject, s[n]) == NULL)
    n++;
  return n;
}

char *strtok_r(char *s, const char *delim, char **save) {
  if (s == NULL)
    s = *save;
  if (s == NULL)
    return NULL;
  s += strspn(s, delim);
  if (*s == '\0') {
    *save = s;
    return NULL;
  }
  char *end = s + strcspn(s, delim);
  if (*end != '\0') {
    *end = '\0';
    *save = end + 1;
  } else {
    *save = end;
  }
  return s;
}

char *strtok(char *s, const char *delim) {
  static char *save;
  return strtok_r(s, delim, &save);
}

/* ------------------------------------------------------------------------- */
/* Heap (bump allocator; a BOF run is short-lived and free is a no-op)       */
/* ------------------------------------------------------------------------- */

#ifndef RV_HEAP_SIZE
#define RV_HEAP_SIZE (1u << 20)
#endif

static unsigned char rv_heap[RV_HEAP_SIZE];
static size_t rv_heap_used;

void *malloc(size_t n) {
  size_t aligned = (n + 15u) & ~(size_t)15u;
  if (aligned < n || rv_heap_used + aligned > RV_HEAP_SIZE) {
    errno = ENOMEM;
    return NULL;
  }
  void *p = rv_heap + rv_heap_used;
  rv_heap_used += aligned;
  return p;
}

void *calloc(size_t n, size_t size) {
  if (n != 0 && size > (size_t)-1 / n) {
    errno = ENOMEM;
    return NULL;
  }
  size_t total = n * size;
  void *p = malloc(total);
  if (p != NULL)
    memset(p, 0, total);
  return p;
}

void free(void *p) { (void)p; }

void *realloc(void *p, size_t n) {
  if (p == NULL)
    return malloc(n);
  size_t old = rv_heap_used - (size_t)((unsigned char *)p - rv_heap);
  /* The bump allocator does not track block sizes; only grow the last block. */
  if ((unsigned char *)p + ((old + 15u) & ~(size_t)15u) ==
          rv_heap + rv_heap_used ||
      (unsigned char *)p < rv_heap ||
      (unsigned char *)p >= rv_heap + rv_heap_used) {
    if (n <= RV_HEAP_SIZE - (size_t)((unsigned char *)p - rv_heap)) {
      size_t need = (n + 15u) & ~(size_t)15u;
      rv_heap_used = (size_t)((unsigned char *)p - rv_heap) + need;
      return p;
    }
  }
  void *q = malloc(n);
  if (q == NULL)
    return NULL;
  size_t copy = n < old ? n : old;
  memcpy(q, p, copy);
  return q;
}

/* ------------------------------------------------------------------------- */
/* stdio                                                                     */
/* ------------------------------------------------------------------------- */

struct _IO_FILE {
  int fd;
  int eof;
  int err;
  unsigned char rbuf[4096];
  size_t rpos;
  size_t rlen;
};

static FILE rv_stdin_file;
static FILE rv_stdout_file = {.fd = 1};
static FILE rv_stderr_file = {.fd = 2};
FILE *const stdin = &rv_stdin_file;
FILE *const stdout = &rv_stdout_file;
FILE *const stderr = &rv_stderr_file;

static int rv_write_all(int fd, const void *buf, size_t len) {
  const unsigned char *p = (const unsigned char *)buf;
  size_t done = 0;
  while (done < len) {
    int n = rv_hostcall(RV_HC_WRITE, (uint32_t)fd,
                        (uint32_t)((uint32_t)(size_t)(p + done)),
                        (uint32_t)(len - done), 0);
    if (n <= 0)
      return -1;
    done += (size_t)n;
  }
  return (int)done;
}

static int rv_read_some(int fd, void *buf, size_t len) {
  return rv_hostcall(RV_HC_READ, (uint32_t)fd, (uint32_t)(size_t)buf,
                     (uint32_t)len, 0);
}

/* Refill a FILE's read buffer. Returns bytes available, 0 at EOF, <0 error. */
static int rv_file_fill(FILE *f) {
  if (f->rpos < f->rlen)
    return (int)(f->rlen - f->rpos);
  int n = rv_read_some(f->fd, f->rbuf, sizeof(f->rbuf));
  if (n < 0) {
    f->err = 1;
    errno = -n;
    return n;
  }
  if (n == 0) {
    f->eof = 1;
    return 0;
  }
  f->rpos = 0;
  f->rlen = (size_t)n;
  return n;
}

FILE *fopen(const char *path, const char *mode) {
  int flags = 0;
  if (mode == NULL || path == NULL)
    return NULL;
  switch (mode[0]) {
  case 'r':
    flags = RV_O_RDONLY;
    break;
  case 'w':
    flags = RV_O_WRONLY | RV_O_CREAT | RV_O_TRUNC;
    break;
  case 'a':
    flags = RV_O_WRONLY | RV_O_CREAT | RV_O_APPEND;
    break;
  default:
    return NULL;
  }
  for (const char *m = mode; *m != '\0'; m++) {
    if (*m == '+')
      flags = (flags & ~(RV_O_RDONLY | RV_O_WRONLY)) | RV_O_RDWR;
    if (*m == 'x')
      flags |= RV_O_EXCL;
  }
  int fd =
      rv_hostcall(RV_HC_OPEN, (uint32_t)(size_t)path, (uint32_t)flags, 0644, 0);
  if (fd < 0) {
    errno = -fd;
    return NULL;
  }
  FILE *f = (FILE *)malloc(sizeof(*f));
  if (f == NULL) {
    rv_hostcall(RV_HC_CLOSE, (uint32_t)fd, 0, 0, 0);
    errno = ENOMEM;
    return NULL;
  }
  f->fd = fd;
  f->eof = 0;
  f->err = 0;
  f->rpos = 0;
  f->rlen = 0;
  return f;
}

size_t fread(void *buf, size_t size, size_t nmemb, FILE *f) {
  if (size == 0 || nmemb == 0)
    return 0;
  size_t want = size * nmemb;
  if (size != 0 && want / size != nmemb) {
    f->err = 1;
    return 0;
  }
  unsigned char *dst = (unsigned char *)buf;
  size_t done = 0;
  /* Drain the buffer first, then read the remainder directly. */
  while (done < want) {
    if (f->rpos < f->rlen) {
      size_t n = f->rlen - f->rpos;
      if (n > want - done)
        n = want - done;
      memcpy(dst + done, f->rbuf + f->rpos, n);
      f->rpos += n;
      done += n;
      continue;
    }
    if (done > 0) {
      int n = rv_read_some(f->fd, dst + done, want - done);
      if (n < 0) {
        f->err = 1;
        errno = -n;
        break;
      }
      if (n == 0) {
        f->eof = 1;
        break;
      }
      done += (size_t)n;
      continue;
    }
    int n = rv_file_fill(f);
    if (n <= 0)
      break;
  }
  return done / size;
}

size_t fwrite(const void *buf, size_t size, size_t nmemb, FILE *f) {
  if (size == 0 || nmemb == 0)
    return 0;
  size_t want = size * nmemb;
  int n = rv_write_all(f->fd, buf, want);
  if (n < 0) {
    f->err = 1;
    return 0;
  }
  return (size_t)n / size;
}

int fclose(FILE *f) {
  if (f == NULL)
    return -1;
  int r = rv_hostcall(RV_HC_CLOSE, (uint32_t)f->fd, 0, 0, 0);
  if (f != stdin && f != stdout && f != stderr)
    free(f);
  return r < 0 ? -1 : 0;
}
int fflush(FILE *f) {
  (void)f;
  return 0;
}

int feof(FILE *f) { return f != NULL ? f->eof : 0; }
int ferror(FILE *f) { return f != NULL ? f->err : 0; }
void clearerr(FILE *f) {
  if (f != NULL) {
    f->eof = 0;
    f->err = 0;
  }
}

int fseek(FILE *f, long offset, int whence) {
  int r =
      rv_hostcall(RV_HC_LSEEK, (uint32_t)f->fd, (uint32_t)offset,
                  (uint32_t)((uint32_t)offset >> 31 ? 0 : 0), (uint32_t)whence);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  f->eof = 0;
  f->rpos = 0;
  f->rlen = 0;
  return 0;
}

long ftell(FILE *f) {
  int r = rv_hostcall(RV_HC_LSEEK, (uint32_t)f->fd, 0, 0, RV_SEEK_CUR);
  return r < 0 ? -1 : (long)r;
}

void rewind(FILE *f) { (void)fseek(f, 0, RV_SEEK_SET); }

char *fgets(char *s, int n, FILE *f) {
  if (s == NULL || n <= 0)
    return NULL;
  int i = 0;
  while (i < n - 1) {
    if (f->rpos >= f->rlen && rv_file_fill(f) <= 0)
      break;
    char c = (char)f->rbuf[f->rpos++];
    s[i++] = c;
    if (c == '\n')
      break;
  }
  if (i == 0)
    return NULL;
  s[i] = '\0';
  return s;
}

int fgetc(FILE *f) {
  if (f->rpos >= f->rlen && rv_file_fill(f) <= 0)
    return -1;
  return f->rbuf[f->rpos++];
}

int getc(FILE *f) { return fgetc(f); }

int fputc(int c, FILE *f) {
  unsigned char b = (unsigned char)c;
  return rv_write_all(f->fd, &b, 1) < 0 ? -1 : b;
}

int putchar(int c) { return fputc(c, stdout); }
int putc(int c, FILE *f) { return fputc(c, f); }

int fputs(const char *s, FILE *f) {
  size_t n = strlen(s);
  return rv_write_all(f->fd, s, n) < 0 ? -1 : (int)n;
}

int puts(const char *s) {
  if (fputs(s, stdout) < 0)
    return -1;
  return fputc('\n', stdout) < 0 ? -1 : 0;
}

/* ------------------------------------------------------------------------- */
/* Formatter                                                                 */
/* ------------------------------------------------------------------------- */

struct rv_fmt {
  char *buf;
  size_t cap;
  size_t len;
};

static void fmt_ch(struct rv_fmt *f, char c) {
  if (f->buf != NULL && f->len + 1 < f->cap)
    f->buf[f->len] = c;
  f->len++;
}

static void fmt_pad(struct rv_fmt *f, char c, int n) {
  while (n-- > 0)
    fmt_ch(f, c);
}

static void fmt_str(struct rv_fmt *f, const char *s, int width, int left) {
  size_t n = strlen(s);
  int pad = width > (int)n ? width - (int)n : 0;
  if (!left)
    fmt_pad(f, ' ', pad);
  for (size_t i = 0; i < n; i++)
    fmt_ch(f, s[i]);
  if (left)
    fmt_pad(f, ' ', pad);
}

static void fmt_num(struct rv_fmt *f, unsigned long long v, int neg, int base,
                    int upper, int width, int zero, int left, int alt,
                    int prec) {
  char tmp[32];
  int n = 0;
  const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
  if (v == 0 && prec != 0)
    tmp[n++] = '0';
  while (v != 0) {
    tmp[n++] = digits[v % (unsigned)base];
    v /= (unsigned)base;
  }
  while (n < prec)
    tmp[n++] = '0';
  int sign = neg ? 1 : 0;
  int prefix = 0;
  if (alt && base == 16)
    prefix = 2;
  else if (alt && base == 8 && (n == 0 || tmp[n - 1] != '0'))
    prefix = 1;
  int total = n + sign + prefix;
  int pad = width > total ? width - total : 0;
  if (!left && !zero)
    fmt_pad(f, ' ', pad);
  if (neg)
    fmt_ch(f, '-');
  if (prefix == 2) {
    fmt_ch(f, '0');
    fmt_ch(f, upper ? 'X' : 'x');
  } else if (prefix == 1) {
    fmt_ch(f, '0');
  }
  if (!left && zero)
    fmt_pad(f, '0', pad);
  while (n > 0)
    fmt_ch(f, tmp[--n]);
  if (left)
    fmt_pad(f, ' ', pad);
}

int vsnprintf(char *buf, size_t cap, const char *fmt, va_list ap) {
  struct rv_fmt f;
  f.buf = buf;
  f.cap = cap;
  f.len = 0;

  for (const char *p = fmt; *p != '\0'; p++) {
    if (*p != '%') {
      fmt_ch(&f, *p);
      continue;
    }
    p++;
    int left = 0, zero = 0, alt = 0, plus = 0;
    for (;; p++) {
      if (*p == '-')
        left = 1;
      else if (*p == '0')
        zero = 1;
      else if (*p == '#')
        alt = 1;
      else if (*p == '+')
        plus = 1;
      else if (*p == ' ')
        plus = 0;
      else
        break;
    }
    int width = 0;
    if (*p == '*') {
      width = va_arg(ap, int);
      if (width < 0) {
        left = 1;
        width = -width;
      }
      p++;
    } else {
      while (*p >= '0' && *p <= '9')
        width = width * 10 + (*p++ - '0');
    }
    int prec = -1;
    if (*p == '.') {
      p++;
      prec = 0;
      if (*p == '*') {
        prec = va_arg(ap, int);
        p++;
      } else {
        while (*p >= '0' && *p <= '9')
          prec = prec * 10 + (*p++ - '0');
      }
    }
    int lng = 0;
    while (*p == 'l' || *p == 'h' || *p == 'z' || *p == 't' || *p == 'j') {
      if (*p == 'l')
        lng++;
      else if (*p == 'z' || *p == 't')
        lng = 1;
      p++;
    }
    char c = *p;
    if (c == '\0')
      break;

    switch (c) {
    case '%':
      fmt_ch(&f, '%');
      break;
    case 'c': {
      char v = (char)va_arg(ap, int);
      if (width > 1 && !left)
        fmt_pad(&f, ' ', width - 1);
      fmt_ch(&f, v);
      if (width > 1 && left)
        fmt_pad(&f, ' ', width - 1);
      break;
    }
    case 's': {
      const char *s = va_arg(ap, const char *);
      if (s == NULL)
        s = "(null)";
      if (prec >= 0) {
        int n = 0;
        while (s[n] != '\0' && n < prec)
          n++;
        char tmp[256];
        if (n < (int)sizeof(tmp)) {
          memcpy(tmp, s, (size_t)n);
          tmp[n] = '\0';
          fmt_str(&f, tmp, width, left);
        } else {
          fmt_str(&f, s, width, left);
        }
      } else {
        fmt_str(&f, s, width, left);
      }
      break;
    }
    case 'd':
    case 'i': {
      long long v = lng >= 2 ? va_arg(ap, long long) : va_arg(ap, int);
      int neg = v < 0;
      unsigned long long u =
          neg ? (unsigned long long)(-v) : (unsigned long long)v;
      if (plus && !neg) {
        if (width > 0 && !left && !zero)
          width--;
        fmt_ch(&f, '+');
      }
      fmt_num(&f, u, neg, 10, 0, width, zero, left, 0, prec);
      break;
    }
    case 'u':
    case 'o':
    case 'x':
    case 'X': {
      unsigned long long u =
          lng >= 2 ? va_arg(ap, unsigned long long) : va_arg(ap, unsigned int);
      int base = c == 'o' ? 8 : (c == 'u' ? 10 : 16);
      fmt_num(&f, u, 0, base, c == 'X', width, zero, left, alt, prec);
      break;
    }
    case 'p': {
      uintptr_t v = (uintptr_t)va_arg(ap, void *);
      fmt_ch(&f, '0');
      fmt_ch(&f, 'x');
      fmt_num(&f, (unsigned long long)v, 0, 16, 0, width - 2, zero, left, 0,
              prec < 1 ? 1 : prec);
      break;
    }
    default:
      fmt_ch(&f, '%');
      fmt_ch(&f, c);
      break;
    }
  }

  if (f.buf != NULL && f.cap > 0) {
    size_t at = f.len < f.cap - 1 ? f.len : f.cap - 1;
    f.buf[at] = '\0';
  }
  return (int)f.len;
}

int snprintf(char *buf, size_t cap, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, cap, fmt, ap);
  va_end(ap);
  return n;
}

int sprintf(char *buf, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, (size_t)-1, fmt, ap);
  va_end(ap);
  return n;
}

int vfprintf(FILE *f, const char *fmt, va_list ap) {
  va_list cp;
  va_copy(cp, ap);
  int n = vsnprintf(NULL, 0, fmt, cp);
  va_end(cp);
  if (n < 0)
    return -1;
  char *b = (char *)malloc((size_t)n + 1);
  if (b == NULL)
    return -1;
  vsnprintf(b, (size_t)n + 1, fmt, ap);
  int r = rv_write_all(f->fd, b, (size_t)n);
  free(b);
  return r < 0 ? -1 : n;
}

int fprintf(FILE *f, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vfprintf(f, fmt, ap);
  va_end(ap);
  return n;
}

int printf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vfprintf(stdout, fmt, ap);
  va_end(ap);
  return n;
}

/* Minimal sscanf: whitespace, literals, %d/%i/%u/%x/%c/%s with width. */
int sscanf(const char *s, const char *fmt, ...) {
  va_list ap;
  int assigned = 0;
  va_start(ap, fmt);
  const char *p = s;
  for (const char *f = fmt; *f != '\0'; f++) {
    if (*f == '%' && f[1] != '%' && f[1] != '\0') {
      f++;
      int width = 0;
      while (*f >= '0' && *f <= '9')
        width = width * 10 + (*f++ - '0');
      char conv = *f;
      while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
      if (*p == '\0')
        break;
      if (conv == 'c') {
        char *out = va_arg(ap, char *);
        *out = *p++;
        assigned++;
      } else if (conv == 's') {
        char *out = va_arg(ap, char *);
        int i = 0;
        while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n' &&
               *p != '\r' && (width == 0 || i < width))
          out[i++] = *p++;
        out[i] = '\0';
        if (i > 0)
          assigned++;
      } else if (conv == 'd' || conv == 'i' || conv == 'u' || conv == 'x') {
        int neg = 0;
        if (*p == '-') {
          neg = 1;
          p++;
        } else if (*p == '+') {
          p++;
        }
        int base = conv == 'x' ? 16 : (conv == 'i' ? 0 : 10);
        long long v = 0;
        int any = 0;
        for (;;) {
          int d;
          char c = *p;
          if (c >= '0' && c <= '9')
            d = c - '0';
          else if (base != 10 && c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
          else if (base != 10 && c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
          else
            break;
          v = v * base + d;
          any = 1;
          p++;
          if (width != 0 && --width == 0)
            break;
        }
        if (!any)
          break;
        if (neg)
          v = -v;
        if (conv == 'u' || conv == 'x') {
          unsigned int *out = va_arg(ap, unsigned int *);
          *out = (unsigned int)v;
        } else {
          int *out = va_arg(ap, int *);
          *out = (int)v;
        }
        assigned++;
      } else {
        break;
      }
    } else {
      while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
      if (*f == ' ' || *f == '\t' || *f == '\n' || *f == '\r')
        continue;
      if (*p != *f)
        break;
      p++;
    }
  }
  va_end(ap);
  return assigned;
}

/* ------------------------------------------------------------------------- */
/* unistd / stat / dirent / pwd                                              */
/* ------------------------------------------------------------------------- */

char *getenv(const char *name) {
  static char value[RV_HC_DATA_CAP];
  int r = rv_hostcall(RV_HC_GETENV, (uint32_t)(size_t)name,
                      (uint32_t)RV_HC_DATA_CAP, 0, 0);
  if (r < 0)
    return NULL;
  memcpy(value, (const void *)rv_hc->data, (size_t)r);
  value[r] = '\0';
  return value;
}

static char *rv_environ_block;
static char *rv_environ_vec[256];
static int rv_environ_ready;

static void rv_build_environ(void) {
  if (rv_environ_ready)
    return;
  rv_environ_ready = 1;
  size_t cap = 8192;
  rv_environ_block = (char *)malloc(cap);
  if (rv_environ_block == NULL)
    return;
  int n = rv_hostcall(RV_HC_ENVIRON, (uint32_t)(size_t)rv_environ_block,
                      (uint32_t)cap, 0, 0);
  if (n <= 0)
    return;
  size_t at = 0;
  int count = 0;
  while (at < (size_t)n && count < 255) {
    rv_environ_vec[count++] = rv_environ_block + at;
    at += strlen(rv_environ_block + at) + 1;
  }
  rv_environ_vec[count] = NULL;
}

extern char **environ;
char **getEnviron(void) {
  rv_build_environ();
  return rv_environ_vec;
}
char **environ = rv_environ_vec;

char *getcwd(char *buf, size_t size) {
  if (buf == NULL || size == 0) {
    errno = EINVAL;
    return NULL;
  }
  int r =
      rv_hostcall(RV_HC_GETCWD, (uint32_t)(size_t)buf, (uint32_t)size, 0, 0);
  if (r < 0) {
    errno = -r;
    return NULL;
  }
  return buf;
}

int close(int fd) {
  int r = rv_hostcall(RV_HC_CLOSE, (uint32_t)fd, 0, 0, 0);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

ssize_t read(int fd, void *buf, size_t len) {
  int r = rv_hostcall(RV_HC_READ, (uint32_t)fd, (uint32_t)(size_t)buf,
                      (uint32_t)len, 0);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return r;
}

ssize_t write(int fd, const void *buf, size_t len) {
  int r = rv_hostcall(RV_HC_WRITE, (uint32_t)fd, (uint32_t)(size_t)buf,
                      (uint32_t)len, 0);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return r;
}

int chmod(const char *path, mode_t mode) {
  int r =
      rv_hostcall(RV_HC_CHMOD, (uint32_t)(size_t)path, (uint32_t)mode, 0, 0);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

ssize_t readlink(const char *path, char *buf, size_t size) {
  int r = rv_hostcall(RV_HC_READLINK, (uint32_t)(size_t)path,
                      (uint32_t)(size_t)buf, (uint32_t)size, 0);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return r;
}

unsigned int sleep(unsigned int seconds) {
  rv_hostcall(RV_HC_USLEEP, seconds * 1000000u, 0, 0, 0);
  return 0;
}

int usleep(unsigned int usec) {
  int r = rv_hostcall(RV_HC_USLEEP, usec, 0, 0, 0);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

uid_t getuid(void) { return (uid_t)rv_hostcall(RV_HC_GETUID, 0, 0, 0, 0); }
uid_t geteuid(void) { return (uid_t)rv_hostcall(RV_HC_GETEUID, 0, 0, 0, 0); }
gid_t getgid(void) { return (gid_t)rv_hostcall(RV_HC_GETGID, 0, 0, 0, 0); }
gid_t getegid(void) { return (gid_t)rv_hostcall(RV_HC_GETEGID, 0, 0, 0, 0); }
pid_t getpid(void) { return (pid_t)rv_hostcall(RV_HC_GETPID, 0, 0, 0, 0); }

int getgroups(int size, gid_t list[]) {
  int n = rv_hostcall(RV_HC_GETGROUPS, (uint32_t)(size_t)list, (uint32_t)size,
                      0, 0);
  if (n < 0) {
    errno = -n;
    return -1;
  }
  return n;
}

int uname(struct utsname *u) {
  int r =
      rv_hostcall(RV_HC_UNAME, (uint32_t)(size_t)u, (uint32_t)sizeof(*u), 0, 0);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

static int rv_do_stat(const char *path, struct stat *st, int follow) {
  struct rv_hc_stat raw;
  int r = rv_hostcall(follow ? RV_HC_STAT : RV_HC_LSTAT, (uint32_t)(size_t)path,
                      (uint32_t)0, 0, 0);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  memcpy(&raw, (const void *)rv_hc->data, sizeof(raw));
  memset(st, 0, sizeof(*st));
  st->st_mode = (mode_t)raw.mode;
  st->st_nlink = (nlink_t)raw.nlink;
  st->st_uid = (uid_t)raw.uid;
  st->st_gid = (gid_t)raw.gid;
  st->st_dev = (dev_t)raw.dev;
  st->st_ino = (ino_t)raw.ino;
  st->st_rdev = (dev_t)raw.rdev;
  st->st_size = (off_t)(((uint64_t)raw.size_hi << 32) | raw.size_lo);
  st->st_atim.tv_sec = (time_t)(((uint64_t)raw.atime_hi << 32) | raw.atime_lo);
  st->st_mtim.tv_sec = (time_t)(((uint64_t)raw.mtime_hi << 32) | raw.mtime_lo);
  st->st_ctim.tv_sec = (time_t)(((uint64_t)raw.ctime_hi << 32) | raw.ctime_lo);
  return 0;
}

int stat(const char *path, struct stat *st) { return rv_do_stat(path, st, 1); }
int lstat(const char *path, struct stat *st) { return rv_do_stat(path, st, 0); }

/* glibc's old interface, declared by find/grep/walk. */
int __xstat(int ver, const char *path, struct stat *st) {
  (void)ver;
  return stat(path, st);
}

struct __dirstream {
  int slot;
  struct dirent ent;
};

DIR *opendir(const char *path) {
  int slot = rv_hostcall(RV_HC_OPENDIR, (uint32_t)(size_t)path, 0, 0, 0);
  if (slot < 0) {
    errno = -slot;
    return NULL;
  }
  DIR *d = (DIR *)malloc(sizeof(*d));
  if (d == NULL) {
    rv_hostcall(RV_HC_CLOSEDIR, (uint32_t)slot, 0, 0, 0);
    errno = ENOMEM;
    return NULL;
  }
  d->slot = slot;
  return d;
}

struct dirent *readdir(DIR *d) {
  int r = rv_hostcall(RV_HC_READDIR, (uint32_t)d->slot, 0, 0, 0);
  if (r <= 0)
    return NULL;
  struct rv_hc_dirent raw;
  memcpy(&raw, (const void *)rv_hc->data, sizeof(raw));
  memset(&d->ent, 0, sizeof(d->ent));
  d->ent.d_type = (unsigned char)raw.type;
  if (raw.name_len >= sizeof(d->ent.d_name))
    raw.name_len = sizeof(d->ent.d_name) - 1;
  memcpy(d->ent.d_name, raw.name, raw.name_len);
  d->ent.d_name[raw.name_len] = '\0';
  d->ent.d_reclen = (unsigned short)sizeof(d->ent);
  return &d->ent;
}

int closedir(DIR *d) {
  if (d == NULL)
    return -1;
  int r = rv_hostcall(RV_HC_CLOSEDIR, (uint32_t)d->slot, 0, 0, 0);
  free(d);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

static struct passwd rv_pw;
static struct group rv_gr;
static char rv_pw_buf[3 * RV_HC_ID_CAP];
static char rv_gr_buf[RV_HC_ID_CAP];

struct passwd *getpwuid(uid_t uid) {
  int r = rv_hostcall(RV_HC_GETPWUID, (uint32_t)uid, 0, 0, 0);
  if (r <= 0)
    return NULL;
  memcpy(rv_pw_buf, (const void *)rv_hc->data, rv_hc->data_len);
  size_t at = 0;
  rv_pw.pw_name = rv_pw_buf + at;
  at += strlen(rv_pw_buf + at) + 1;
  rv_pw.pw_dir = rv_pw_buf + at;
  at += strlen(rv_pw_buf + at) + 1;
  rv_pw.pw_shell = rv_pw_buf + at;
  rv_pw.pw_passwd = (char *)"x";
  rv_pw.pw_uid = (uid_t)rv_hc->a0;
  rv_pw.pw_gid = (gid_t)rv_hc->a1;
  rv_pw.pw_gecos = rv_pw.pw_name;
  return &rv_pw;
}

struct group *getgrgid(gid_t gid) {
  int r = rv_hostcall(RV_HC_GETGRGID, (uint32_t)gid, 0, 0, 0);
  if (r <= 0)
    return NULL;
  memcpy(rv_gr_buf, (const void *)rv_hc->data, rv_hc->data_len);
  rv_gr.gr_name = rv_gr_buf;
  rv_gr.gr_passwd = (char *)"x";
  rv_gr.gr_gid = (gid_t)rv_hc->a0;
  rv_gr.gr_mem = NULL;
  return &rv_gr;
}

/* ------------------------------------------------------------------------- */
/* inet                                                                      */
/* ------------------------------------------------------------------------- */

char *inet_ntoa(struct in_addr in) {
  static char buf[16];
  const unsigned char *b = (const unsigned char *)&in;
  snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
  return buf;
}

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
  if (af == AF_INET) {
    const unsigned char *b = (const unsigned char *)src;
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    size_t n = strlen(tmp) + 1;
    if (n > size)
      return NULL;
    memcpy(dst, tmp, n);
    return dst;
  }
  return NULL;
}

/* ------------------------------------------------------------------------- */
/* Windows BOF API subset                                                    */
/*                                                                           */
/* Windows BOFs import APIs as MODULE$Function (KERNEL32$VirtualAlloc, ...).  */
/* The loader strips the prefix, so these guest implementations make simple   */
/* Windows BOFs run on any agent. This is intentionally a small, honest       */
/* subset: memory, handles, strings and time. Unsupported imports fail at     */
/* load time with a named unresolved symbol.                                  */
/* ------------------------------------------------------------------------- */

void *VirtualAlloc(void *addr, unsigned size, unsigned type, unsigned prot) {
  (void)addr;
  (void)type;
  (void)prot;
  return calloc(1, size);
}

int VirtualFree(void *addr, unsigned size, unsigned type) {
  (void)addr;
  (void)size;
  (void)type;
  return 1;
}

void *GetProcessHeap(void) { return (void *)1; }

void *HeapAlloc(void *heap, unsigned flags, unsigned size) {
  (void)heap;
  (void)flags;
  return calloc(1, size);
}

void *HeapReAlloc(void *heap, unsigned flags, void *p, unsigned size) {
  (void)heap;
  (void)flags;
  return realloc(p, size);
}

int HeapFree(void *heap, unsigned flags, void *p) {
  (void)heap;
  (void)flags;
  (void)p;
  return 1;
}

void *LocalAlloc(unsigned flags, unsigned size) {
  (void)flags;
  return calloc(1, size);
}

void *LocalFree(void *p) {
  (void)p;
  return NULL;
}

unsigned GetLastError(void) { return 0; }
void SetLastError(unsigned err) { (void)err; }

int CloseHandle(void *h) {
  (void)h;
  return 1;
}

void Sleep(unsigned ms) { rv_hostcall(RV_HC_USLEEP, ms * 1000u, 0, 0, 0); }

void *GetCurrentProcess(void) { return (void *)0xffffffffu; }

unsigned GetCurrentProcessId(void) {
  return (unsigned)rv_hostcall(RV_HC_GETPID, 0, 0, 0, 0);
}

int lstrlenA(const char *s) { return (int)strlen(s); }

char *lstrcpyA(char *dst, const char *src) { return strcpy(dst, src); }

char *lstrcatA(char *dst, const char *src) { return strcat(dst, src); }

int _stricmp(const char *a, const char *b) {
  while (*a != '\0' && *b != '\0') {
    char ca = *a, cb = *b;
    if (ca >= 'A' && ca <= 'Z')
      ca = (char)(ca - 'A' + 'a');
    if (cb >= 'A' && cb <= 'Z')
      cb = (char)(cb - 'A' + 'a');
    if (ca != cb)
      return (unsigned char)ca - (unsigned char)cb;
    a++;
    b++;
  }
  return (unsigned char)*a - (unsigned char)*b;
}

/* ------------------------------------------------------------------------- */
/* Beacon API                                                                */
/* ------------------------------------------------------------------------- */

typedef struct {
  char *original;
  char *buffer;
  int length;
  int size;
} datap;
typedef datap formatp;

void BeaconDataParse(datap *parser, char *buffer, int size) {
  if (parser == NULL)
    return;
  parser->original = buffer;
  parser->buffer = buffer;
  parser->length = 0;
  parser->size = 0;
  if (buffer == NULL || size < 4)
    return;
  uint32_t body_len;
  memcpy(&body_len, buffer, 4);
  size_t available = (size_t)size - 4;
  if (body_len > available)
    body_len = (uint32_t)available;
  parser->buffer = buffer + 4;
  parser->length = (int)body_len;
  parser->size = (int)body_len;
}

int BeaconDataInt(datap *parser) {
  if (parser == NULL || parser->length < 4)
    return 0;
  int v;
  memcpy(&v, parser->buffer, 4);
  parser->buffer += 4;
  parser->length -= 4;
  return v;
}

short BeaconDataShort(datap *parser) {
  if (parser == NULL || parser->length < 2)
    return 0;
  short v;
  memcpy(&v, parser->buffer, 2);
  parser->buffer += 2;
  parser->length -= 2;
  return v;
}

int BeaconDataLength(datap *parser) {
  return parser != NULL ? parser->length : 0;
}

char *BeaconDataExtract(datap *parser, int *size) {
  if (size != NULL)
    *size = 0;
  if (parser == NULL || parser->length < 4)
    return NULL;
  int len;
  memcpy(&len, parser->buffer, 4);
  parser->buffer += 4;
  parser->length -= 4;
  if (len < 0 || len > parser->length)
    return NULL;
  char *out = parser->buffer;
  parser->buffer += len;
  parser->length -= len;
  if (size != NULL)
    *size = len;
  return out;
}

void BeaconFormatAlloc(formatp *format, int maxsz) {
  if (format == NULL || maxsz <= 0)
    return;
  format->original = (char *)calloc((size_t)maxsz, 1);
  format->buffer = format->original;
  format->length = 0;
  format->size = format->original ? maxsz : 0;
}

void BeaconFormatReset(formatp *format) {
  if (format == NULL || format->original == NULL)
    return;
  memset(format->original, 0, (size_t)format->size);
  format->buffer = format->original;
  format->length = 0;
}

void BeaconFormatFree(formatp *format) {
  if (format == NULL)
    return;
  free(format->original);
  format->original = NULL;
  format->buffer = NULL;
  format->length = 0;
  format->size = 0;
}

void BeaconFormatAppend(formatp *format, char *text, int len) {
  if (format == NULL || text == NULL || len <= 0)
    return;
  if (format->length + len > format->size)
    return;
  memcpy(format->buffer + format->length, text, (size_t)len);
  format->length += len;
}

void BeaconFormatPrintf(formatp *format, char *fmt, ...) {
  if (format == NULL || fmt == NULL)
    return;
  va_list ap;
  va_start(ap, fmt);
  int room = format->size - format->length;
  if (room > 0)
    vsnprintf(format->buffer + format->length, (size_t)room, fmt, ap);
  va_end(ap);
  format->length = format->size; /* compat layer cannot know the exact size */
}

char *BeaconFormatToString(formatp *format, int *size) {
  if (size != NULL)
    *size = format != NULL ? format->length : 0;
  if (format == NULL || format->original == NULL)
    return NULL;
  format->original[format->length < format->size ? format->length
                                                 : format->size - 1] = '\0';
  return format->original;
}

void BeaconFormatInt(formatp *format, int value) {
  if (format == NULL || format->length + 4 > format->size)
    return;
  memcpy(format->buffer + format->length, &value, 4);
  format->length += 4;
}

static void beacon_write(const char *data, size_t len) {
  if (data != NULL && len > 0)
    rv_write_all(1, data, len);
}

void BeaconOutput(int type, const char *data, int len) {
  (void)type;
  if (data != NULL && len > 0)
    beacon_write(data, (size_t)len);
}

void BeaconPrintf(int type, const char *fmt, ...) {
  (void)type;
  if (fmt == NULL)
    return;
  va_list ap;
  va_start(ap, fmt);
  int needed = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (needed < 0)
    return;
  char *buf = (char *)malloc((size_t)needed + 2);
  if (buf == NULL)
    return;
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)needed + 1, fmt, ap);
  va_end(ap);
  buf[needed] = '\n';
  beacon_write(buf, (size_t)needed + 1);
  free(buf);
}

int BeaconIsAdmin(void) { return getuid() == 0; }

uint32_t swap_endianess(uint32_t indata) {
  return ((indata & 0x000000ffu) << 24) | ((indata & 0x0000ff00u) << 8) |
         ((indata & 0x00ff0000u) >> 8) | ((indata & 0xff000000u) >> 24);
}

const char *getOSName(void) { return "lin"; }

char *BeaconGetOutputData(int *outsize) {
  if (outsize != NULL)
    *outsize = 0;
  return NULL;
}

/* ------------------------------------------------------------------------- */
/* Entry trampoline                                                          */
/* ------------------------------------------------------------------------- */

typedef int (*rv_bof_entry)(char *args, int len);

int rv_bof_invoke(rv_bof_entry entry, char *args, int len) {
  int rc = entry(args, len);
  rv_guest_exit(rc);
  return rc;
}

/* Keep the compiler from dropping otherwise-unreferenced exports. */
void *rv_bof_runtime_anchor[] = {
    (void *)BeaconPrintf, (void *)BeaconOutput,  (void *)getEnviron,
    (void *)getOSName,    (void *)rv_bof_invoke, (void *)fopen,
    (void *)fread,        (void *)fclose,        (void *)opendir,
    (void *)readdir,      (void *)closedir,      (void *)stat,
    (void *)__xstat,      (void *)readlink,      (void *)uname,
    (void *)getpwuid,     (void *)getgrgid,      (void *)getgroups,
    (void *)inet_ntoa,    (void *)inet_ntop,     (void *)sscanf,
};
