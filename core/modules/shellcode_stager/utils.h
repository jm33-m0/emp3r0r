#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

typedef long ssize_t;

#define UINT_MAX 4294967295U
#define INT_MAX 2147483647

// Memory protection
#define PROT_NONE 0x0
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

// Map flags
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_ANON MAP_ANONYMOUS
#define MAP_FAILED ((void *)-1)

// Waitpid options
#ifndef WNOHANG
#define WNOHANG 1
#endif
#ifndef WUNTRACED
#define WUNTRACED 2
#endif

// Wait status macros
#define WIFEXITED(status) (((status) & 0x7f) == 0)
#define WIFSIGNALED(status) (((signed char) (((status) & 0x7f) + 1) >> 1) > 0)
#define WIFSTOPPED(status) (((status) & 0xff) == 0x7f)
#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)
#define WTERMSIG(status) ((status) & 0x7f)
#define WSTOPSIG(status) (((status) & 0xff00) >> 8)

// File descriptors
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

// Open flags
#define O_RDONLY 00
#define O_WRONLY 01
#define O_RDWR   02

// Lseek whence
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2


struct timespec {
  long tv_sec;
  long tv_nsec;
};

#define WNOHANG 1

// Signal
#define SIGTRAP 5
#define SIGKILL 9

#define SIGCONT 18
#define SIG_DFL ((void (*)(int))0)
#define SIG_IGN ((void (*)(int))1)
#define NSIG 64
#define _NSIG_BPW 64
#define _NSIG_WORDS (NSIG / _NSIG_BPW)

typedef unsigned long old_sigset_t;

typedef struct {
  unsigned long sig[_NSIG_WORDS];
} sigset_t;

struct sigaction {
  void (*sa_handler)(int);
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  sigset_t sa_mask;
};

// Libc replacements
void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
size_t strlen(const char *s);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strstr(const char *haystack, const char *needle);
int snprintf(char *str, size_t size, const char *format,
             ...); // Minimal implementation or stub
void debug_print(const char *format, ...);
void perror(const char *s); // Stub

// Random
long getrandom(void *buf, size_t buflen, unsigned int flags);

// Syscall wrappers
long write(int fd, const void *buf, size_t count);
long read(int fd, void *buf, size_t count);
long close(int fd);
long open(const char *pathname, int flags, int mode);
long lseek(int fd, long offset, int whence);
long exit(int error_code);
long mmap(void *addr, size_t length, int prot, int flags, int fd, long offset);
long munmap(void *addr, size_t length);
long mprotect(void *addr, size_t len, int prot);
long fork(void);
long pipe(int pipefd[2]);
long dup2(int oldfd, int newfd);
long waitpid(int pid, int *status, int options);
long getuid(void);
long geteuid(void);
long getgid(void);
long getegid(void);
long kill(int pid, int sig);
long nanosleep(const struct timespec *req, struct timespec *rem);
int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact);
int sigemptyset(sigset_t *set);

#endif
