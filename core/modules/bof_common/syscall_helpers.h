#ifndef SYSCALL_HELPERS_H
#define SYSCALL_HELPERS_H

#include <stddef.h>
#include "syscalls.h"

// Types needed for getdents64
struct linux_dirent64 {
    unsigned long long d_ino;
    long long          d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};

// Flags for open
#define O_RDONLY 0
#define O_DIRECTORY 0200000

// Helper: String length
static inline size_t my_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

// Helper: Memory copy
static inline void my_memcpy(void *dest, const void *src, size_t n) {
    char *d = (char *)dest;
    const char *s = (const char *)src;
    while (n--) *d++ = *s++;
}

// Helper to convert int to string
static inline void my_itoa(int n, char *s) {
    int i = 0, sign = n;
    if (sign < 0) n = -n;
    
    do {
        s[i++] = n % 10 + '0';
    } while ((n /= 10) > 0);
    
    if (sign < 0) s[i++] = '-';
    s[i] = '\0';

    // Reverse
    for (int j = 0, k = i - 1; j < k; j++, k--) {
        char temp = s[j];
        s[j] = s[k];
        s[k] = temp;
    }
}

// Helper: Append string
static inline void append_str(char *dest, size_t *offset, size_t max_len, const char *src) {
    size_t src_len = my_strlen(src);
    
    if (*offset + src_len >= max_len - 1) {
        if (*offset < max_len - 1) {
            src_len = max_len - 1 - *offset;
        } else {
            return;
        }
    }
    
    my_memcpy(dest + *offset, src, src_len);
    *offset += src_len;
    dest[*offset] = '\0';
}

#endif
