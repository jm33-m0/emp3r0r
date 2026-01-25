#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <shellcode.bin> [args...]\n", argv[0]);
        return 1;
    }

    const char *shellcode_path = argv[1];
    
    // Open shellcode file
    int fd = open(shellcode_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // Get file size
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    
    printf("[*] Shellcode size: %ld bytes\n", size);

    // Allocate executable memory
    void *shellcode = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shellcode == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    // Read shellcode
    if (read(fd, shellcode, size) != size) {
        perror("read");
        munmap(shellcode, size);
        close(fd);
        return 1;
    }
    close(fd);

    printf("[*] Shellcode loaded at: %p\n", shellcode);
    printf("[*] Jumping to shellcode...\n");
    printf("=====================================\n");
    fflush(stdout);

    // Setup a fake stack that the shellcode expects:
    // [sp] = argc
    // [sp + 8] = argv[0]
    // [sp + 16] = NULL (end of argv)
    // [sp + 24] = NULL (end of envp)
    static const char *sh_argv[] = {"shellcode_test", NULL};
    
    __asm__ __volatile__(
        "mov %0, %%rdi\n"          // argv[0]
        "push $0\n"               // envp[0] = NULL
        "push $0\n"               // argv[1] = NULL
        "push %%rdi\n"            // argv[0]
        "push $1\n"               // argc = 1
        "jmp *%1\n"
        : : "r"(sh_argv[0]), "r"(shellcode) : "rdi", "memory"
    );

    return 0;
}
