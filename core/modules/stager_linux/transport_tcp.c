#include "transport.h"
#include "net_utils.h"
#include "utils.h"

#define BUFFER_SIZE 65536

/* Download the stage blob over raw TCP: the listener sends the encrypted blob
 * verbatim and closes the connection when done. */
static size_t tcp_download(const char *host, const char *port,
                           const char *path, void *buffer, size_t capacity,
                           const uint8_t *key) {
  (void)path;
  (void)key;

  struct sockaddr_in serv_addr;
  if (resolve_addr(host, port, &serv_addr) != 0)
    return 0;

  int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sockfd == -1)
    return 0;
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
    close(sockfd);
    return 0;
  }

  char temp_buffer[BUFFER_SIZE];
  size_t data_size = 0;
  while (1) {
    long n = recv(sockfd, temp_buffer, BUFFER_SIZE, 0);
    if (n <= 0)
      break;
    if (data_size + (size_t)n > capacity)
      break;
    memcpy((char *)buffer + data_size, temp_buffer, (size_t)n);
    data_size += (size_t)n;
  }

  close(sockfd);
  return data_size;
}

const char *transport_name(void) { return "tcp"; }

size_t transport_download(const char *host, const char *port, const char *path,
                          void *buffer, size_t capacity, const uint8_t *key) {
  return tcp_download(host, port, path, buffer, capacity, key);
}
