#include "transport.h"
#include "net_utils.h"
#include "utils.h"

#define BUFFER_SIZE 65536

/* Download the stage blob over raw HTTP (no TLS). The listener is expected to
 * sit behind a CDN/nginx reverse proxy that terminates TLS. */
static size_t http_download(const char *host, const char *port,
                            const char *path, void *buffer, size_t capacity,
                            const uint8_t *key) {
  (void)key; /* raw HTTP has no authentication handshake */

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

  /* Build the HTTP GET request. */
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
    return 0;
  }

  /* Read the response body, skipping the headers. */
  char temp_buffer[BUFFER_SIZE];
  size_t data_size = 0;
  unsigned int http_marker = 0;
  int header_end = 0;
  const char *delim = "\r\n\r\n";
  while (1) {
    long n = recv(sockfd, temp_buffer, BUFFER_SIZE, 0);
    if (n <= 0)
      break;

    if (!header_end) {
      for (long i = 0; i < n; i++) {
        if ((unsigned char)temp_buffer[i] ==
            (unsigned char)delim[http_marker]) {
          http_marker++;
          if (http_marker == 4) {
            header_end = 1;
            if (i + 1 < n) {
              size_t body = (size_t)(n - (i + 1));
              if (data_size + body > capacity)
                goto done;
              memcpy((char *)buffer + data_size, temp_buffer + i + 1, body);
              data_size += body;
            }
            break;
          }
        } else {
          http_marker =
              ((unsigned char)temp_buffer[i] == (unsigned char)delim[0]) ? 1
                                                                         : 0;
        }
      }
    } else {
      if (data_size + (size_t)n > capacity)
        break;
      memcpy((char *)buffer + data_size, temp_buffer, (size_t)n);
      data_size += (size_t)n;
    }
  }

done:
  close(sockfd);
  return data_size;
}

const char *transport_name(void) { return "http"; }

size_t transport_download(const char *host, const char *port, const char *path,
                          void *buffer, size_t capacity, const uint8_t *key) {
  return http_download(host, port, path, buffer, capacity, key);
}
