#include "packer.h" /* DERIVED_KEY_LEN */
#include "transport.h"
#include "net_utils.h"
#include "utils.h"

#define BUFFER_SIZE 65536

/* Download the stage blob over raw UDP. The listener authenticates the hello
 * packet via a key hash before sending the blob in sequenced chunks. */
static size_t udp_download(const char *host, const char *port,
                           const char *path, void *buffer, size_t capacity,
                           const uint8_t *key) {
  (void)path;

  struct sockaddr_in serv_addr;
  if (resolve_addr(host, port, &serv_addr) != 0)
    return 0;

  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sockfd == -1)
    return 0;

  struct sockaddr_in src_addr;
  unsigned int src_len = sizeof(src_addr);
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

  uint32_t key_hash = 0;
  for (int i = 0; i < DERIVED_KEY_LEN; i++) {
    key_hash ^= ((uint32_t)key[i]) << ((i % 4) * 8);
  }

  char hello_packet[5];
  hello_packet[0] = 0x02;
  memcpy(hello_packet + 1, &key_hash, 4);
  uint32_t expected_seq = 0;
  int hello_retries = 0;

  char temp_buffer[BUFFER_SIZE];
  size_t data_size = 0;

  while (1) {
    if (expected_seq == 0) {
      if (sendto(sockfd, hello_packet, 5, 0, (struct sockaddr *)&serv_addr,
                 sizeof(serv_addr)) == -1) {
        close(sockfd);
        return 0;
      }
    }
    long n = recvfrom(sockfd, temp_buffer, BUFFER_SIZE, 0,
                      (struct sockaddr *)&src_addr, &src_len);
    if (n <= 0) {
      if (expected_seq == 0) {
        hello_retries++;
        if (hello_retries > 20)
          break;
        continue;
      }
      break;
    }
    if (n > 4) {
      uint32_t seq = 0;
      memcpy(&seq, temp_buffer, 4);
      if (seq == expected_seq) {
        size_t body = (size_t)n - 4;
        if (data_size + body > capacity)
          break;
        memcpy((char *)buffer + data_size, temp_buffer + 4, body);
        data_size += body;
        expected_seq++;
        sendto(sockfd, &seq, 4, 0, (struct sockaddr *)&src_addr, src_len);
      } else if (seq < expected_seq) {
        sendto(sockfd, &seq, 4, 0, (struct sockaddr *)&src_addr, src_len);
      }
    }
  }

  close(sockfd);
  return data_size;
}

const char *transport_name(void) { return "udp"; }

size_t transport_download(const char *host, const char *port, const char *path,
                          void *buffer, size_t capacity, const uint8_t *key) {
  return udp_download(host, port, path, buffer, capacity, key);
}
