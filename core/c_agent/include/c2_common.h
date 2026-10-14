#ifndef C2_COMMON_H
#define C2_COMMON_H

/*
 * c2_common.h — root constants and helpers for the emp3r0r C2 wire protocol.
 *
 * This header is deliberately freestanding: it only needs <stddef.h> and
 * <stdint.h> so it compiles in a -nostdlib PIC stager as well as in a hosted
 * agent. It carries no state and pulls in no crypto, CBOR or network code.
 *
 * The normative description of the protocol is PROTOCOL.md at the repository
 * root. Every constant here is a transcription of a Go constant or default so
 * a C agent can be written without re-reading the Go source. If a value changes
 * on the Go side it MUST change here in the same commit.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Protocol identity                                                          */
/* ------------------------------------------------------------------------- */

/*
 * ProtocolVersion is carried in every MsgAuth (CBOR key 20). The C2 rejects any
 * other value, so all peers must be built from the same batch. Bump it for any
 * incompatible wire change and update def.ProtocolVersion in the Go source.
 */
#define C2_PROTOCOL_VERSION 1

/* Value of MsgAuth.Type. */
#define C2_MSGAUTH_TYPE "auth_v1"

/* ------------------------------------------------------------------------- */
/* Hard limits (mirrors PROTOCOL.md §2.4)                                     */
/* ------------------------------------------------------------------------- */

/* The first CBOR frame (MsgAuth) must fit in one SecureConn frame. */
#define C2_AUTH_FRAME_MAX 8192u
/* Maximum encrypted frame length enforced by SecureConn on both sides. */
#define C2_FRAME_ENC_MAX (10u * 1024u * 1024u)
/* Maximum HTTP request body accepted by the server (http_poll). */
#define C2_HTTP_BODY_MAX (50u * 1024u * 1024u)
/* Allowed clock skew for MsgAuth.Timestamp, in seconds. */
#define C2_REPLAY_WINDOW_SECONDS 60
/* Server-side timeout for an unauthenticated stream. */
#define C2_HANDSHAKE_TIMEOUT_SECONDS 10
/* Message-tunnel silence timeout on the server. */
#define C2_TUNNEL_SILENCE_SECONDS 600
/* Maximum plaintext payload that may carry stealth padding. */
#define C2_PADDING_MAX_FRAME (32u * 1024u)

/* ------------------------------------------------------------------------- */
/* Cryptographic sizes                                                        */
/* ------------------------------------------------------------------------- */

#define C2_AES_KEY_BYTES 32u
#define C2_GCM_NONCE_BYTES 12u
#define C2_GCM_TAG_BYTES 16u
#define C2_SHA256_BYTES 32u
#define C2_MD5_BYTES 16u
#define C2_MD5_HEX_BYTES 32u /* lowercase hex text, used as the PSK */

/* P-256 public keys travel as X || Y, each coordinate left-padded to 32 bytes. */
#define C2_P256_COORD_BYTES 32u
#define C2_P256_PRIV_BYTES 32u
#define C2_P256_PUB_BYTES 64u

/* ------------------------------------------------------------------------- */
/* Key derivation context (mirrors transport.DeriveSessionKey)                */
/* ------------------------------------------------------------------------- */

#define C2_PFS_SALT "session-key-salt-v1"
#define C2_PFS_INFO_PREFIX "client-session:"

/* ------------------------------------------------------------------------- */
/* Route names                                                                */
/* ------------------------------------------------------------------------- */

/*
 * These are defaults only. The real names are per-build config values and are
 * carried in c2_agent_config.routes (CBOR key 75). An agent MUST use the
 * configured names from its embedded config, not these defaults.
 */
#define C2_ROUTE_DEFAULT_CHECKIN "c2-checkin"
#define C2_ROUTE_DEFAULT_MSG "c2-msg"
#define C2_ROUTE_DEFAULT_FTP "c2-ftp"
#define C2_ROUTE_DEFAULT_WWW "c2-www"
#define C2_ROUTE_DEFAULT_PROXY "c2-proxy"

/* ------------------------------------------------------------------------- */
/* MsgAuth.Capabilities tokens                                                */
/* ------------------------------------------------------------------------- */

/*
 * Exactly one route token must be present; the C2 ranks the others as feature
 * advertisement. Unknown tokens are ignored by the server (so feature
 * advertising is forward compatible) but are part of the signed canonical
 * string, so they must be sent exactly as advertised.
 */
#define C2_CAP_FILE_MGMT "file-mgmt"
#define C2_CAP_BOF "bof"
#define C2_CAP_MEMMOD "memmod"
#define C2_CAP_SOCKS5 "socks5"
#define C2_CAP_MESH "mesh"

/* AgentToken.Capability value that authorises mesh routing. */
#define C2_CAP_ROUTER "router"

/* Maximum capability tokens c2_auth_canonical will sort. A route plus a handful
 * of feature tokens is the realistic maximum; the bound keeps sorting off the
 * heap in freestanding builds. */
#define C2_MAX_CAPABILITIES 32

/* ------------------------------------------------------------------------- */
/* MsgTunData.Tag values                                                      */
/* ------------------------------------------------------------------------- */

#define C2_TAG_CHECKIN_OK "checkin-ok" /* C2 -> agent check-in ACK        */
#define C2_TAG_HANDSHAKE "handshake"   /* C2 -> agent ECDH / keep-alive   */
#define C2_TAG_PEER_LIST "peer_list"   /* C2 -> agent gossip peers        */
#define C2_TAG_AGENT_TOKEN "agent_token" /* C2 -> agent mesh token        */

/* ------------------------------------------------------------------------- */
/* Status codes                                                               */
/* ------------------------------------------------------------------------- */

typedef enum {
  C2_OK = 0,
  C2_ERR_ARG = -1,       /* invalid argument or buffer too small        */
  C2_ERR_NOMEM = -2,     /* caller buffer exhausted                     */
  C2_ERR_PROTO = -3,     /* malformed frame / CBOR / message            */
  C2_ERR_CRYPTO = -4,    /* encrypt/decrypt/signature failure           */
  C2_ERR_AUTH = -5,      /* identity, replay or CA verification failure */
  C2_ERR_IO = -6,        /* transport read/write/close failure          */
  C2_ERR_TIMEOUT = -7,   /* operation exceeded its deadline             */
  C2_ERR_OVERFLOW = -8,  /* untrusted length/count out of range         */
  C2_ERR_UNSUPPORTED = -9,
} c2_status;

/* Human-readable name of a status code (never NULL). */
const char *c2_status_str(c2_status st);

/* ------------------------------------------------------------------------- */
/* Byte-order helpers (big-endian on the wire)                                */
/* ------------------------------------------------------------------------- */

static inline uint32_t c2_be32_load(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint64_t c2_be64_load(const uint8_t *p) {
  return ((uint64_t)c2_be32_load(p) << 32) | (uint64_t)c2_be32_load(p + 4);
}

static inline void c2_be32_store(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static inline void c2_be64_store(uint8_t *p, uint64_t v) {
  c2_be32_store(p, (uint32_t)(v >> 32));
  c2_be32_store(p + 4, (uint32_t)v);
}

/* ------------------------------------------------------------------------- */
/* Small security helpers                                                     */
/* ------------------------------------------------------------------------- */

/*
 * Zero a buffer in a way the optimizer cannot elide. Use it for every key,
 * nonce and decrypted plaintext that is no longer needed.
 */
static inline void c2_secure_zero(void *p, size_t n) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n--) {
    *v++ = 0;
  }
}

/* Constant-time equality. Returns 1 when the n bytes match, 0 otherwise. */
static inline int c2_ct_equal(const void *a, const void *b, size_t n) {
  const volatile uint8_t *x = (const volatile uint8_t *)a;
  const volatile uint8_t *y = (const volatile uint8_t *)b;
  uint8_t diff = 0;
  while (n--) {
    diff |= (uint8_t)(*x++ ^ *y++);
  }
  return diff == 0;
}

/* Bounded length/offset check: 0 <= off <= total && len <= total - off. */
static inline int c2_range_ok(size_t off, size_t len, size_t total) {
  return off <= total && len <= total - off;
}

/* ------------------------------------------------------------------------- */
/* Slice types used by the message codecs                                     */
/* ------------------------------------------------------------------------- */

/*
 * Strings and byte strings are borrowed slices into a caller-owned buffer. The
 * decode side points into the input CBOR; the encode side may point at any
 * caller-owned memory. Neither carries a NUL terminator: use .len.
 */
typedef struct {
  const char *ptr;
  size_t len;
} c2_str;

typedef struct {
  const uint8_t *ptr;
  size_t len;
} c2_bytes;

static inline c2_str c2_str_lit(const char *s) {
  c2_str out;
  out.ptr = s;
  out.len = 0;
  if (s) {
    const char *p = s;
    while (*p) {
      p++;
    }
    out.len = (size_t)(p - s);
  }
  return out;
}

static inline c2_str c2_str_of(const char *s, size_t len) {
  c2_str out;
  out.ptr = s;
  out.len = len;
  return out;
}

static inline c2_bytes c2_bytes_of(const void *p, size_t len) {
  c2_bytes out;
  out.ptr = (const uint8_t *)p;
  out.len = len;
  return out;
}

static inline int c2_str_equal(c2_str a, const char *b) {
  if (!b) {
    return a.len == 0;
  }
  size_t i = 0;
  while (i < a.len && b[i] && a.ptr[i] == b[i]) {
    i++;
  }
  return i == a.len && b[i] == '\0';
}

static inline int c2_str_equal_str(c2_str a, c2_str b) {
  return a.len == b.len &&
         (a.len == 0 || c2_ct_equal(a.ptr, b.ptr, a.len));
}

/* ------------------------------------------------------------------------- */
/* Hex and base64url (URL-safe, padded) text codecs                           */
/* ------------------------------------------------------------------------- */

static inline size_t c2_hex_encode(const uint8_t *in, size_t n, char *out) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[i * 2] = digits[in[i] >> 4];
    out[i * 2 + 1] = digits[in[i] & 0x0f];
  }
  return n * 2;
}

static inline int c2_hex_nibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* Decode exactly n hex chars (n must be even) into out. Returns bytes or -1. */
static inline long c2_hex_decode(const char *in, size_t n, uint8_t *out,
                                 size_t cap) {
  if ((n & 1u) != 0 || n / 2 > cap)
    return -1;
  for (size_t i = 0; i < n / 2; i++) {
    int hi = c2_hex_nibble(in[i * 2]);
    int lo = c2_hex_nibble(in[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return (long)(n / 2);
}

static inline size_t c2_base64url_encoded_len(size_t n) {
  return ((n + 2u) / 3u) * 4u;
}

/* Encode n bytes as URL-safe base64. Returns chars written or 0 on overflow. */
static inline size_t c2_base64url_encode(const uint8_t *in, size_t n, char *out,
                                         size_t cap) {
  static const char tbl[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  size_t need = c2_base64url_encoded_len(n);
  if (need > cap)
    return 0;
  size_t o = 0;
  for (size_t i = 0; i < n; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16;
    if (i + 1 < n)
      v |= (uint32_t)in[i + 1] << 8;
    if (i + 2 < n)
      v |= (uint32_t)in[i + 2];
    out[o++] = tbl[(v >> 18) & 0x3f];
    out[o++] = tbl[(v >> 12) & 0x3f];
    out[o++] = (i + 1 < n) ? tbl[(v >> 6) & 0x3f] : '=';
    out[o++] = (i + 2 < n) ? tbl[v & 0x3f] : '=';
  }
  return o;
}

static inline int c2_base64url_value(char c) {
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '-')
    return 62;
  if (c == '_')
    return 63;
  return -1;
}

/*
 * Decode URL-safe base64 with padding into out. Accepts only the canonical
 * padded form. Returns C2_OK and sets *out_len on success, else a c2_status.
 */
static inline c2_status c2_base64url_decode(const char *in, size_t n,
                                            uint8_t *out, size_t cap,
                                            size_t *out_len) {
  if ((n & 3u) != 0 || n < 4) {
    return C2_ERR_PROTO;
  }
  size_t o = 0;
  for (size_t i = 0; i < n; i += 4) {
    int a = c2_base64url_value(in[i]);
    int b = c2_base64url_value(in[i + 1]);
    int c = in[i + 2] == '=' ? -2 : c2_base64url_value(in[i + 2]);
    int d = in[i + 3] == '=' ? -2 : c2_base64url_value(in[i + 3]);
    if (a < 0 || b < 0 || c == -1 || d == -1) {
      return C2_ERR_PROTO;
    }
    uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12);
    if (o < cap)
      out[o] = (uint8_t)(v >> 16);
    o++;
    if (c >= 0) {
      v |= (uint32_t)c << 6;
      if (o < cap)
        out[o] = (uint8_t)(v >> 8);
      o++;
      if (d >= 0) {
        v |= (uint32_t)d;
        if (o < cap)
          out[o] = (uint8_t)v;
        o++;
      }
    }
  }
  *out_len = o;
  return o <= cap ? C2_OK : C2_ERR_NOMEM;
}

#ifdef __cplusplus
}
#endif

#endif /* C2_COMMON_H */
