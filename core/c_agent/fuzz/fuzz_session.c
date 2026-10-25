#include "transport.h"

#include "fuzz_common.h"
#include "stub_crypto.h"

#include "cbor.h"

#include <stdlib.h>
#include <string.h>

/*
 * c2_session_read is the join point between SecureConn and the CBOR message
 * decoder, and it also drives the PFS handshake state machine. The individual
 * pieces have their own fuzz targets; this one feeds arbitrary CBOR as a valid
 * MsgTunData frame, then exercises hello -> handshake reply -> key switch on
 * the same session.
 */

static c2_crypto_backend g_be;
static c2_agent_session g_session;
static c2_agent_config g_config;
static int g_ready;

static void session_init_once(void) {
  static const char *const uuid = "fuzz-uuid-1234";
  static const char *const tag = "fuzz";
  static const char *const magic = "fuzz-magic";

  if (g_ready)
    return;
  g_ready = 1;

  static uint32_t rng = 0x5eed1234u;
  stub_crypto_init(&g_be, &rng);
  memset(&g_config, 0, sizeof(g_config));
  g_config.magic_string = c2_str_of(magic, strlen(magic));
  g_config.agent_uuid = c2_str_of(uuid, strlen(uuid));
  g_config.agent_tag = c2_str_of(tag, strlen(tag));
  g_config.routes.checkin = c2_str_lit(C2_ROUTE_DEFAULT_CHECKIN);
  g_config.routes.msg = c2_str_lit(C2_ROUTE_DEFAULT_MSG);
  g_config.routes.ftp = c2_str_lit(C2_ROUTE_DEFAULT_FTP);
  g_config.routes.www = c2_str_lit(C2_ROUTE_DEFAULT_WWW);
  g_config.routes.proxy = c2_str_lit(C2_ROUTE_DEFAULT_PROXY);
  c2_transport no_transport = {0};
  if (c2_session_init(&g_session, &g_be, no_transport, &g_config, NULL) !=
      C2_OK) {
    memset(&g_session, 0, sizeof(g_session));
    g_ready = 0;
  }
}

static void session_reset(void) {
  g_session.pfs_established = 0;
  g_session.pfs_pending = 0;
  g_session.hello_job_id[0] = '\0';
  c2_secure_zero(g_session.pfs_priv, sizeof(g_session.pfs_priv));
  c2_secure_zero(g_session.pfs_pub, sizeof(g_session.pfs_pub));
  c2_secure_zero(g_session.session_key, sizeof(g_session.session_key));
}

typedef struct {
  const uint8_t *data;
  size_t len;
  size_t pos;
} rbuf;

static long rb_read(void *ctx, uint8_t *buf, size_t cap) {
  rbuf *r = (rbuf *)ctx;
  size_t n = r->len - r->pos;
  if (n > cap)
    n = cap;
  if (n)
    memcpy(buf, r->data + r->pos, n);
  r->pos += n;
  return (long)n;
}

static long rb_write(void *ctx, const uint8_t *buf, size_t len) {
  (void)ctx;
  (void)buf;
  return (long)len;
}

static void rb_close(void *ctx) { (void)ctx; }

static const c2_stream_ops g_rb_ops = {rb_read, rb_write, rb_close};

/* Encode one payload as a SecureConn frame, then run it through
 * c2_session_read. */
static void read_payload(const uint8_t *payload, size_t len) {
  size_t cap = len + C2_FRAME_OVERHEAD;
  uint8_t *frame = (uint8_t *)malloc(cap ? cap : 1);
  if (frame == NULL)
    return;

  c2_secureconn writer;
  c2_secureconn_init(&writer, &g_be, (c2_stream){0}, g_session.psk);
  size_t frame_len = 0;
  c2_status st = c2_secureconn_encode_frame(&writer, payload, len, 0, frame,
                                            cap, &frame_len);
  c2_secureconn_close(&writer);
  if (st != C2_OK) {
    free(frame);
    return;
  }

  rbuf rb = {frame, frame_len, 0};
  c2_secureconn reader;
  c2_secureconn_init(&reader, &g_be, (c2_stream){&g_rb_ops, &rb},
                     g_session.psk);
  c2_msgtun out;
  memset(&out, 0, sizeof(out));
  int is_job = 0;
  (void)c2_session_read(&g_session, &reader, &out, &is_job);
  c2_secureconn_close(&reader);
  free(frame);
}

/* Exercise the first-hello path and the handshake-reply branch (ECDH, HKDF and
 * the SecureConn key switch) with a fixed 64-byte reply. */
static void exercise_handshake(const uint8_t *data, size_t size) {
  c2_secureconn sink;
  c2_secureconn_init(&sink, &g_be, (c2_stream){&g_rb_ops, NULL}, g_session.psk);
  if (c2_session_hello(&g_session, &sink, 1) != C2_OK) {
    c2_secureconn_close(&sink);
    return;
  }
  c2_secureconn_close(&sink);

  uint8_t reply[C2_P256_PUB_BYTES];
  for (size_t i = 0; i < sizeof(reply); i++)
    reply[i] = size ? data[i % size] : (uint8_t)i;

  c2_msgtun m;
  memset(&m, 0, sizeof(m));
  m.job_id = c2_str_of(g_session.hello_job_id, strlen(g_session.hello_job_id));
  m.tag = c2_str_lit(C2_TAG_HANDSHAKE);
  m.response = c2_bytes_of(reply, sizeof(reply));

  uint8_t payload[512];
  CborEncoder enc;
  cbor_encoder_init(&enc, payload, sizeof(payload), 0);
  if (c2_msgtun_encode(&enc, &m) == C2_OK)
    read_payload(payload, cbor_encoder_get_buffer_size(&enc, payload));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  session_init_once();
  if (!g_ready)
    return 0;

  session_reset();
  read_payload(data, size);

  session_reset();
  exercise_handshake(data, size);
  session_reset();

  return 0;
}
