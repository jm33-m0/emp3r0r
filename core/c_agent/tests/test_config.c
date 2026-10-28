#include "transport.h"

#include "crypto.h"

#include "cbor.h"

#include "test.h"

/*
 * c2_agent_config_decode turns the plaintext of the embedded build config into
 * the communication subset of def.AgentConfig. The encoder lives in Go, so the
 * tests construct the CBOR the Go builder emits (integer keys, nested route and
 * malleable-HTTP maps, text-keyed custom headers) and assert both the decoded
 * values and the NormalizeC2Routes defaults. c2_config_decrypt is checked with
 * a real encrypt/decrypt round trip.
 */

static c2_status decode_cfg(const uint8_t *buf, size_t len,
                            c2_agent_config *cfg) {
  CborParser p;
  CborValue it;
  if (cbor_parser_init(buf, len, 0, &p, &it) != CborNoError)
    return C2_ERR_PROTO;
  return c2_agent_config_decode(&it, cfg);
}

static void enc_text(CborEncoder *m, uint64_t k, const char *v) {
  CHECK(cbor_encode_uint(m, k) == CborNoError);
  CHECK(cbor_encode_text_stringz(m, v) == CborNoError);
}

static void enc_bytes(CborEncoder *m, uint64_t k, const char *v) {
  CHECK(cbor_encode_uint(m, k) == CborNoError);
  CHECK(cbor_encode_byte_string(m, (const uint8_t *)v, strlen(v)) ==
        CborNoError);
}

static void enc_int(CborEncoder *m, uint64_t k, int64_t v) {
  CHECK(cbor_encode_uint(m, k) == CborNoError);
  CHECK(cbor_encode_int(m, v) == CborNoError);
}

static void enc_bool(CborEncoder *m, uint64_t k, int v) {
  CHECK(cbor_encode_uint(m, k) == CborNoError);
  CHECK(cbor_encode_boolean(m, v != 0) == CborNoError);
}

static void enc_routes(CborEncoder *m) {
  CHECK(cbor_encode_uint(m, C2_KEY_CFG_C2_ROUTES) == CborNoError);
  CborEncoder r;
  CHECK(cbor_encoder_create_map(m, &r, 5) == CborNoError);
  enc_text(&r, C2_KEY_ROUTE_CHECKIN, "r-checkin");
  enc_text(&r, C2_KEY_ROUTE_MSG, "r-msg");
  enc_text(&r, C2_KEY_ROUTE_FTP, "r-ftp");
  enc_text(&r, C2_KEY_ROUTE_WWW, "r-www");
  enc_text(&r, C2_KEY_ROUTE_PROXY, "r-proxy");
  CHECK(cbor_encoder_close_container(m, &r) == CborNoError);
}

static void enc_profile(CborEncoder *m, int headers) {
  CHECK(cbor_encode_uint(m, C2_KEY_CFG_MALLEABLE_C2) == CborNoError);
  CborEncoder p;
  CHECK(cbor_encoder_create_map(m, &p, 8) == CborNoError);
  enc_text(&p, C2_KEY_HTTP_PATH, "/api/v1");
  enc_text(&p, C2_KEY_HTTP_SESSION_HEADER, "X-Session");
  enc_text(&p, C2_KEY_HTTP_SESSION_VALUE, "id-%s");
  enc_text(&p, C2_KEY_HTTP_INIT_HEADER, "X-Init");
  enc_text(&p, C2_KEY_HTTP_INIT_VALUE, "1");
  enc_text(&p, C2_KEY_HTTP_CLOSE_HEADER, "X-Close");
  enc_text(&p, C2_KEY_HTTP_CLOSE_VALUE, "1");
  CHECK(cbor_encode_uint(&p, C2_KEY_HTTP_CUSTOM_HEADERS) == CborNoError);
  CborEncoder h;
  CHECK(cbor_encoder_create_map(&p, &h, headers) == CborNoError);
  for (int i = 0; i < headers; i++) {
    char k[16];
    snprintf(k, sizeof(k), "X-H%d", i);
    CHECK(cbor_encode_text_stringz(&h, k) == CborNoError);
    CHECK(cbor_encode_text_stringz(&h, "v") == CborNoError);
  }
  CHECK(cbor_encoder_close_container(&p, &h) == CborNoError);
  CHECK(cbor_encoder_close_container(m, &p) == CborNoError);
}

static void enc_transport_options(CborEncoder *m) {
  CHECK(cbor_encode_uint(m, C2_KEY_CFG_TRANSPORT_OPTIONS) == CborNoError);
  CborEncoder opts;
  CHECK(cbor_encoder_create_map(m, &opts, 2) == CborNoError);
  CHECK(cbor_encode_text_stringz(&opts, "socks5") == CborNoError);
  CHECK(cbor_encode_text_stringz(&opts, "127.0.0.1:9050") == CborNoError);
  CHECK(cbor_encode_text_stringz(&opts, "zone") == CborNoError);
  CHECK(cbor_encode_text_stringz(&opts, "example.onion") == CborNoError);
  CHECK(cbor_encoder_close_container(m, &opts) == CborNoError);
}

static size_t build_full_config(uint8_t *buf, size_t cap, int pairs) {
  CborEncoder e, m;
  cbor_encoder_init(&e, buf, cap, 0);
  CHECK(cbor_encoder_create_map(&e, &m, pairs) == CborNoError);
  enc_text(&m, C2_KEY_CFG_CC_ADDRESS, "10.0.0.1");
  enc_text(&m, C2_KEY_CFG_CC_HTTP_PORT, "8080");
  enc_text(&m, C2_KEY_CFG_CC_H2_PORT, "8443");
  enc_text(&m, C2_KEY_CFG_PASSWORD, "sekret");
  enc_text(&m, C2_KEY_CFG_CAPEM, "-----BEGIN CERTIFICATE-----");
  enc_text(&m, C2_KEY_CFG_DOH_SERVER, "https://1.1.1.1/dns-query");
  enc_text(&m, C2_KEY_CFG_AGENT_UUID, "uuid-1");
  enc_bytes(&m, C2_KEY_CFG_AGENT_UUID_SIG, "sig");
  enc_text(&m, C2_KEY_CFG_AGENT_TAG, "abcd1234");
  enc_int(&m, C2_KEY_CFG_PADDING_MIN, 16);
  enc_int(&m, C2_KEY_CFG_PADDING_MAX, 64);
  enc_int(&m, C2_KEY_CFG_JITTER, 20);
  enc_int(&m, C2_KEY_CFG_POLL_INTERVAL, 10);
  enc_bool(&m, C2_KEY_CFG_IS_RUN_BY_STAGER, 1);
  enc_text(&m, C2_KEY_CFG_C2_CHANNEL_MODE, "h2conn");
  enc_routes(&m);
  enc_profile(&m, 2);
  enc_transport_options(&m);
  enc_text(&m, 999, "future key"); /* unknown keys must be skipped */
  CHECK(cbor_encoder_close_container(&e, &m) == CborNoError);
  return cbor_encoder_get_buffer_size(&e, buf);
}

int main(void) {
  uint8_t buf[2048];
  c2_agent_config cfg;

  /* Full config: every communication key is decoded, nested maps included. */
  {
    size_t n = build_full_config(buf, sizeof(buf), 19);
    memset(&cfg, 0, sizeof(cfg));
    c2_str hk[4], hv[4];
    cfg.http.header_keys = hk;
    cfg.http.header_values = hv;
    cfg.http.header_cap = 4;
    CHECK(decode_cfg(buf, n, &cfg) == C2_OK);
    CHECK(c2_str_equal(cfg.cc_address, "10.0.0.1"));
    CHECK(c2_str_equal(cfg.cc_http_port, "8080"));
    CHECK(c2_str_equal(cfg.cc_h2_port, "8443"));
    CHECK(c2_str_equal(cfg.password, "sekret"));
    CHECK(c2_str_equal(cfg.doh_server, "https://1.1.1.1/dns-query"));
    CHECK(c2_str_equal(cfg.agent_uuid, "uuid-1"));
    CHECK(cfg.agent_uuid_sig.len == 3 &&
          memcmp(cfg.agent_uuid_sig.ptr, "sig", 3) == 0);
    CHECK(c2_str_equal(cfg.agent_tag, "abcd1234"));
    CHECK(c2_str_equal(cfg.c2_channel_mode, "h2conn"));
    CHECK_EQ_LONG(cfg.padding_min, 16);
    CHECK_EQ_LONG(cfg.padding_max, 64);
    CHECK_EQ_LONG(cfg.jitter, 20);
    CHECK_EQ_LONG(cfg.poll_interval, 10);
    CHECK_EQ_LONG(cfg.is_run_by_stager, 1);
    CHECK(c2_str_equal(cfg.routes.checkin, "r-checkin"));
    CHECK(c2_str_equal(cfg.routes.www, "r-www"));
    CHECK(c2_str_equal(cfg.http.c2_path, "/api/v1"));
    CHECK(c2_str_equal(cfg.http.session_header, "X-Session"));
    CHECK(c2_str_equal(cfg.http.session_value, "id-%s"));
    CHECK(c2_str_equal(cfg.http.init_header, "X-Init"));
    CHECK_EQ_LONG(cfg.http.header_count, 2);
    CHECK(c2_str_equal(cfg.http.header_keys[0], "X-H0"));
    CHECK(c2_str_equal(cfg.http.header_values[1], "v"));
    CHECK_EQ_LONG(cfg.transport_option_count, 2);
    CHECK(c2_str_equal(c2_agent_config_option(&cfg, "socks5"),
                       "127.0.0.1:9050"));
    CHECK(c2_str_equal(c2_agent_config_option(&cfg, "zone"),
                       "example.onion"));
    CHECK(c2_agent_config_option(&cfg, "missing").len == 0);
  }

  /* Go encodes a nil TransportOptions map as CBOR null. */
  {
    CborEncoder e, m;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_map(&e, &m, 1) == CborNoError);
    CHECK(cbor_encode_uint(&m, C2_KEY_CFG_TRANSPORT_OPTIONS) == CborNoError);
    CHECK(cbor_encode_null(&m) == CborNoError);
    CHECK(cbor_encoder_close_container(&e, &m) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);
    memset(&cfg, 0, sizeof(cfg));
    CHECK(decode_cfg(buf, n, &cfg) == C2_OK);
    CHECK_EQ_LONG(cfg.transport_option_count, 0);
    CHECK(c2_agent_config_option(&cfg, "socks5").len == 0);
  }

  /* Empty config: the decoder fills the Go defaults (NormalizeC2Routes). */
  {
    CborEncoder e, m;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_map(&e, &m, 0) == CborNoError);
    CHECK(cbor_encoder_close_container(&e, &m) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);
    memset(&cfg, 0, sizeof(cfg));
    CHECK(decode_cfg(buf, n, &cfg) == C2_OK);
    CHECK(c2_str_equal(cfg.routes.checkin, C2_ROUTE_DEFAULT_CHECKIN));
    CHECK(c2_str_equal(cfg.routes.msg, C2_ROUTE_DEFAULT_MSG));
    CHECK(c2_str_equal(cfg.routes.ftp, C2_ROUTE_DEFAULT_FTP));
    CHECK(c2_str_equal(cfg.routes.www, C2_ROUTE_DEFAULT_WWW));
    CHECK(c2_str_equal(cfg.routes.proxy, C2_ROUTE_DEFAULT_PROXY));
    CHECK(c2_str_equal(cfg.c2_channel_mode, C2_CHANNEL_DEFAULT));
  }

  /* Custom headers that do not fit the caller's array: C2_ERR_NOMEM. */
  {
    CborEncoder e, m;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_map(&e, &m, 1) == CborNoError);
    enc_profile(&m, 3);
    CHECK(cbor_encoder_close_container(&e, &m) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);
    memset(&cfg, 0, sizeof(cfg));
    c2_str hk[1], hv[1];
    cfg.http.header_keys = hk;
    cfg.http.header_values = hv;
    cfg.http.header_cap = 1;
    CHECK(decode_cfg(buf, n, &cfg) == C2_ERR_NOMEM);
  }

  /* A wrong value type is malformed, not silently ignored. */
  {
    CborEncoder e, m;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_map(&e, &m, 1) == CborNoError);
    enc_int(&m, C2_KEY_CFG_CC_ADDRESS, 5);
    CHECK(cbor_encoder_close_container(&e, &m) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);
    memset(&cfg, 0, sizeof(cfg));
    CHECK(decode_cfg(buf, n, &cfg) == C2_ERR_PROTO);
  }

  /* A top-level array instead of a map is rejected. */
  {
    CborEncoder e, a;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_array(&e, &a, 0) == CborNoError);
    CHECK(cbor_encoder_close_container(&e, &a) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);
    memset(&cfg, 0, sizeof(cfg));
    CHECK(decode_cfg(buf, n, &cfg) == C2_ERR_PROTO);
  }

  /* NULL arguments. */
  CHECK(c2_agent_config_decode(NULL, &cfg) == C2_ERR_ARG);

  /* c2_config_decrypt is exactly the password AES-GCM container. */
  {
    c2_crypto_backend *be = c2_crypto_open();
    CHECK(be != NULL);
    if (be != NULL) {
      size_t n = build_full_config(buf, sizeof(buf), 19);
      uint8_t enc[4096];
      size_t enc_len = 0;
      c2_str magic = c2_str_lit("test-magic");
      CHECK(c2_aes_gcm_encrypt_password(be, magic, buf, n, enc, sizeof(enc),
                                        &enc_len) == C2_OK);
      uint8_t plain[4096];
      size_t plain_len = 0;
      CHECK(c2_config_decrypt(be, magic, enc, enc_len, plain, sizeof(plain),
                              &plain_len) == C2_OK);
      CHECK_EQ_LONG(plain_len, n);
      CHECK(memcmp(plain, buf, n) == 0);

      /* Wrong magic cannot decrypt. */
      c2_str bad = c2_str_lit("wrong-magic");
      CHECK(c2_config_decrypt(be, bad, enc, enc_len, plain, sizeof(plain),
                              &plain_len) != C2_OK);
      c2_crypto_close(be);
    }
  }

  /* c2_status_str is total and stable for every code. */
  CHECK(c2_str_eq_ci(c2_status_str(C2_OK), "ok"));
  CHECK(c2_str_eq_ci(c2_status_str(C2_ERR_ARG), "invalid argument"));
  CHECK(c2_str_eq_ci(c2_status_str(C2_ERR_NOMEM), "buffer too small"));
  CHECK(c2_str_eq_ci(c2_status_str(C2_ERR_PROTO), "malformed protocol data"));
  CHECK(c2_str_eq_ci(c2_status_str(C2_ERR_CRYPTO), "crypto failure"));
  CHECK(c2_str_eq_ci(c2_status_str(C2_ERR_AUTH), "authentication failure"));
  CHECK(c2_str_eq_ci(c2_status_str(C2_ERR_IO), "io failure"));
  CHECK(c2_str_eq_ci(c2_status_str(C2_ERR_TIMEOUT), "timeout"));
  CHECK(c2_str_eq_ci(c2_status_str(C2_ERR_OVERFLOW), "length out of range"));
  CHECK(c2_str_eq_ci(c2_status_str(C2_ERR_UNSUPPORTED), "unsupported"));
  CHECK(c2_str_eq_ci(c2_status_str((c2_status)-1234), "unknown status"));

  TEST_DONE();
}
