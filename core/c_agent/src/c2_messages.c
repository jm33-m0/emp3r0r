/*
 * c2_messages.c — CBOR codecs for the C2 message schemas.
 *
 * The CBOR layer is Intel's vendored tinycbor (see vendor/tinycbor). Only the
 * two envelopes the agent always needs are implemented here: c2_auth_canonical
 * (the string AgentProof signs) and MsgAuth / MsgTunData. The check-in body,
 * AgentToken and peer list are separate translation units.
 *
 * Decoding is zero-copy: every c2_str/c2_bytes returned by the decoder points
 * into the reader's input buffer. String lists take caller-provided storage
 * (items/cap); a list that does not fit returns C2_ERR_NOMEM.
 */

#include "c2_messages.h"
#include "c2_crypto.h"

#include "strings.h"

/* ------------------------------------------------------------------------- */
/* Bounded string builder for the canonical auth string                      */
/* ------------------------------------------------------------------------- */

typedef struct {
  char *buf;
  size_t cap;
  size_t len;
} c2_sb;

static c2_status sb_put(c2_sb *s, const void *p, size_t n) {
  if (n > s->cap - s->len)
    return C2_ERR_NOMEM;
  if (n)
    memcpy(s->buf + s->len, p, n);
  s->len += n;
  return C2_OK;
}

static c2_status sb_puts(c2_sb *s, c2_str v) {
  if (v.len > 0 && v.ptr == NULL)
    return C2_ERR_ARG;
  return sb_put(s, v.ptr, v.len);
}

static c2_status sb_putc(c2_sb *s, char c) { return sb_put(s, &c, 1); }

static c2_status sb_put_i64(c2_sb *s, int64_t v) {
  char tmp[20];
  size_t n = 0;
  uint64_t mag;
  c2_status st;

  if (v < 0) {
    st = sb_putc(s, '-');
    if (st != C2_OK)
      return st;
    mag = (uint64_t)(-(v + 1)) + 1u; /* avoids overflow on INT64_MIN */
  } else {
    mag = (uint64_t)v;
  }
  do {
    tmp[n++] = (char)('0' + (mag % 10u));
    mag /= 10u;
  } while (mag);
  for (size_t i = 0; i < n / 2; i++) {
    char t = tmp[i];
    tmp[i] = tmp[n - 1 - i];
    tmp[n - 1 - i] = t;
  }
  return sb_put(s, tmp, n);
}

/* Bytewise lexicographic order, matching Go's sort.Strings and ==. */
static int c2_str_cmp(c2_str a, c2_str b) {
  size_t n = a.len < b.len ? a.len : b.len;
  for (size_t i = 0; i < n; i++) {
    unsigned char x = (unsigned char)a.ptr[i];
    unsigned char y = (unsigned char)b.ptr[i];
    if (x != y)
      return x < y ? -1 : 1;
  }
  if (a.len == b.len)
    return 0;
  return a.len < b.len ? -1 : 1;
}

c2_status c2_auth_canonical(c2_str agent_uuid, int64_t timestamp, c2_str nonce,
                            const c2_str_list *caps, char *out, size_t out_cap,
                            size_t *out_len) {
  if (out == NULL || out_cap == 0)
    return C2_ERR_ARG;
  if (agent_uuid.len > 0 && agent_uuid.ptr == NULL)
    return C2_ERR_ARG;
  if (nonce.len > 0 && nonce.ptr == NULL)
    return C2_ERR_ARG;

  size_t count = caps ? caps->count : 0;
  if (count > C2_MAX_CAPABILITIES)
    return C2_ERR_OVERFLOW;

  /* Copy and insertion-sort the capability views; caller storage is untouched. */
  c2_str sorted[C2_MAX_CAPABILITIES];
  for (size_t i = 0; i < count; i++) {
    if (caps->items[i].len > 0 && caps->items[i].ptr == NULL)
      return C2_ERR_ARG;
    sorted[i] = caps->items[i];
  }
  for (size_t i = 1; i < count; i++) {
    c2_str key = sorted[i];
    size_t j = i;
    while (j > 0 && c2_str_cmp(sorted[j - 1], key) > 0) {
      sorted[j] = sorted[j - 1];
      j--;
    }
    sorted[j] = key;
  }

  /* Reserve one byte for the trailing NUL. */
  c2_sb sb = {out, out_cap - 1, 0};
  c2_status st;
  if ((st = sb_puts(&sb, agent_uuid)) != C2_OK)
    return st;
  if ((st = sb_putc(&sb, '\n')) != C2_OK)
    return st;
  if ((st = sb_put_i64(&sb, timestamp)) != C2_OK)
    return st;
  if ((st = sb_putc(&sb, '\n')) != C2_OK)
    return st;
  if ((st = sb_puts(&sb, nonce)) != C2_OK)
    return st;
  if ((st = sb_putc(&sb, '\n')) != C2_OK)
    return st;
  for (size_t i = 0; i < count; i++) {
    if (i) {
      if ((st = sb_putc(&sb, ',')) != C2_OK)
        return st;
    }
    if ((st = sb_puts(&sb, sorted[i])) != C2_OK)
      return st;
  }
  out[sb.len] = '\0';
  if (out_len)
    *out_len = sb.len;
  return C2_OK;
}

/* ------------------------------------------------------------------------- */
/* tinycbor glue                                                              */
/* ------------------------------------------------------------------------- */

static c2_status ec(CborError e) {
  return e == CborNoError ? C2_OK : C2_ERR_NOMEM;
}

/* Decode-side error mapping: any tinycbor error is malformed input. */
static c2_status dc(CborError e) {
  return e == CborNoError ? C2_OK : C2_ERR_PROTO;
}

static c2_status wr_key(CborEncoder *w, uint64_t key) {
  return ec(cbor_encode_uint(w, key));
}

static c2_status wr_text(CborEncoder *w, uint64_t key, c2_str v) {
  c2_status st = wr_key(w, key);
  if (st != C2_OK)
    return st;
  return ec(cbor_encode_text_string(w, v.ptr ? v.ptr : "", v.len));
}

static c2_status wr_bytes(CborEncoder *w, uint64_t key, c2_bytes v) {
  c2_status st = wr_key(w, key);
  if (st != C2_OK)
    return st;
  return ec(cbor_encode_byte_string(
      w, v.ptr ? v.ptr : (const uint8_t *)"", v.len));
}

static c2_status wr_int(CborEncoder *w, uint64_t key, int64_t v) {
  c2_status st = wr_key(w, key);
  if (st != C2_OK)
    return st;
  return ec(cbor_encode_int(w, v));
}

static c2_status wr_str_list(CborEncoder *w, uint64_t key,
                             const c2_str_list *l) {
  c2_status st = wr_key(w, key);
  if (st != C2_OK)
    return st;
  CborEncoder arr;
  st = ec(cbor_encoder_create_array(w, &arr, l->count));
  if (st != C2_OK)
    return st;
  for (size_t i = 0; i < l->count; i++) {
    st = ec(cbor_encode_text_string(&arr,
                                    l->items[i].ptr ? l->items[i].ptr : "",
                                    l->items[i].len));
    if (st != C2_OK)
      return st;
  }
  return ec(cbor_encoder_close_container(w, &arr));
}

/* Zero-copy text/bytes read. tinycbor exposes string contents only through its
 * chunk iterator, so begin the iteration, read the chunk(s), then finish. An
 * indefinite-length (multi-chunk) string is rejected: the C2 never emits one
 * and reassembling chunks would break zero-copy. */
static c2_status rd_text(CborValue *it, c2_str *out) {
  if (!cbor_value_is_text_string(it))
    return C2_ERR_PROTO;
  CborValue cur = *it;
  if (cbor_value_begin_string_iteration(&cur) != CborNoError)
    return C2_ERR_PROTO;

  const char *ptr = NULL;
  size_t len = 0;
  int chunks = 0;
  while (!cbor_value_string_iteration_at_end(&cur)) {
    CborValue next;
    const char *cp = NULL;
    size_t cl = 0;
    if (cbor_value_get_text_string_chunk(&cur, &cp, &cl, &next) != CborNoError) {
      return C2_ERR_PROTO;
    }
    if (chunks == 0) {
      ptr = cp;
      len = cl;
    }
    chunks++;
    cur = next;
  }
  if (cbor_value_finish_string_iteration(&cur) != CborNoError)
    return C2_ERR_PROTO;
  *it = cur;
  if (chunks > 1)
    return C2_ERR_UNSUPPORTED;
  out->ptr = ptr ? ptr : "";
  out->len = len;
  return C2_OK;
}

static c2_status rd_bytes(CborValue *it, c2_bytes *out) {
  if (!cbor_value_is_byte_string(it))
    return C2_ERR_PROTO;
  CborValue cur = *it;
  if (cbor_value_begin_string_iteration(&cur) != CborNoError)
    return C2_ERR_PROTO;

  const uint8_t *ptr = NULL;
  size_t len = 0;
  int chunks = 0;
  while (!cbor_value_string_iteration_at_end(&cur)) {
    CborValue next;
    const uint8_t *cp = NULL;
    size_t cl = 0;
    if (cbor_value_get_byte_string_chunk(&cur, &cp, &cl, &next) != CborNoError) {
      return C2_ERR_PROTO;
    }
    if (chunks == 0) {
      ptr = cp;
      len = cl;
    }
    chunks++;
    cur = next;
  }
  if (cbor_value_finish_string_iteration(&cur) != CborNoError)
    return C2_ERR_PROTO;
  *it = cur;
  if (chunks > 1)
    return C2_ERR_UNSUPPORTED;
  out->ptr = ptr ? ptr : (const uint8_t *)"";
  out->len = len;
  return C2_OK;
}

static c2_status rd_int(CborValue *it, int64_t *v) {
  if (!cbor_value_is_integer(it))
    return C2_ERR_PROTO;
  int64_t tmp;
  if (cbor_value_get_int64_checked(it, &tmp) != CborNoError)
    return C2_ERR_OVERFLOW;
  *v = tmp;
  return dc(cbor_value_advance(it));
}

static c2_status rd_str_list(CborValue *it, c2_str_list *out) {
  if (!cbor_value_is_array(it))
    return C2_ERR_PROTO;
  CborValue arr;
  c2_status st = dc(cbor_value_enter_container(it, &arr));
  if (st != C2_OK)
    return st;
  out->count = 0;
  while (!cbor_value_at_end(&arr)) {
    c2_str s;
    st = rd_text(&arr, &s);
    if (st != C2_OK)
      return st;
    if (out->count >= out->cap)
      return C2_ERR_NOMEM;
    out->items[out->count++] = s;
  }
  return dc(cbor_value_leave_container(it, &arr));
}

/* Enter a map for iteration; the caller must reach cbor_value_at_end before
 * calling leave_container. */
static c2_status map_enter(CborValue *it, CborValue *map) {
  if (!cbor_value_is_map(it))
    return C2_ERR_PROTO;
  return dc(cbor_value_enter_container(it, map));
}

static c2_status map_key(CborValue *map, uint64_t *key, int *done) {
  *done = 0;
  if (cbor_value_at_end(map)) {
    *done = 1;
    return C2_OK;
  }
  if (!cbor_value_is_unsigned_integer(map))
    return C2_ERR_PROTO;
  if (cbor_value_get_uint64(map, key) != CborNoError)
    return C2_ERR_PROTO;
  c2_status st = dc(cbor_value_advance(map));
  if (st != C2_OK)
    return st;
  /* A key must be followed by a value; an odd item ends the map here. */
  if (cbor_value_at_end(map))
    return C2_ERR_PROTO;
  return C2_OK;
}

static c2_status map_skip(CborValue *map) {
  /* cbor_value_advance moves past a tag to its tagged value, not past the
   * whole value, so consume any tag wrappers first. The C2 never emits tags,
   * but hostile input can. */
  if (cbor_value_skip_tag(map) != CborNoError)
    return C2_ERR_PROTO;
  return dc(cbor_value_advance(map));
}

/* ------------------------------------------------------------------------- */
/* MsgAuth                                                                    */
/* ------------------------------------------------------------------------- */

c2_status c2_msgauth_encode(CborEncoder *w, const c2_msgauth *m) {
  if (w == NULL || m == NULL)
    return C2_ERR_ARG;

  size_t pairs = 8;
  if (m->ephem_public_key.len)
    pairs++;
  if (m->stream_id.len)
    pairs++;

  CborEncoder map;
  c2_status st = ec(cbor_encoder_create_map(w, &map, pairs));
  if (st != C2_OK)
    return st;
  if ((st = wr_text(&map, C2_KEY_AUTH_TYPE, m->type)) != C2_OK)
    return st;
  if ((st = wr_text(&map, C2_KEY_AUTH_AGENT_UUID, m->agent_uuid)) != C2_OK)
    return st;
  if ((st = wr_text(&map, C2_KEY_AUTH_IDENTITY_TOKEN, m->identity_token)) !=
      C2_OK)
    return st;
  if ((st = wr_int(&map, C2_KEY_AUTH_TIMESTAMP, m->timestamp)) != C2_OK)
    return st;
  if ((st = wr_text(&map, C2_KEY_AUTH_NONCE, m->nonce)) != C2_OK)
    return st;
  if ((st = wr_str_list(&map, C2_KEY_AUTH_CAPABILITIES, &m->capabilities)) !=
      C2_OK)
    return st;
  if ((st = wr_text(&map, C2_KEY_AUTH_AGENT_PROOF, m->agent_proof)) != C2_OK)
    return st;
  if (m->ephem_public_key.len &&
      (st = wr_bytes(&map, C2_KEY_AUTH_EPHEM_PUBLIC, m->ephem_public_key)) !=
          C2_OK)
    return st;
  if (m->stream_id.len &&
      (st = wr_text(&map, C2_KEY_AUTH_STREAM_ID, m->stream_id)) != C2_OK)
    return st;
  if ((st = wr_int(&map, C2_KEY_AUTH_PROTOCOL_VERSION, m->protocol_version)) !=
      C2_OK)
    return st;
  return ec(cbor_encoder_close_container(w, &map));
}

c2_status c2_msgauth_decode(CborValue *r, c2_msgauth *m) {
  if (r == NULL || m == NULL)
    return C2_ERR_ARG;

  CborValue map;
  c2_status st = map_enter(r, &map);
  if (st != C2_OK)
    return st;

  int done;
  uint64_t key;
  while ((st = map_key(&map, &key, &done)) == C2_OK && !done) {
    switch (key) {
    case C2_KEY_AUTH_TYPE:
      st = rd_text(&map, &m->type);
      break;
    case C2_KEY_AUTH_AGENT_UUID:
      st = rd_text(&map, &m->agent_uuid);
      break;
    case C2_KEY_AUTH_IDENTITY_TOKEN:
      st = rd_text(&map, &m->identity_token);
      break;
    case C2_KEY_AUTH_TIMESTAMP:
      st = rd_int(&map, &m->timestamp);
      break;
    case C2_KEY_AUTH_NONCE:
      st = rd_text(&map, &m->nonce);
      break;
    case C2_KEY_AUTH_CAPABILITIES:
      st = rd_str_list(&map, &m->capabilities);
      break;
    case C2_KEY_AUTH_AGENT_PROOF:
      st = rd_text(&map, &m->agent_proof);
      break;
    case C2_KEY_AUTH_EPHEM_PUBLIC:
      st = rd_bytes(&map, &m->ephem_public_key);
      break;
    case C2_KEY_AUTH_STREAM_ID:
      st = rd_text(&map, &m->stream_id);
      break;
    case C2_KEY_AUTH_PROTOCOL_VERSION:
      st = rd_int(&map, &m->protocol_version);
      break;
    default:
      st = map_skip(&map);
      break;
    }
    if (st != C2_OK)
      return st;
  }
  if (st != C2_OK)
    return st;
  return dc(cbor_value_leave_container(r, &map));
}

/* ------------------------------------------------------------------------- */
/* MsgTunData                                                                 */
/* ------------------------------------------------------------------------- */

c2_status c2_msgtun_encode(CborEncoder *w, const c2_msgtun *m) {
  if (w == NULL || m == NULL)
    return C2_ERR_ARG;
  if (m->enriched_peer_list)
    return C2_ERR_UNSUPPORTED; /* encoded by the peer-list codec */

  size_t pairs = 0;
  if (m->job_id.len)
    pairs++;
  if (m->cmd_slice.count)
    pairs++;
  if (m->response.len)
    pairs++;
  if (m->tag.len)
    pairs++;
  if (m->time.len)
    pairs++;
  if (m->agent_uuid.len)
    pairs++;
  if (m->agent_uuid_sig.len)
    pairs++;
  if (m->ephem_public_key.len)
    pairs++;
  if (m->peer_list.count)
    pairs++;

  CborEncoder map;
  c2_status st = ec(cbor_encoder_create_map(w, &map, pairs));
  if (st != C2_OK)
    return st;
  if (m->job_id.len &&
      (st = wr_text(&map, C2_KEY_TUN_JOB_ID, m->job_id)) != C2_OK)
    return st;
  if (m->cmd_slice.count &&
      (st = wr_str_list(&map, C2_KEY_TUN_CMD_SLICE, &m->cmd_slice)) != C2_OK)
    return st;
  if (m->response.len &&
      (st = wr_bytes(&map, C2_KEY_TUN_RESPONSE, m->response)) != C2_OK)
    return st;
  if (m->tag.len && (st = wr_text(&map, C2_KEY_TUN_TAG, m->tag)) != C2_OK)
    return st;
  if (m->time.len && (st = wr_text(&map, C2_KEY_TUN_TIME, m->time)) != C2_OK)
    return st;
  if (m->agent_uuid.len &&
      (st = wr_text(&map, C2_KEY_TUN_AGENT_UUID, m->agent_uuid)) != C2_OK)
    return st;
  if (m->agent_uuid_sig.len &&
      (st = wr_text(&map, C2_KEY_TUN_AGENT_UUID_SIG, m->agent_uuid_sig)) !=
          C2_OK)
    return st;
  if (m->ephem_public_key.len &&
      (st = wr_bytes(&map, C2_KEY_TUN_EPHEM_PUBLIC, m->ephem_public_key)) !=
          C2_OK)
    return st;
  if (m->peer_list.count &&
      (st = wr_str_list(&map, C2_KEY_TUN_PEER_LIST, &m->peer_list)) != C2_OK)
    return st;
  return ec(cbor_encoder_close_container(w, &map));
}

c2_status c2_msgtun_decode(CborValue *r, c2_msgtun *m) {
  if (r == NULL || m == NULL)
    return C2_ERR_ARG;

  if (m->enriched_peer_list)
    m->enriched_peer_list->count = 0;

  CborValue map;
  c2_status st = map_enter(r, &map);
  if (st != C2_OK)
    return st;

  int done;
  uint64_t key;
  while ((st = map_key(&map, &key, &done)) == C2_OK && !done) {
    switch (key) {
    case C2_KEY_TUN_JOB_ID:
      st = rd_text(&map, &m->job_id);
      break;
    case C2_KEY_TUN_CMD_SLICE:
      st = rd_str_list(&map, &m->cmd_slice);
      break;
    case C2_KEY_TUN_RESPONSE:
      st = rd_bytes(&map, &m->response);
      break;
    case C2_KEY_TUN_TAG:
      st = rd_text(&map, &m->tag);
      break;
    case C2_KEY_TUN_TIME:
      st = rd_text(&map, &m->time);
      break;
    case C2_KEY_TUN_AGENT_UUID:
      st = rd_text(&map, &m->agent_uuid);
      break;
    case C2_KEY_TUN_AGENT_UUID_SIG:
      st = rd_text(&map, &m->agent_uuid_sig);
      break;
    case C2_KEY_TUN_EPHEM_PUBLIC:
      st = rd_bytes(&map, &m->ephem_public_key);
      break;
    case C2_KEY_TUN_PEER_LIST:
      st = rd_str_list(&map, &m->peer_list);
      break;
    default:
      st = map_skip(&map);
      break;
    }
    if (st != C2_OK)
      return st;
  }
  if (st != C2_OK)
    return st;
  return dc(cbor_value_leave_container(r, &map));
}

/* ------------------------------------------------------------------------- */
/* Identity signature helper                                                  */
/* ------------------------------------------------------------------------- */

c2_status c2_sign_uuid_base64(const c2_crypto_backend *be,
                              const uint8_t priv[C2_P256_PRIV_BYTES],
                              c2_str uuid, char *out, size_t out_cap,
                              size_t *out_len) {
  if (be == NULL || be->ecdsa_p256_sign_der == NULL || priv == NULL ||
      out == NULL)
    return C2_ERR_ARG;

  uint8_t sig[80];
  size_t sig_len = 0;
  int rc = be->ecdsa_p256_sign_der(be->ctx, priv, (const uint8_t *)uuid.ptr,
                                   uuid.len, sig, sizeof(sig), &sig_len);
  if (rc != 0)
    return C2_ERR_CRYPTO;

  size_t n = c2_base64url_encode(sig, sig_len, out, out_cap);
  if (n == 0)
    return C2_ERR_NOMEM;
  if (out_len)
    *out_len = n;
  return C2_OK;
}
