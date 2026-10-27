#ifndef C2_CBOR_UTIL_H
#define C2_CBOR_UTIL_H

/*
 * cbor_util.h — internal tinycbor glue shared by every message codec.
 *
 * These helpers are `static inline` so each translation unit gets its own copy
 * (there is no extra object file to link) while still sharing one definition.
 * They are not part of the public protocol surface: only translation units
 * under src are expected to include this.
 *
 * The codecs are zero-copy on decode: every c2_str/c2_bytes points into the
 * reader's input buffer and stays valid only while that buffer lives. String
 * lists borrow caller storage (items/cap). Nothing here allocates.
 */

#include "common.h"
#include "messages.h"

#include "cbor.h"

#include <string.h>

/* Encode-side error mapping: exhaustion of the output buffer is C2_ERR_NOMEM. */
static inline c2_status c2_cbor_ec(CborError e) {
  return e == CborNoError ? C2_OK : C2_ERR_NOMEM;
}

/* Decode-side error mapping: any tinycbor error is malformed input. */
static inline c2_status c2_cbor_dc(CborError e) {
  return e == CborNoError ? C2_OK : C2_ERR_PROTO;
}

static inline c2_status c2_cbor_write_key(CborEncoder *w, uint64_t key) {
  return c2_cbor_ec(cbor_encode_uint(w, key));
}

static inline c2_status c2_cbor_write_text(CborEncoder *w, uint64_t key,
                                           c2_str v) {
  c2_status st = c2_cbor_write_key(w, key);
  if (st != C2_OK)
    return st;
  return c2_cbor_ec(cbor_encode_text_string(w, v.ptr ? v.ptr : "", v.len));
}

static inline c2_status c2_cbor_write_bytes(CborEncoder *w, uint64_t key,
                                            c2_bytes v) {
  c2_status st = c2_cbor_write_key(w, key);
  if (st != C2_OK)
    return st;
  return c2_cbor_ec(
      cbor_encode_byte_string(w, v.ptr ? v.ptr : (const uint8_t *)"", v.len));
}

static inline c2_status c2_cbor_write_int(CborEncoder *w, uint64_t key,
                                          int64_t v) {
  c2_status st = c2_cbor_write_key(w, key);
  if (st != C2_OK)
    return st;
  return c2_cbor_ec(cbor_encode_int(w, v));
}

static inline c2_status c2_cbor_write_bool(CborEncoder *w, uint64_t key,
                                           int v) {
  c2_status st = c2_cbor_write_key(w, key);
  if (st != C2_OK)
    return st;
  return c2_cbor_ec(cbor_encode_boolean(w, v != 0));
}

/* Encode a definite-length array of text strings under `key`. */
static inline c2_status c2_cbor_write_str_list(CborEncoder *w, uint64_t key,
                                               const c2_str_list *l) {
  c2_status st = c2_cbor_write_key(w, key);
  if (st != C2_OK)
    return st;
  CborEncoder arr;
  st = c2_cbor_ec(cbor_encoder_create_array(w, &arr, l->count));
  if (st != C2_OK)
    return st;
  for (size_t i = 0; i < l->count; i++) {
    st = c2_cbor_ec(cbor_encode_text_string(
        &arr, l->items[i].ptr ? l->items[i].ptr : "", l->items[i].len));
    if (st != C2_OK)
      return st;
  }
  return c2_cbor_ec(cbor_encoder_close_container(w, &arr));
}

/*
 * Zero-copy text read. tinycbor exposes string contents only through its chunk
 * iterator, so begin the iteration, read the chunk(s), then finish. An
 * indefinite-length (multi-chunk) string is rejected: the C2 never emits one
 * and reassembling chunks would break zero-copy.
 */
static inline c2_status c2_cbor_read_text(CborValue *it, c2_str *out) {
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
    if (cbor_value_get_text_string_chunk(&cur, &cp, &cl, &next) !=
        CborNoError) {
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

static inline c2_status c2_cbor_read_bytes(CborValue *it, c2_bytes *out) {
  /* Go encodes a nil []byte as CBOR null; treat it as an empty slice. */
  if (cbor_value_is_null(it)) {
    out->ptr = NULL;
    out->len = 0;
    return c2_cbor_dc(cbor_value_advance(it));
  }
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
    if (cbor_value_get_byte_string_chunk(&cur, &cp, &cl, &next) !=
        CborNoError) {
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

static inline c2_status c2_cbor_read_int(CborValue *it, int64_t *v) {
  if (!cbor_value_is_integer(it))
    return C2_ERR_PROTO;
  int64_t tmp;
  if (cbor_value_get_int64_checked(it, &tmp) != CborNoError)
    return C2_ERR_OVERFLOW;
  *v = tmp;
  return c2_cbor_dc(cbor_value_advance(it));
}

/* Decode a CBOR bool into *v (0/1). Integers are not accepted: the C2 always
 * emits a real boolean, and treating 0/1 as a bool hides wire bugs. */
static inline c2_status c2_cbor_read_bool(CborValue *it, int *v) {
  if (!cbor_value_is_boolean(it))
    return C2_ERR_PROTO;
  bool b = false;
  if (cbor_value_get_boolean(it, &b) != CborNoError)
    return C2_ERR_PROTO;
  *v = b ? 1 : 0;
  return c2_cbor_dc(cbor_value_advance(it));
}

static inline c2_status c2_cbor_read_str_list(CborValue *it, c2_str_list *out) {
  /* Go encodes a nil slice as CBOR null; treat it as an empty list. */
  if (cbor_value_is_null(it)) {
    out->count = 0;
    return c2_cbor_dc(cbor_value_advance(it));
  }
  if (!cbor_value_is_array(it))
    return C2_ERR_PROTO;
  CborValue arr;
  c2_status st = c2_cbor_dc(cbor_value_enter_container(it, &arr));
  if (st != C2_OK)
    return st;
  out->count = 0;
  while (!cbor_value_at_end(&arr)) {
    c2_str s;
    st = c2_cbor_read_text(&arr, &s);
    if (st != C2_OK)
      return st;
    if (out->count >= out->cap)
      return C2_ERR_NOMEM;
    out->items[out->count++] = s;
  }
  return c2_cbor_dc(cbor_value_leave_container(it, &arr));
}

/* Enter a map for iteration; the caller must reach cbor_value_at_end before
 * calling leave_container. */
static inline c2_status c2_cbor_map_enter(CborValue *it, CborValue *map) {
  if (!cbor_value_is_map(it))
    return C2_ERR_PROTO;
  return c2_cbor_dc(cbor_value_enter_container(it, map));
}

static inline c2_status c2_cbor_map_key(CborValue *map, uint64_t *key,
                                        int *done) {
  *done = 0;
  if (cbor_value_at_end(map)) {
    *done = 1;
    return C2_OK;
  }
  if (!cbor_value_is_unsigned_integer(map))
    return C2_ERR_PROTO;
  if (cbor_value_get_uint64(map, key) != CborNoError)
    return C2_ERR_PROTO;
  c2_status st = c2_cbor_dc(cbor_value_advance(map));
  if (st != C2_OK)
    return st;
  /* A key must be followed by a value; an odd item ends the map here. */
  if (cbor_value_at_end(map))
    return C2_ERR_PROTO;
  return C2_OK;
}

/* Skip a key's value, including any tag wrappers tinycbor would otherwise step
 * over one level at a time. Hostile input may wrap a value in a tag. */
static inline c2_status c2_cbor_map_skip(CborValue *map) {
  if (cbor_value_skip_tag(map) != CborNoError)
    return C2_ERR_PROTO;
  return c2_cbor_dc(cbor_value_advance(map));
}

/*
 * Switch-case helpers for the message codecs. Every decoder is the same shape:
 * a `while (c2_cbor_map_key)` loop with a `switch (key)` whose cases read one
 * field. These collapse each case into one line. They expand to a case label,
 * so they must be used inside the switch and rely on `map` and `st` being the
 * iterator and status variable of the enclosing loop (the same convention the
 * encoder's PUT_ and COUNT_ macros use).
 */
#define C2_CASE_TEXT(k, obj, f)                                                \
  case (k):                                                                    \
    st = c2_cbor_read_text(&map, &(obj)->f);                                   \
    break
#define C2_CASE_BYTES(k, obj, f)                                               \
  case (k):                                                                    \
    st = c2_cbor_read_bytes(&map, &(obj)->f);                                  \
    break
#define C2_CASE_INT(k, obj, f)                                                 \
  case (k):                                                                    \
    st = c2_cbor_read_int(&map, &(obj)->f);                                    \
    break
#define C2_CASE_STR_LIST(k, obj, f)                                            \
  case (k):                                                                    \
    st = c2_cbor_read_str_list(&map, &(obj)->f);                               \
    break
/* `hasf` is set to whether the bool was present, mirroring the Go pointer. */
#define C2_CASE_BOOL(k, obj, f, hasf)                                          \
  case (k):                                                                    \
    st = c2_cbor_read_bool(&map, &(obj)->f);                                   \
    (obj)->hasf = (st == C2_OK);                                               \
    break
#define C2_CASE_INT_HAS(k, obj, f, hasf)                                       \
  case (k):                                                                    \
    st = c2_cbor_read_int(&map, &(obj)->f);                                    \
    (obj)->hasf = (st == C2_OK);                                               \
    break
/* Decode an integer that is stored in a 32-bit field (config knobs). */
#define C2_CASE_INT32(k, obj, f)                                               \
  case (k): {                                                                  \
    int64_t v_;                                                                \
    if ((st = c2_cbor_read_int(&map, &v_)) == C2_OK)                           \
      (obj)->f = (int32_t)v_;                                                  \
    break;                                                                     \
  }

#endif /* C2_CBOR_UTIL_H */
