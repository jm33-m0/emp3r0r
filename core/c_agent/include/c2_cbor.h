#ifndef C2_CBOR_H
#define C2_CBOR_H

/*
 * c2_cbor.h — minimal, bounded CBOR (RFC 8949) reader/writer contract.
 *
 * The C2 encodes every message as a CBOR map with integer keys (Go keyasint).
 * Maps and arrays are definite-length; integers use their shortest form. A
 * conforming decoder accepts any valid ordering and both definite and
 * indefinite lengths, and MUST NOT recurse without a depth bound (hostile
 * input).
 *
 * This header defines the generic codec interface and the small concrete
 * helpers the message codecs need. The implementation lives in the agent (or
 * a shared library); it is deliberately not tied to one CBOR package so a
 * freestanding agent can vendor a tiny one.
 *
 * Reader semantics:
 *   - text/bytes reads are zero-copy slices pointing into the reader buffer;
 *     they stay valid as long as the buffer does.
 *   - every read validates lengths against the remaining buffer and returns
 *     C2_ERR_PROTO on malformed input; none of them can over-read.
 */

#include "c2_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CBOR major types. */
enum {
  C2_CBOR_MAJOR_UINT = 0,
  C2_CBOR_MAJOR_NEGINT = 1,
  C2_CBOR_MAJOR_BYTES = 2,
  C2_CBOR_MAJOR_TEXT = 3,
  C2_CBOR_MAJOR_ARRAY = 4,
  C2_CBOR_MAJOR_MAP = 5,
  C2_CBOR_MAJOR_TAG = 6,
  C2_CBOR_MAJOR_SIMPLE = 7,
};

/* Additional-information values. */
#define C2_CBOR_AI_INDEFINITE 31u
#define C2_CBOR_BREAK 0xffu

/* Returned in a count when the map/array uses indefinite length. */
#define C2_CBOR_INDEFINITE ((size_t)-1)

/* Maximum nesting depth c2_cbor_skip may descend into. */
#define C2_CBOR_MAX_DEPTH 16u

typedef struct {
  const uint8_t *buf;
  size_t len;
  size_t pos;
} c2_cbor_reader;

typedef struct {
  uint8_t *buf;
  size_t cap;
  size_t len;
} c2_cbor_writer;

/* ---- reader -------------------------------------------------------------- */

void c2_cbor_reader_init(c2_cbor_reader *r, const void *buf, size_t len);

/* Bytes still unread. */
static inline size_t c2_cbor_reader_remaining(const c2_cbor_reader *r) {
  return r->len - r->pos;
}

/* Reads an unsigned integer (major 0). */
c2_status c2_cbor_read_uint(c2_cbor_reader *r, uint64_t *v);

/* Reads a signed integer (major 0 or 1). */
c2_status c2_cbor_read_int(c2_cbor_reader *r, int64_t *v);

/* Reads a map/array header. *count is C2_CBOR_INDEFINITE for indefinite form. */
c2_status c2_cbor_read_map(c2_cbor_reader *r, size_t *pairs);
c2_status c2_cbor_read_array(c2_cbor_reader *r, size_t *items);

/* Zero-copy text/bytes read. */
c2_status c2_cbor_read_text(c2_cbor_reader *r, c2_str *out);
c2_status c2_cbor_read_bytes(c2_cbor_reader *r, c2_bytes *out);

/* Booleans and null (CBOR simple values). */
c2_status c2_cbor_read_bool(c2_cbor_reader *r, int *v);
c2_status c2_cbor_read_null(c2_cbor_reader *r);

/* Skip exactly one data item (recursively for composites, depth-bounded). */
c2_status c2_cbor_skip(c2_cbor_reader *r);

/* Peek the next item's major type without consuming it. */
c2_status c2_cbor_peek_major(const c2_cbor_reader *r, uint8_t *major);

/* True when the next byte is a CBOR break (0xff). */
static inline int c2_cbor_at_break(const c2_cbor_reader *r) {
  return r->pos < r->len && r->buf[r->pos] == C2_CBOR_BREAK;
}

/* Consume a break byte. */
c2_status c2_cbor_consume_break(c2_cbor_reader *r);

/* ---- writer -------------------------------------------------------------- */

void c2_cbor_writer_init(c2_cbor_writer *w, void *buf, size_t cap);

static inline size_t c2_cbor_writer_len(const c2_cbor_writer *w) {
  return w->len;
}

c2_status c2_cbor_write_map(c2_cbor_writer *w, size_t pairs);
c2_status c2_cbor_write_array(c2_cbor_writer *w, size_t items);
c2_status c2_cbor_write_uint(c2_cbor_writer *w, uint64_t v);
c2_status c2_cbor_write_int(c2_cbor_writer *w, int64_t v);
c2_status c2_cbor_write_text(c2_cbor_writer *w, c2_str s);
c2_status c2_cbor_write_bytes(c2_cbor_writer *w, c2_bytes b);
c2_status c2_cbor_write_bool(c2_cbor_writer *w, int v);
c2_status c2_cbor_write_null(c2_cbor_writer *w);

#ifdef __cplusplus
}
#endif

#endif /* C2_CBOR_H */
