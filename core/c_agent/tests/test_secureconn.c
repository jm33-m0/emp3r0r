#include "secureconn.h"

#include "stub_crypto.h"
#include "test.h"

#include <stdlib.h>

/* ------------------------------------------------------------------------- */
/* In-memory byte stream                                                      */
/* ------------------------------------------------------------------------- */

typedef struct {
  uint8_t buf[65536];
  size_t len;
  size_t rpos;
} memstream;

static long ms_read(void *ctx, uint8_t *buf, size_t cap) {
  memstream *m = (memstream *)ctx;
  size_t avail = m->len - m->rpos;
  size_t n = cap < avail ? cap : avail;
  memcpy(buf, m->buf + m->rpos, n);
  m->rpos += n;
  return (long)n;
}

static long ms_write(void *ctx, const uint8_t *buf, size_t len) {
  memstream *m = (memstream *)ctx;
  if (len > sizeof(m->buf) - m->len)
    return -1;
  memcpy(m->buf + m->len, buf, len);
  m->len += len;
  return (long)len;
}

static void ms_close(void *ctx) {
  (void)ctx;
}

static const c2_stream_ops g_ms_ops = {ms_read, ms_write, ms_close};

/* A polling stream that reports C2_STREAM_IDLE before it yields the bytes the
 * peer wrote, modelling an http_poll long-poll cycle with no data. */
typedef struct {
  memstream inner;
  int idle_left;
} idlestream;

static long ids_read(void *ctx, uint8_t *buf, size_t cap) {
  idlestream *s = (idlestream *)ctx;
  if (s->idle_left > 0) {
    s->idle_left--;
    return C2_STREAM_IDLE;
  }
  return ms_read(&s->inner, buf, cap);
}

static long ids_write(void *ctx, const uint8_t *buf, size_t len) {
  return ms_write(&((idlestream *)ctx)->inner, buf, len);
}

static void ids_close(void *ctx) {
  (void)ctx;
}

static const c2_stream_ops g_ids_ops = {ids_read, ids_write, ids_close};

int main(void) {
  uint32_t rng = 1;
  c2_crypto_backend be;
  stub_crypto_init(&be, &rng);

  uint8_t key[C2_AES_KEY_BYTES];
  for (size_t i = 0; i < sizeof(key); i++)
    key[i] = (uint8_t)i;

  /* Direct frame round-trip. */
  {
    c2_secureconn enc = {0}, dec = {0};
    c2_secureconn_init(&enc, &be, (c2_stream){0}, key);
    c2_secureconn_init(&dec, &be, (c2_stream){0}, key);

    uint8_t frame[256];
    size_t frame_len = 0;
    const char *msg = "hello secureconn";
    CHECK(c2_secureconn_encode_frame(&enc, (const uint8_t *)msg, strlen(msg), 0,
                                     frame, sizeof(frame),
                                     &frame_len) == C2_OK);
    CHECK(frame_len > strlen(msg));

    uint8_t plain[256];
    uint8_t *payload = NULL;
    size_t plen = 0;
    CHECK(c2_secureconn_decode_frame(&dec, frame + 4, frame_len - 4, plain,
                                     sizeof(plain), &payload, &plen) == C2_OK);
    CHECK_EQ_LONG(plen, strlen(msg));
    CHECK(memcmp(payload, msg, plen) == 0);
  }

  /* Padding is appended but stripped on decode. */
  {
    c2_secureconn enc = {0}, dec = {0};
    c2_secureconn_init(&enc, &be, (c2_stream){0}, key);
    c2_secureconn_init(&dec, &be, (c2_stream){0}, key);
    uint8_t frame[256];
    size_t frame_len = 0;
    CHECK(c2_secureconn_encode_frame(&enc, (const uint8_t *)"x", 1, 100, frame,
                                     sizeof(frame), &frame_len) == C2_OK);
    uint8_t plain[256];
    uint8_t *payload = NULL;
    size_t plen = 0;
    CHECK(c2_secureconn_decode_frame(&dec, frame + 4, frame_len - 4, plain,
                                     sizeof(plain), &payload, &plen) == C2_OK);
    CHECK_EQ_LONG(plen, 1);
    CHECK(payload[0] == 'x');
  }

  /* Full write/read over the stream, with a destination smaller than the
   * payload so the reassembly buffer is exercised. */
  {
    memstream ms = {0};
    c2_secureconn enc = {0}, dec = {0};
    c2_secureconn_init(&enc, &be, (c2_stream){&g_ms_ops, &ms}, key);
    c2_secureconn_init(&dec, &be, (c2_stream){&g_ms_ops, &ms}, key);
    c2_secureconn_set_padding(&enc, 1, 16);

    uint8_t big[100];
    for (size_t i = 0; i < sizeof(big); i++)
      big[i] = (uint8_t)(i + 1);
    CHECK(c2_secureconn_write(&enc, big, sizeof(big)) == C2_OK);
    CHECK(c2_secureconn_write(&enc, (const uint8_t *)"tail", 4) == C2_OK);

    uint8_t out[8];
    CHECK_EQ_LONG(c2_secureconn_read(&dec, out, sizeof(out)), sizeof(out));
    CHECK(memcmp(out, big, sizeof(out)) == 0);
    for (size_t got = sizeof(out); got < sizeof(big); got += sizeof(out)) {
      long n = c2_secureconn_read(&dec, out, sizeof(out));
      CHECK(n > 0);
      CHECK(memcmp(out, big + got, (size_t)n) == 0);
    }
    CHECK_EQ_LONG(c2_secureconn_read(&dec, out, sizeof(out)), 4);
    CHECK(memcmp(out, "tail", 4) == 0);
    CHECK_EQ_LONG(c2_secureconn_read(&dec, out, sizeof(out)), 0); /* EOF */
    c2_secureconn_close(&dec);
  }

  /* Normal writes are padded regardless of payload size; bulk writes opt out. */
  {
    memstream ms = {0};
    c2_secureconn enc = {0};
    c2_secureconn_init(&enc, &be, (c2_stream){&g_ms_ops, &ms}, key);
    c2_secureconn_set_padding(&enc, 7, 7);

    uint8_t big[40 * 1024] = {0};
    CHECK(c2_secureconn_write(&enc, big, sizeof(big)) == C2_OK);
    size_t padded_len = ms.len;
    ms.len = 0;
    ms.rpos = 0;
    CHECK(c2_secureconn_write_bulk(&enc, big, sizeof(big)) == C2_OK);
    CHECK_EQ_LONG(padded_len - ms.len, 7);
  }

  /* Empty control frames are skipped, not returned as EOF. */
  {
    memstream ms = {0};
    c2_secureconn enc = {0}, dec = {0};
    c2_secureconn_init(&enc, &be, (c2_stream){&g_ms_ops, &ms}, key);
    c2_secureconn_init(&dec, &be, (c2_stream){&g_ms_ops, &ms}, key);
    CHECK(c2_secureconn_write(&enc, NULL, 0) == C2_OK); /* payload_len == 0 */
    CHECK(c2_secureconn_write(&enc, (const uint8_t *)"after", 5) == C2_OK);
    uint8_t out[8];
    CHECK_EQ_LONG(c2_secureconn_read(&dec, out, sizeof(out)), 5);
    CHECK(memcmp(out, "after", 5) == 0);
    c2_secureconn_close(&dec);
  }

  /* Wrong key fails authentication. */
  {
    c2_secureconn enc = {0}, dec = {0};
    uint8_t wrong[C2_AES_KEY_BYTES];
    memcpy(wrong, key, sizeof(key));
    wrong[0] ^= 0xff;
    c2_secureconn_init(&enc, &be, (c2_stream){0}, key);
    c2_secureconn_init(&dec, &be, (c2_stream){0}, wrong);
    uint8_t frame[64];
    size_t frame_len = 0;
    CHECK(c2_secureconn_encode_frame(&enc, (const uint8_t *)"m", 1, 0, frame,
                                     sizeof(frame), &frame_len) == C2_OK);
    uint8_t plain[64];
    uint8_t *payload = NULL;
    size_t plen = 0;
    CHECK_EQ_LONG(c2_secureconn_decode_frame(&dec, frame + 4, frame_len - 4,
                                             plain, sizeof(plain), &payload,
                                             &plen),
                  C2_ERR_CRYPTO);
  }

  /* Key switch: re-init the decoder with the sender's key succeeds. */
  {
    c2_secureconn enc = {0}, dec = {0};
    c2_secureconn_init(&enc, &be, (c2_stream){0}, key);
    c2_secureconn_init(&dec, &be, (c2_stream){0}, key);
    uint8_t frame[64];
    size_t frame_len = 0;
    CHECK(c2_secureconn_encode_frame(&enc, (const uint8_t *)"z", 1, 0, frame,
                                     sizeof(frame), &frame_len) == C2_OK);
    c2_secureconn_set_key(&dec, key);
    uint8_t plain[64];
    size_t plen = 0;
    CHECK(c2_secureconn_decode_frame(&dec, frame + 4, frame_len - 4, plain,
                                     sizeof(plain), NULL, &plen) == C2_OK);
    CHECK_EQ_LONG(plen, 1);
  }

  /* Oversized and truncated frames are rejected. */
  {
    memstream ms = {0};
    c2_secureconn dec = {0};
    c2_secureconn_init(&dec, &be, (c2_stream){&g_ms_ops, &ms}, key);

    ms.buf[0] = 0xff;
    ms.buf[1] = 0xff;
    ms.buf[2] = 0xff;
    ms.buf[3] = 0xff;
    ms.len = 4;
    ms.rpos = 0;
    uint8_t out[8];
    CHECK_EQ_LONG(c2_secureconn_read(&dec, out, sizeof(out)), C2_ERR_PROTO);

    /* A valid length prefix followed by too few bytes is a protocol error. */
    ms.len = 4;
    ms.rpos = 0;
    ms.buf[0] = 0;
    ms.buf[1] = 0;
    ms.buf[2] = 0;
    ms.buf[3] = 40;
    ms.len = 4 + 10; /* claims 40, provides 10 */
    CHECK_EQ_LONG(c2_secureconn_read(&dec, out, sizeof(out)), C2_ERR_PROTO);
    c2_secureconn_close(&dec);
  }

  /* An idle long-poll must surface as C2_ERR_TIMEOUT (not data, not EOF), so
   * the agent can send a keepalive and keep polling; the next read returns the
   * frame once the peer's bytes arrive. */
  {
    c2_secureconn enc = {0}, dec = {0};
    static idlestream s;
    memset(&s, 0, sizeof(s));
    s.idle_left = 2;
    c2_secureconn_init(&enc, &be, (c2_stream){&g_ids_ops, &s}, key);
    c2_secureconn_init(&dec, &be, (c2_stream){&g_ids_ops, &s}, key);

    const char *msg = "after idle";
    CHECK(c2_secureconn_write(&enc, (const uint8_t *)msg, strlen(msg)) ==
          C2_OK);

    uint8_t out[64];
    size_t outlen = 0;
    int eof = 0;
    CHECK_EQ_LONG(c2_secureconn_read_msg(&dec, out, sizeof(out), &outlen, &eof),
                  C2_ERR_TIMEOUT);
    CHECK_EQ_LONG(c2_secureconn_read_msg(&dec, out, sizeof(out), &outlen, &eof),
                  C2_ERR_TIMEOUT);
    CHECK_EQ_LONG(c2_secureconn_read_msg(&dec, out, sizeof(out), &outlen, &eof),
                  C2_OK);
    CHECK_EQ_LONG(outlen, strlen(msg));
    CHECK(memcmp(out, msg, outlen) == 0);
    c2_secureconn_close(&enc);
    c2_secureconn_close(&dec);
  }

  /* A streaming read (file downloads) must not surface idle as an error: the
   * operator may take a while to serve the file, so read() keeps polling. */
  {
    c2_secureconn enc = {0}, dec = {0};
    static idlestream s;
    memset(&s, 0, sizeof(s));
    s.idle_left = 3;
    c2_secureconn_init(&enc, &be, (c2_stream){&g_ids_ops, &s}, key);
    c2_secureconn_init(&dec, &be, (c2_stream){&g_ids_ops, &s}, key);

    const char *msg = "download body";
    CHECK(c2_secureconn_write(&enc, (const uint8_t *)msg, strlen(msg)) ==
          C2_OK);

    uint8_t out[64];
    CHECK_EQ_LONG(c2_secureconn_read(&dec, out, sizeof(out)),
                  (long)strlen(msg));
    CHECK(memcmp(out, msg, strlen(msg)) == 0);
    c2_secureconn_close(&enc);
    c2_secureconn_close(&dec);
  }

  TEST_DONE();
}
