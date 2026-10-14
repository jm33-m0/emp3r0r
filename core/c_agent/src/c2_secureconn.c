/*
 * c2_secureconn.c — SecureConn framing and encryption.
 *
 * The frame layout is documented in c2_secureconn.h. The codec is stateless
 * apart from the key and the reassembly buffer; every frame is encoded into a
 * temporary buffer and written in one piece.
 *
 * Allocation: the hosted agent links malloc/realloc/free. Frame buffers are
 * transient; the reassembly buffer is only allocated when a read destination is
 * smaller than a single frame's payload, and is freed by
 * c2_secureconn_close when the codec owns it.
 */

#include "c2_secureconn.h"

#include "strings.h"

#include <stdlib.h>

/* Read exactly len bytes. *clean_eof is set only when the stream ended before
 * any byte of this read; a partial read is an error. */
static c2_status read_exact(c2_stream *s, uint8_t *buf, size_t len,
                            int *clean_eof) {
  if (clean_eof)
    *clean_eof = 0;
  size_t off = 0;
  while (off < len) {
    long n = s->ops->read(s->ctx, buf + off, len - off);
    if (n < 0)
      return C2_ERR_IO;
    if (n == 0) {
      if (off == 0) {
        if (clean_eof)
          *clean_eof = 1;
        return C2_OK;
      }
      /* EOF in the middle of a frame: the peer truncated it. */
      return C2_ERR_PROTO;
    }
    off += (size_t)n;
  }
  return C2_OK;
}

static c2_status write_all(c2_stream *s, const uint8_t *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    long n = s->ops->write(s->ctx, buf + off, len - off);
    if (n <= 0)
      return C2_ERR_IO;
    off += (size_t)n;
  }
  return C2_OK;
}

static c2_status fill_random(const c2_crypto_backend *be, uint8_t *buf,
                             size_t len) {
  if (be != NULL && be->random != NULL)
    return be->random(be->ctx, buf, len) == 0 ? C2_OK : C2_ERR_CRYPTO;
  /* No RNG configured: deterministic zeros. Only acceptable for tests. */
  memset(buf, 0, len);
  return C2_OK;
}

static c2_status random_below(const c2_crypto_backend *be, uint32_t bound,
                              uint32_t *out) {
  if (bound == 0) {
    *out = 0;
    return C2_OK;
  }
  uint32_t v = 0;
  c2_status st = fill_random(be, (uint8_t *)&v, sizeof(v));
  if (st != C2_OK)
    return st;
  *out = v % bound;
  return C2_OK;
}

void c2_secureconn_init(c2_secureconn *sc, const c2_crypto_backend *be,
                        c2_stream stream, const uint8_t key[C2_AES_KEY_BYTES]) {
  if (sc == NULL)
    return;
  sc->be = be;
  sc->stream = stream;
  if (key != NULL)
    memcpy(sc->key, key, C2_AES_KEY_BYTES);
  else
    memset(sc->key, 0, C2_AES_KEY_BYTES);
  sc->pad_min = 0;
  sc->pad_max = 0;
  sc->rxbuf = NULL;
  sc->rxcap = 0;
  sc->rxlen = 0;
  sc->rxoff = 0;
  sc->rx_owned = 0;
}

void c2_secureconn_set_key(c2_secureconn *sc,
                           const uint8_t key[C2_AES_KEY_BYTES]) {
  if (sc == NULL || key == NULL)
    return;
  memcpy(sc->key, key, C2_AES_KEY_BYTES);
}

void c2_secureconn_set_padding(c2_secureconn *sc, uint32_t min, uint32_t max) {
  if (sc == NULL)
    return;
  if (max < min)
    max = min;
  sc->pad_min = min;
  sc->pad_max = max;
}

void c2_secureconn_use_buffer(c2_secureconn *sc, uint8_t *buf, size_t cap) {
  if (sc == NULL)
    return;
  if (sc->rx_owned && sc->rxbuf != NULL)
    free(sc->rxbuf);
  sc->rxbuf = buf;
  sc->rxcap = buf ? cap : 0;
  sc->rxlen = 0;
  sc->rxoff = 0;
  sc->rx_owned = 0;
}

void c2_secureconn_close(c2_secureconn *sc) {
  if (sc == NULL)
    return;
  if (sc->rx_owned && sc->rxbuf != NULL) {
    free(sc->rxbuf);
    sc->rxbuf = NULL;
    sc->rxcap = 0;
    sc->rxlen = 0;
    sc->rxoff = 0;
    sc->rx_owned = 0;
  }
  if (sc->stream.ops != NULL && sc->stream.ops->close != NULL)
    sc->stream.ops->close(sc->stream.ctx);
}

/* ------------------------------------------------------------------------- */
/* Frame codec                                                                */
/* ------------------------------------------------------------------------- */

c2_status c2_secureconn_encode_frame(c2_secureconn *sc, const uint8_t *payload,
                                     size_t payload_len, size_t pad_len,
                                     uint8_t *out, size_t out_cap,
                                     size_t *out_len) {
  if (sc == NULL || sc->be == NULL || sc->be->aes256_gcm_seal == NULL ||
      out == NULL)
    return C2_ERR_ARG;
  if (payload_len > 0 && payload == NULL)
    return C2_ERR_ARG;
  if (payload_len > 0xffffffffu)
    return C2_ERR_OVERFLOW;

  size_t pt_len = 4 + payload_len + pad_len;
  if (pt_len < 4)
    return C2_ERR_OVERFLOW;
  size_t enc_len = C2_GCM_NONCE_BYTES + pt_len + C2_GCM_TAG_BYTES;
  if (enc_len > C2_FRAME_ENC_MAX)
    return C2_ERR_OVERFLOW;
  if (out_cap < 4 + enc_len)
    return C2_ERR_NOMEM;

  uint8_t *plain = (uint8_t *)malloc(pt_len);
  if (plain == NULL)
    return C2_ERR_NOMEM;
  c2_be32_store(plain, (uint32_t)payload_len);
  if (payload_len)
    memcpy(plain + 4, payload, payload_len);
  c2_status st = fill_random(sc->be, plain + 4 + payload_len, pad_len);
  if (st != C2_OK) {
    free(plain);
    return st;
  }

  uint8_t nonce[C2_GCM_NONCE_BYTES];
  st = fill_random(sc->be, nonce, sizeof(nonce));
  if (st != C2_OK) {
    free(plain);
    return st;
  }

  uint8_t *blob = out + 4; /* nonce || ciphertext||tag */
  size_t ct_len = 0;
  int rc = sc->be->aes256_gcm_seal(sc->be->ctx, sc->key, nonce, plain, pt_len,
                                   blob + C2_GCM_NONCE_BYTES,
                                   enc_len - C2_GCM_NONCE_BYTES, &ct_len);
  free(plain);
  if (rc != 0)
    return C2_ERR_CRYPTO;
  if (ct_len != pt_len + C2_GCM_TAG_BYTES)
    return C2_ERR_CRYPTO;

  memcpy(blob, nonce, C2_GCM_NONCE_BYTES);
  c2_be32_store(out, (uint32_t)(C2_GCM_NONCE_BYTES + ct_len));
  if (out_len)
    *out_len = 4 + C2_GCM_NONCE_BYTES + ct_len;
  return C2_OK;
}

c2_status c2_secureconn_decode_frame(c2_secureconn *sc, const uint8_t *enc,
                                     size_t enc_len, uint8_t *plain,
                                     size_t plain_cap, uint8_t **payload,
                                     size_t *payload_len) {
  if (sc == NULL || sc->be == NULL || sc->be->aes256_gcm_open == NULL ||
      enc == NULL || plain == NULL)
    return C2_ERR_ARG;
  if (enc_len < C2_GCM_NONCE_BYTES + C2_GCM_TAG_BYTES)
    return C2_ERR_PROTO;
  size_t ct_len = enc_len - C2_GCM_NONCE_BYTES;
  if (plain_cap < ct_len)
    return C2_ERR_NOMEM;

  const uint8_t *nonce = enc;
  const uint8_t *ct = enc + C2_GCM_NONCE_BYTES;
  size_t pt_len = 0;
  int rc = sc->be->aes256_gcm_open(sc->be->ctx, sc->key, nonce, ct, ct_len,
                                   plain, plain_cap, &pt_len);
  if (rc != 0)
    return C2_ERR_CRYPTO;
  if (pt_len < 4)
    return C2_ERR_PROTO;

  uint32_t plen = c2_be32_load(plain);
  if (plen > pt_len - 4)
    return C2_ERR_PROTO;
  if (payload)
    *payload = plain + 4;
  if (payload_len)
    *payload_len = plen;
  return C2_OK;
}

/* ------------------------------------------------------------------------- */
/* Stream API                                                                 */
/* ------------------------------------------------------------------------- */

static c2_status write_frame(c2_secureconn *sc, const uint8_t *payload,
                             size_t len, size_t pad_len) {
  size_t frame_cap = 4 + C2_FRAME_OVERHEAD + len + pad_len;
  uint8_t *frame = (uint8_t *)malloc(frame_cap);
  if (frame == NULL)
    return C2_ERR_NOMEM;
  size_t frame_len = 0;
  c2_status st = c2_secureconn_encode_frame(sc, payload, len, pad_len, frame,
                                            frame_cap, &frame_len);
  if (st == C2_OK)
    st = write_all(&sc->stream, frame, frame_len);
  free(frame);
  return st;
}

c2_status c2_secureconn_write(c2_secureconn *sc, const uint8_t *payload,
                              size_t len) {
  if (sc == NULL)
    return C2_ERR_ARG;
  size_t pad = 0;
  if (len > 0 && len <= C2_PADDING_MAX_FRAME && sc->pad_min > 0) {
    uint32_t span = sc->pad_max > sc->pad_min ? sc->pad_max - sc->pad_min : 0;
    uint32_t r = 0;
    c2_status st = random_below(sc->be, span + 1, &r);
    if (st != C2_OK)
      return st;
    pad = sc->pad_min + r;
  }
  return write_frame(sc, payload, len, pad);
}

c2_status c2_secureconn_write_bulk(c2_secureconn *sc, const uint8_t *payload,
                                   size_t len) {
  if (sc == NULL)
    return C2_ERR_ARG;
  return write_frame(sc, payload, len, 0);
}

long c2_secureconn_read(c2_secureconn *sc, uint8_t *buf, size_t cap) {
  if (sc == NULL || sc->stream.ops == NULL || sc->stream.ops->read == NULL ||
      buf == NULL || cap == 0)
    return C2_ERR_ARG;

  if (sc->rxoff < sc->rxlen) {
    size_t avail = sc->rxlen - sc->rxoff;
    size_t n = avail < cap ? avail : cap;
    memcpy(buf, sc->rxbuf + sc->rxoff, n);
    sc->rxoff += n;
    if (sc->rxoff == sc->rxlen)
      sc->rxoff = sc->rxlen = 0;
    return (long)n;
  }

  for (;;) {
    uint8_t hdr[4];
    int eof = 0;
    c2_status st = read_exact(&sc->stream, hdr, sizeof(hdr), &eof);
    if (st != C2_OK)
      return st;
    if (eof)
      return 0; /* clean end of stream */

    uint32_t enc_len = c2_be32_load(hdr);
    if (enc_len == 0 || enc_len > C2_FRAME_ENC_MAX)
      return C2_ERR_PROTO;

    uint8_t *enc = (uint8_t *)malloc(enc_len);
    if (enc == NULL)
      return C2_ERR_NOMEM;
    st = read_exact(&sc->stream, enc, enc_len, &eof);
    if (st != C2_OK || eof) {
      free(enc);
      return eof ? C2_ERR_PROTO : st;
    }

    uint8_t *plain = (uint8_t *)malloc(enc_len);
    if (plain == NULL) {
      free(enc);
      return C2_ERR_NOMEM;
    }
    uint8_t *payload = NULL;
    size_t plen = 0;
    st = c2_secureconn_decode_frame(sc, enc, enc_len, plain, enc_len, &payload,
                                    &plen);
    free(enc);
    if (st != C2_OK) {
      free(plain);
      return st;
    }
    if (plen == 0) {
      /* Empty control frame: skip it, never surface it as EOF. */
      free(plain);
      continue;
    }

    size_t n = plen < cap ? plen : cap;
    memcpy(buf, payload, n);
    if (n < plen) {
      size_t rem = plen - n;
      if (!sc->rx_owned || sc->rxcap < rem) {
        uint8_t *nb = (uint8_t *)realloc(sc->rx_owned ? sc->rxbuf : NULL, rem);
        if (nb == NULL) {
          free(plain);
          return C2_ERR_NOMEM;
        }
        sc->rxbuf = nb;
        sc->rxcap = rem;
        sc->rx_owned = 1;
      }
      memcpy(sc->rxbuf, payload + n, rem);
      sc->rxoff = 0;
      sc->rxlen = rem;
    } else {
      sc->rxoff = sc->rxlen = 0;
    }
    free(plain);
    return (long)n;
  }
}
