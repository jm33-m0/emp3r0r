#ifndef C2_SECURECONN_H
#define C2_SECURECONN_H

/*
 * secureconn.h — SecureConn framing and encryption.
 *
 * Every channel (http_poll, h2conn, quic, kcp, smb, ...) is reduced to a
 * bidirectional byte stream and then wrapped in SecureConn. All CBOR is written
 * through it, one message per frame.
 *
 * Frame layout (all integers big-endian):
 *
 *   frame     := uint32(enc_len) || enc_blob
 *   enc_blob  := nonce[12] || AES-256-GCM(plaintext)
 *   plaintext := uint32(payload_len) || payload || padding
 *   enc_len    = 12 + len(plaintext) + 16
 *
 * There is no AAD. payload_len lives inside the authenticated plaintext, so a
 * tampered length fails the GCM tag. The outer enc_len is untrusted and only
 * bounds the read.
 *
 * Key lifecycle (README.md §4.2):
 *   1. every stream starts on the per-build PSK;
 *   2. checkin/msg exchange the ECDH handshake on the PSK;
 *   3. after the handshake reply is read, switch the msg stream to the session
 *      key; auxiliary streams re-key right after their MsgAuth frame.
 */

#include "common.h"
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 4-byte length prefix + 12-byte nonce + 4-byte payload length + 16-byte tag. */
#define C2_FRAME_OVERHEAD (4u + C2_GCM_NONCE_BYTES + 4u + C2_GCM_TAG_BYTES)

/*
 * Raw byte stream provided by a channel. read returns >0 bytes, 0 on clean
 * EOF, or a negative c2_status on error. write returns the number of payload
 * bytes accepted, or a negative c2_status. close releases the stream and is
 * idempotent.
 */
/*
 * A polling transport returns C2_STREAM_IDLE from read() when a long-poll
 * cycle completes with no data. It is neither data nor an error: the caller
 * uses it to send a keepalive before polling again. A blocking/duplex
 * transport never returns it.
 */
#define C2_STREAM_IDLE (-1001L)

typedef struct c2_stream_ops {
  long (*read)(void *ctx, uint8_t *buf, size_t cap);
  long (*write)(void *ctx, const uint8_t *buf, size_t len);
  void (*close)(void *ctx);
} c2_stream_ops;

typedef struct c2_stream {
  const c2_stream_ops *ops;
  void *ctx;
} c2_stream;

typedef struct {
  const c2_crypto_backend *be;
  c2_stream stream;

  uint8_t key[C2_AES_KEY_BYTES];

  /* Sender-side padding range; 0,0 disables it. Only applied to control
   * frames (payload <= C2_PADDING_MAX_FRAME). */
  uint32_t pad_min;
  uint32_t pad_max;

  /* Decrypted but not yet consumed payload. Freestanding callers may attach
   * their own buffer with c2_secureconn_use_buffer; otherwise the first read
   * may allocate and c2_secureconn_close frees what it allocated. */
  uint8_t *rxbuf;
  size_t rxcap;
  size_t rxlen;
  size_t rxoff;
  int rx_owned;
} c2_secureconn;

/* Initialise a SecureConn over an already-open raw stream, using `key`. */
void c2_secureconn_init(c2_secureconn *sc, const c2_crypto_backend *be,
                        c2_stream stream, const uint8_t key[C2_AES_KEY_BYTES]);

/* Switch to the ephemeral PFS session key (after the handshake reply). */
void c2_secureconn_set_key(c2_secureconn *sc,
                           const uint8_t key[C2_AES_KEY_BYTES]);

/* Configure control-frame padding. max < min is clamped to min. */
void c2_secureconn_set_padding(c2_secureconn *sc, uint32_t min, uint32_t max);

/* Attach a caller-owned buffer for reassembling a decrypted frame larger than
 * the read() destination. Must be called before the first read when the
 * allocator is unavailable. */
void c2_secureconn_use_buffer(c2_secureconn *sc, uint8_t *buf, size_t cap);

/* Write one whole CBOR message as exactly one padded control frame. */
c2_status c2_secureconn_write(c2_secureconn *sc, const uint8_t *payload,
                              size_t len);

/* Write one whole CBOR message as a frame without padding (bulk transfers). */
c2_status c2_secureconn_write_bulk(c2_secureconn *sc, const uint8_t *payload,
                                   size_t len);

/*
 * Read payload bytes into buf. Returns >0 the number of bytes copied, 0 on
 * clean EOF, negative c2_status on error. Zero-length frames are skipped, so
 * a return of 0 always means EOF and not "empty control frame".
 */
long c2_secureconn_read(c2_secureconn *sc, uint8_t *buf, size_t cap);

/*
 * Read exactly one frame's payload (one CBOR message) into buf. Empty control
 * frames are skipped. On clean stream EOF, *eof is set to 1 and C2_OK is
 * returned; otherwise *eof is 0 and *len holds the payload length. Returns
 * C2_ERR_NOMEM when the message does not fit in `cap` (the session layer sizes
 * its buffer to the message cap, so this is a protocol violation).
 */
c2_status c2_secureconn_read_msg(c2_secureconn *sc, uint8_t *buf, size_t cap,
                                 size_t *len, int *eof);

/* Close the underlying stream. Does not zero the key; do that yourself. */
void c2_secureconn_close(c2_secureconn *sc);

/* ---- low-level frame helpers (tests / custom transports) ---------------- */

/*
 * Encode a single frame into out. The output is the full wire frame including
 * the length prefix. `pad_len` is the number of random padding bytes appended
 * inside the authenticated plaintext. out_cap must be at least
 * C2_FRAME_OVERHEAD + payload_len + pad_len.
 */
c2_status c2_secureconn_encode_frame(c2_secureconn *sc, const uint8_t *payload,
                                     size_t payload_len, size_t pad_len,
                                     uint8_t *out, size_t out_cap,
                                     size_t *out_len);

/*
 * Decode one frame read as `enc_len` bytes into enc (the bytes following the
 * length prefix). On success payload points into `plain` and *payload_len is
 * its length. `plain_cap` must be at least enc_len - C2_GCM_NONCE_BYTES -
 * C2_GCM_TAG_BYTES.
 */
c2_status c2_secureconn_decode_frame(c2_secureconn *sc, const uint8_t *enc,
                                     size_t enc_len, uint8_t *plain,
                                     size_t plain_cap, uint8_t **payload,
                                     size_t *payload_len);

#ifdef __cplusplus
}
#endif

#endif /* C2_SECURECONN_H */
