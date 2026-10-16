#include "secureconn.h"

#include "stub_crypto.h"

#include "fuzz_common.h"

#include <string.h>

/* Identity "AEAD": open returns the ciphertext minus its 16-byte tag unchanged,
 * seal appends a zero tag. This lets arbitrary fuzz input control the
 * plaintext, so the frame parser (enc_len, payload_len, padding, the
 * reassembly buffer) is exercised exhaustively rather than failing the tag
 * immediately. */
static int id_seal(void *ctx, const uint8_t key[C2_AES_KEY_BYTES],
                   const uint8_t nonce[C2_GCM_NONCE_BYTES], const uint8_t *in,
                   size_t in_len, uint8_t *out, size_t out_cap,
                   size_t *out_len) {
  (void)ctx;
  (void)key;
  (void)nonce;
  if (out_cap < in_len + C2_GCM_TAG_BYTES)
    return -1;
  if (in_len)
    memcpy(out, in, in_len);
  memset(out + in_len, 0, C2_GCM_TAG_BYTES);
  *out_len = in_len + C2_GCM_TAG_BYTES;
  return 0;
}

static int id_open(void *ctx, const uint8_t key[C2_AES_KEY_BYTES],
                   const uint8_t nonce[C2_GCM_NONCE_BYTES], const uint8_t *in,
                   size_t in_len, uint8_t *out, size_t out_cap,
                   size_t *out_len) {
  (void)ctx;
  (void)key;
  (void)nonce;
  if (in_len < C2_GCM_TAG_BYTES)
    return -1;
  size_t n = in_len - C2_GCM_TAG_BYTES;
  if (out_cap < n)
    return -1;
  if (n)
    memcpy(out, in, n);
  *out_len = n;
  return 0;
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

static void drive_read(const c2_crypto_backend *be, const uint8_t *data,
                       size_t size, const uint8_t key[C2_AES_KEY_BYTES]) {
  rbuf rb = {data, size, 0};
  c2_secureconn sc;
  c2_secureconn_init(&sc, be, (c2_stream){&g_rb_ops, &rb}, key);
  c2_secureconn_set_padding(&sc, 1, 32);
  uint8_t out[64];
  for (int i = 0; i < 128; i++) {
    long n = c2_secureconn_read(&sc, out, sizeof(out));
    if (n <= 0)
      break;
  }
  c2_secureconn_close(&sc);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t key[C2_AES_KEY_BYTES];
  for (size_t i = 0; i < sizeof(key); i++)
    key[i] = (uint8_t)(i * 31u + (size ? data[i % size] : 0));

  /* Identity backend: maximum parser coverage on arbitrary plaintext. */
  c2_crypto_backend id;
  memset(&id, 0, sizeof(id));
  id.aes256_gcm_seal = id_seal;
  id.aes256_gcm_open = id_open;
  drive_read(&id, data, size, key);

  /* Real-shaped stub backend: exercises the authentication-failure path. */
  uint32_t rng = 0x12345678u ^ (uint32_t)size;
  c2_crypto_backend stub;
  stub_crypto_init(&stub, &rng);
  drive_read(&stub, data, size, key);

  /* Direct frame decode of the raw input (enc = nonce || ct || tag). */
  {
    uint8_t plain[4096];
    uint8_t *payload = NULL;
    size_t plen = 0;
    c2_secureconn sc;
    c2_secureconn_init(&sc, &id, (c2_stream){0}, key);
    (void)c2_secureconn_decode_frame(&sc, data, size, plain, sizeof(plain),
                                     &payload, &plen);
    c2_secureconn_close(&sc);
  }

  /* Encode/decode round-trip with the stub AEAD. */
  {
    uint8_t frame[8192];
    size_t frame_len = 0;
    c2_secureconn sc;
    c2_secureconn_init(&sc, &stub, (c2_stream){0}, key);
    if (c2_secureconn_encode_frame(&sc, data, size, size % 16, frame,
                                   sizeof(frame), &frame_len) == C2_OK) {
      uint8_t plain[8192];
      uint8_t *payload = NULL;
      size_t plen = 0;
      c2_secureconn sc2;
      c2_secureconn_init(&sc2, &stub, (c2_stream){0}, key);
      (void)c2_secureconn_decode_frame(&sc2, frame + 4, frame_len - 4, plain,
                                       sizeof(plain), &payload, &plen);
      c2_secureconn_close(&sc2);
    }
    c2_secureconn_close(&sc);
  }

  return 0;
}
