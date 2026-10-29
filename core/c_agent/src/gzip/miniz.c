/*
 * miniz.c — gzip support backed by the vendored miniz (tdefl/tinfl).
 *
 * miniz is a self-contained, MIT-licensed zlib implementation, so gzip needs no
 * system zlib: FTP uploads (a wire requirement) and gunzipping a downloaded
 * module both work on a stripped host. The gzip container framing is written
 * here (miniz provides raw DEFLATE only), so the CRC-32 and ISIZE trailer are
 * produced/verified explicitly.
 */

#include "gzip.h"

#include "miniz.h"

#include <string.h>

/* ------------------------------------------------------------------------- */
/* gzip constants                                                             */
/* ------------------------------------------------------------------------- */

#define GZIP_HEADER_BYTES 10u
#define GZIP_TRAILER_BYTES 8u

/* Worst case for tdefl on incompressible data: DEFLATE adds at most ~5 bytes
 * per 16 KiB block plus a small fixed overhead. */
size_t c2_gzip_bound(size_t in_len) {
  const size_t overhead = GZIP_HEADER_BYTES + GZIP_TRAILER_BYTES + 64u;
  if (in_len > (SIZE_MAX - overhead) / 9u * 8u)
    return SIZE_MAX;
  return GZIP_HEADER_BYTES + in_len + in_len / 8 + 64 + GZIP_TRAILER_BYTES;
}

/* ------------------------------------------------------------------------- */
/* CRC-32 (RFC 1952)                                                          */
/* ------------------------------------------------------------------------- */

static uint32_t crc32_update(uint32_t crc, const uint8_t *p, size_t n) {
  crc = ~crc;
  for (size_t i = 0; i < n; i++) {
    crc ^= p[i];
    for (int k = 0; k < 8; k++) {
      uint32_t mask = (uint32_t) - (int32_t)(crc & 1u);
      crc = (crc >> 1) ^ (0xEDB88320u & mask);
    }
  }
  return ~crc;
}

static void put_le32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------------- */
/* gzip writer                                                                */
/* ------------------------------------------------------------------------- */

c2_status c2_gzip_compress(const uint8_t *in, size_t in_len, uint8_t *out,
                           size_t out_cap, size_t *out_len) {
  if (out == NULL)
    return C2_ERR_ARG;
  if (in_len > 0 && in == NULL)
    return C2_ERR_ARG;
  size_t bound = c2_gzip_bound(in_len);
  if (bound == SIZE_MAX || out_cap < GZIP_HEADER_BYTES + GZIP_TRAILER_BYTES ||
      bound > out_cap)
    return C2_ERR_NOMEM;

  /* Fixed 10-byte header: no name/comment, mtime 0, OS = Unix. */
  static const uint8_t header[GZIP_HEADER_BYTES] = {
      0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
  memcpy(out, header, sizeof(header));

  size_t deflate_cap = out_cap - GZIP_HEADER_BYTES - GZIP_TRAILER_BYTES;
  size_t csize = tdefl_compress_mem_to_mem(
      out + GZIP_HEADER_BYTES, deflate_cap, in, in_len, 0);
  if (csize == 0 || csize > deflate_cap)
    return C2_ERR_CRYPTO; /* tdefl returns 0 only on failure */

  size_t o = GZIP_HEADER_BYTES + csize;
  put_le32(out + o, crc32_update(0, in, in_len));
  put_le32(out + o + 4, (uint32_t)in_len);
  if (out_len)
    *out_len = o + GZIP_TRAILER_BYTES;
  return C2_OK;
}

/* ------------------------------------------------------------------------- */
/* gzip reader                                                                */
/* ------------------------------------------------------------------------- */

c2_status c2_gzip_decompress(const uint8_t *in, size_t in_len, uint8_t *out,
                             size_t out_cap, size_t *out_len) {
  if (out == NULL)
    return C2_ERR_ARG;
  if (in_len > 0 && in == NULL)
    return C2_ERR_ARG;
  if (in_len < GZIP_HEADER_BYTES + GZIP_TRAILER_BYTES)
    return C2_ERR_PROTO;
  if (in[0] != 0x1f || in[1] != 0x8b || in[2] != 0x08)
    return C2_ERR_PROTO;

  /* Skip the optional header fields selected by FLG. */
  size_t off = GZIP_HEADER_BYTES;
  uint8_t flg = in[3];
  if (flg & 0x04) { /* FEXTRA */
    if (off + 2 > in_len)
      return C2_ERR_PROTO;
    uint16_t xlen = (uint16_t)(in[off] | (in[off + 1] << 8));
    off += 2 + xlen;
  }
  if (flg & 0x08) { /* FNAME */
    while (off < in_len && in[off] != 0)
      off++;
    off++;
  }
  if (flg & 0x10) { /* FCOMMENT */
    while (off < in_len && in[off] != 0)
      off++;
    off++;
  }
  if (flg & 0x02) /* FHCRC */
    off += 2;
  if (off + GZIP_TRAILER_BYTES > in_len)
    return C2_ERR_PROTO;

  size_t def_len = in_len - off - GZIP_TRAILER_BYTES;
  size_t n = tinfl_decompress_mem_to_mem(out, out_cap, in + off, def_len, 0);
  if (n == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED)
    return C2_ERR_PROTO;

  if ((uint32_t)n != get_le32(in + in_len - 4))
    return C2_ERR_PROTO; /* ISIZE */
  if (crc32_update(0, out, n) != get_le32(in + in_len - 8))
    return C2_ERR_PROTO; /* CRC-32 */

  if (out_len)
    *out_len = n;
  return C2_OK;
}
