/*
 * memfile.c — in-memory file store with transparent gzip + AES-GCM.
 * See memfile.h. Not thread-safe; the agent's job loop is the owner.
 */

#include "memfile.h"

#include "gzip.h"

#include <stdlib.h>
#include <string.h>

static int key_eq(const char *stored, c2_str key) {
  size_t n = strlen(stored);
  return n == key.len && (n == 0 || memcmp(stored, key.ptr, n) == 0);
}

static c2_memfile_entry *entry_find(c2_memfile *m, c2_str key) {
  for (size_t i = 0; i < m->count; i++)
    if (key_eq(m->entries[i].key, key))
      return &m->entries[i];
  return NULL;
}

static const c2_memfile_entry *entry_find_const(const c2_memfile *m,
                                                c2_str key) {
  for (size_t i = 0; i < m->count; i++)
    if (key_eq(m->entries[i].key, key))
      return &m->entries[i];
  return NULL;
}

void c2_memfile_init(c2_memfile *m, const c2_crypto_backend *be,
                     c2_str password, size_t max_bytes) {
  if (m == NULL)
    return;
  memset(m, 0, sizeof(*m));
  m->be = be;
  m->password = password;
  m->max_bytes = max_bytes ? max_bytes : C2_MEMFILE_DEFAULT_MAX_BYTES;
}

void c2_memfile_free(c2_memfile *m) {
  if (m == NULL)
    return;
  for (size_t i = 0; i < m->count; i++) {
    if (m->entries[i].blob != NULL) {
      c2_secure_zero(m->entries[i].blob, m->entries[i].blob_len);
      free(m->entries[i].blob);
    }
    free(m->entries[i].key);
  }
  free(m->entries);
  memset(m, 0, sizeof(*m));
}

size_t c2_memfile_key(const char *name, size_t name_len, char *out,
                      size_t cap) {
  if (name == NULL)
    return 0;
  const char *base = name;
  size_t base_len = name_len;
  for (size_t i = name_len; i > 0; i--) {
    if (name[i - 1] == '/') {
      base = name + i;
      base_len = name_len - i;
      break;
    }
  }
  size_t prefix_len = sizeof(C2_MEMFILE_PREFIX) - 1;
  if (prefix_len + base_len + 1 > cap)
    return 0;
  memcpy(out, C2_MEMFILE_PREFIX, prefix_len);
  memcpy(out + prefix_len, base, base_len);
  out[prefix_len + base_len] = '\0';
  return prefix_len + base_len;
}

c2_status c2_memfile_write(c2_memfile *m, c2_str key, const uint8_t *data,
                           size_t len) {
  if (m == NULL || m->be == NULL)
    return C2_ERR_ARG;
  if (key.len == 0 || key.ptr == NULL)
    return C2_ERR_ARG;
  if (len > 0 && data == NULL)
    return C2_ERR_ARG;

  /* Compress first: ciphertext of compressed plaintext is the storage form. */
  size_t gz_cap = c2_gzip_bound(len);
  if (gz_cap == 0)
    return C2_ERR_UNSUPPORTED;
  uint8_t *gz = (uint8_t *)malloc(gz_cap);
  if (gz == NULL)
    return C2_ERR_NOMEM;
  size_t gz_len = 0;
  c2_status st = c2_gzip_compress(data, len, gz, gz_cap, &gz_len);
  if (st != C2_OK) {
    free(gz);
    return st;
  }

  uint8_t *blob = gz;
  size_t blob_len = gz_len;
  if (m->password.ptr != NULL) {
    size_t enc_cap = gz_len + 16 + 12 + 16;
    blob = (uint8_t *)malloc(enc_cap);
    if (blob == NULL) {
      free(gz);
      return C2_ERR_NOMEM;
    }
    st = c2_aes_gcm_encrypt_password(m->be, m->password, gz, gz_len, blob,
                                     enc_cap, &blob_len);
    c2_secure_zero(gz, gz_len);
    free(gz);
    if (st != C2_OK) {
      free(blob);
      return st;
    }
  }

  c2_memfile_entry *e = entry_find(m, key);
  size_t old_len = e ? e->blob_len : 0;
  if (m->bytes - old_len + blob_len > m->max_bytes) {
    free(blob);
    return C2_ERR_NOMEM; /* over budget: never grow past the cap */
  }

  if (e != NULL) {
    c2_secure_zero(e->blob, e->blob_len);
    free(e->blob);
    e->blob = blob;
    e->blob_len = blob_len;
    e->plain_len = len;
    m->bytes = m->bytes - old_len + blob_len;
    return C2_OK;
  }

  if (m->count == m->cap) {
    size_t cap = m->cap ? m->cap * 2 : 8;
    c2_memfile_entry *ne =
        (c2_memfile_entry *)realloc(m->entries, cap * sizeof(*ne));
    if (ne == NULL) {
      free(blob);
      return C2_ERR_NOMEM;
    }
    m->entries = ne;
    m->cap = cap;
  }
  char *k = (char *)malloc(key.len + 1);
  if (k == NULL) {
    free(blob);
    return C2_ERR_NOMEM;
  }
  memcpy(k, key.ptr, key.len);
  k[key.len] = '\0';
  m->entries[m->count].key = k;
  m->entries[m->count].blob = blob;
  m->entries[m->count].blob_len = blob_len;
  m->entries[m->count].plain_len = len;
  m->count++;
  m->bytes += blob_len;
  return C2_OK;
}

c2_status c2_memfile_read(const c2_memfile *m, c2_str key, uint8_t *out,
                          size_t out_cap, size_t *out_len) {
  if (m == NULL || out == NULL)
    return C2_ERR_ARG;
  const c2_memfile_entry *e = entry_find_const(m, key);
  if (e == NULL)
    return C2_ERR_PROTO; /* not found */

  const uint8_t *gz = e->blob;
  size_t gz_len = e->blob_len;
  uint8_t *dec = NULL;
  if (m->password.ptr != NULL) {
    if (m->be == NULL || m->be->aes256_gcm_open == NULL)
      return C2_ERR_UNSUPPORTED;
    dec = (uint8_t *)malloc(e->blob_len);
    if (dec == NULL)
      return C2_ERR_NOMEM;
    c2_status st = c2_aes_gcm_decrypt_password(m->be, m->password, e->blob,
                                               e->blob_len, dec, e->blob_len,
                                               &gz_len);
    if (st != C2_OK) {
      c2_secure_zero(dec, e->blob_len);
      free(dec);
      return st;
    }
    gz = dec;
  }

  c2_status st = c2_gzip_decompress(gz, gz_len, out, out_cap, out_len);
  if (dec != NULL) {
    c2_secure_zero(dec, e->blob_len);
    free(dec);
  }
  return st;
}

c2_status c2_memfile_read_alloc(const c2_memfile *m, c2_str key, uint8_t **out,
                                size_t *out_len) {
  if (m == NULL || out == NULL || out_len == NULL)
    return C2_ERR_ARG;
  const c2_memfile_entry *e = entry_find_const(m, key);
  if (e == NULL)
    return C2_ERR_PROTO;

  /* The plaintext size is not known up front (it is inside the compressed
   * stream), so grow until it fits. We wrote the entry ourselves, so a failure
   * before the cap is a size mismatch, not corruption. */
  size_t cap = e->blob_len * 4;
  if (cap < 4096)
    cap = 4096;
  for (;;) {
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (buf == NULL)
      return C2_ERR_NOMEM;
    size_t n = 0;
    c2_status st = c2_memfile_read(m, key, buf, cap, &n);
    if (st == C2_OK) {
      *out = buf;
      *out_len = n;
      return C2_OK;
    }
    free(buf);
    /* Only a too-small destination is retried; a crypto/format error would
     * otherwise spin allocating up to the ceiling before failing. */
    if (st != C2_ERR_NOMEM || cap >= C2_MEMFILE_DEFAULT_MAX_BYTES)
      return st;
    cap *= 2;
  }
}

int c2_memfile_has(const c2_memfile *m, c2_str key) {
  return m != NULL && entry_find_const(m, key) != NULL;
}

c2_status c2_memfile_remove(c2_memfile *m, c2_str key) {
  if (m == NULL)
    return C2_ERR_ARG;
  for (size_t i = 0; i < m->count; i++) {
    if (!key_eq(m->entries[i].key, key))
      continue;
    c2_secure_zero(m->entries[i].blob, m->entries[i].blob_len);
    free(m->entries[i].blob);
    free(m->entries[i].key);
    m->bytes -= m->entries[i].blob_len;
    for (size_t j = i + 1; j < m->count; j++)
      m->entries[j - 1] = m->entries[j];
    m->count--;
    return C2_OK;
  }
  return C2_ERR_PROTO; /* not found */
}

size_t c2_memfile_count(const c2_memfile *m) { return m ? m->count : 0; }

const char *c2_memfile_key_at(const c2_memfile *m, size_t i) {
  if (m == NULL || i >= m->count)
    return NULL;
  return m->entries[i].key;
}

size_t c2_memfile_plain_len_at(const c2_memfile *m, size_t i) {
  if (m == NULL || i >= m->count)
    return 0;
  return m->entries[i].plain_len;
}

size_t c2_memfile_bytes(const c2_memfile *m) { return m ? m->bytes : 0; }
