/* Cobalt Strike Beacon compatibility API for Linux BOFs.
 *
 * Adapted from TrustedSec ELFLoader's beacon_compatibility.c (BSD; see
 * core/modules/SA_linux/LICENSE.txt), with bounds checks and a working reset.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if !defined(__GLIBC__)
#include <dlfcn.h>
#endif

#include "beacon_compat.h"

/* Bound the captured output. Keep it below the agent's 10 MiB tunnel frame
 * cap so one BOF result fits in one response, and so a BOF that prints
 * without end cannot grow the agent's heap without limit. */
#define BOF_OUTPUT_MAX (8u << 20)

static char *output_buf = NULL;
static size_t output_len = 0;
static size_t output_cap = 0;

static void output_append(const char *data, size_t len) {
  if (data == NULL || len == 0)
    return;
  if (len > BOF_OUTPUT_MAX - 1u - output_len)
    return;
  if (output_len + len + 1 > output_cap) {
    size_t new_cap = output_cap ? output_cap * 2 : 4096;
    if (new_cap < output_len + len + 1)
      new_cap = output_len + len + 4096;
    if (new_cap > BOF_OUTPUT_MAX)
      new_cap = BOF_OUTPUT_MAX;
    char *new_buf = realloc(output_buf, new_cap);
    if (!new_buf)
      return;
    output_buf = new_buf;
    output_cap = new_cap;
  }
  memcpy(output_buf + output_len, data, len);
  output_len += len;
  output_buf[output_len] = '\0';
}

void beacon_output_reset(void) {
  free(output_buf);
  output_buf = NULL;
  output_len = 0;
  output_cap = 0;
}

char *beacon_output_take(void) {
  char *buf = output_buf;
  output_buf = NULL;
  output_len = 0;
  output_cap = 0;
  return buf;
}

void BeaconPrintf(int type, const char *fmt, ...) {
  (void)type;
  if (fmt == NULL)
    return;

  va_list ap;
  va_start(ap, fmt);
  int needed = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (needed < 0)
    return;

  char *buf = malloc((size_t)needed + 1);
  if (!buf)
    return;
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)needed + 1, fmt, ap);
  va_end(ap);

  output_append(buf, (size_t)needed);
  output_append("\n", 1);
  free(buf);
}

void BeaconOutput(int type, const char *data, int len) {
  (void)type;
  if (data != NULL && len > 0)
    output_append(data, (size_t)len);
}

static uint32_t swap_endianess(uint32_t indata) {
  uint32_t testint = 0xaabbccdd;
  uint32_t outint = indata;
  if (((unsigned char *)&testint)[0] == 0xdd) {
    ((unsigned char *)&outint)[0] = ((unsigned char *)&indata)[3];
    ((unsigned char *)&outint)[1] = ((unsigned char *)&indata)[2];
    ((unsigned char *)&outint)[2] = ((unsigned char *)&indata)[1];
    ((unsigned char *)&outint)[3] = ((unsigned char *)&indata)[0];
  }
  return outint;
}

void BeaconFormatAlloc(formatp *format, int maxsz) {
  if (format == NULL || maxsz <= 0)
    return;
  format->original = (char *)calloc((size_t)maxsz, 1);
  format->buffer = format->original;
  format->length = 0;
  format->size = format->original ? maxsz : 0;
}

void BeaconFormatReset(formatp *format) {
  if (format == NULL || format->original == NULL)
    return;
  memset(format->original, 0, (size_t)format->size);
  format->buffer = format->original;
  format->length = 0;
}

void BeaconFormatFree(formatp *format) {
  if (format == NULL)
    return;
  free(format->original);
  format->original = NULL;
  format->buffer = NULL;
  format->length = 0;
  format->size = 0;
}

void BeaconFormatAppend(formatp *format, char *text, int len) {
  if (format == NULL || text == NULL || len <= 0 || format->original == NULL)
    return;
  if (format->length < 0 || format->length > format->size ||
      len > format->size - format->length)
    return;
  memcpy(format->buffer, text, (size_t)len);
  format->buffer += len;
  format->length += len;
}

void BeaconFormatPrintf(formatp *format, char *fmt, ...) {
  if (format == NULL || fmt == NULL || format->original == NULL)
    return;
  int available = format->size - format->length;
  if (available <= 0)
    return;

  va_list args;
  va_start(args, fmt);
  int needed = vsnprintf(format->buffer, (size_t)available, fmt, args);
  va_end(args);
  if (needed < 0)
    return;
  int written = needed < available ? needed : available - 1;
  format->buffer += written;
  format->length += written;
}

char *BeaconFormatToString(formatp *format, int *size) {
  if (format == NULL)
    return NULL;
  if (size != NULL)
    *size = format->length;
  return format->original;
}

void BeaconFormatInt(formatp *format, int value) {
  if (format == NULL || format->original == NULL)
    return;
  if (format->length < 0 || format->length > format->size ||
      format->size - format->length < 4)
    return;
  uint32_t outdata = swap_endianess((uint32_t)value);
  memcpy(format->buffer, &outdata, 4);
  format->length += 4;
  format->buffer += 4;
}

int BeaconIsAdmin(void) {
  return geteuid() == 0;
}

void BeaconDataParse(datap *parser, char *buffer, int size) {
  if (parser == NULL)
    return;
  parser->original = buffer;
  parser->buffer = buffer;
  parser->length = 0;
  parser->size = 0;
  if (buffer == NULL || size < 4)
    return;

  /* The loader's argument buffer starts with a uint32 body length, matching
   * the Windows COFFLoader ABI and hello_linux's in-BOF helper. BOFs pass the
   * whole buffer to BeaconDataParse, so skip that prefix and clamp the body to
   * the supplied size before exposing it to BeaconData* accessors. */
  uint32_t body_len;
  memcpy(&body_len, buffer, 4);
  size_t available = (size_t)size - 4;
  if (body_len > available)
    body_len = (uint32_t)available;
  parser->buffer = buffer + 4;
  parser->length = (int)body_len;
  parser->size = (int)body_len;
}

int BeaconDataInt(datap *parser) {
  if (parser == NULL || parser->length < 4)
    return 0;
  int value;
  memcpy(&value, parser->buffer, 4);
  parser->buffer += 4;
  parser->length -= 4;
  return value;
}

short BeaconDataShort(datap *parser) {
  if (parser == NULL || parser->length < 2)
    return 0;
  short value;
  memcpy(&value, parser->buffer, 2);
  parser->buffer += 2;
  parser->length -= 2;
  return value;
}

int BeaconDataLength(datap *parser) {
  return parser != NULL ? parser->length : 0;
}

char *BeaconDataExtract(datap *parser, int *size) {
  if (size != NULL)
    *size = 0;
  if (parser == NULL || parser->length < 4)
    return NULL;

  int len;
  memcpy(&len, parser->buffer, 4);
  parser->buffer += 4;
  parser->length -= 4;
  if (len < 0 || len > parser->length)
    return NULL;

  char *out = parser->buffer;
  parser->buffer += len;
  parser->length -= len;
  if (size != NULL)
    *size = len;
  return out;
}

#if defined(__GLIBC__)
/* glibc's internal dlsym() needs a module handle. Earlier glibc versions crash
 * on a NULL handle, so open libc by soname first; newer versions keep the same
 * internal entry points as local symbols. */
extern void *__libc_dlsym(void *handle, const char *name);
extern void *__libc_dlopen_mode(const char *name, int mode);
extern int __libc_dlclose(void *handle);
#define C2_DLSYM(handle, name) __libc_dlsym((handle), (name))
#else
#include <dlfcn.h>
#define C2_DLSYM(handle, name) dlsym((handle), (name))
#endif

static void *libc_handle;

void *beacon_host_dlsym(const char *name) {
#if defined(__GLIBC__)
  if (libc_handle == NULL)
    libc_handle = __libc_dlopen_mode("libc.so.6", 1 /* RTLD_LAZY */);
  if (libc_handle != NULL)
    return C2_DLSYM(libc_handle, name);
#endif
  return C2_DLSYM(NULL, name);
}

void beacon_host_dlsym_reset(void) {
#if defined(__GLIBC__)
  if (libc_handle != NULL) {
    (void)__libc_dlclose(libc_handle);
    libc_handle = NULL;
  }
#endif
}

/* getEnviron must return a live char **. Resolving the environ data symbol
 * through dlsym works for functions on some hosts but not for data, and a
 * direct environ import needs a data relocation the C agent's in-memory loader
 * does not apply. Read /proc/self/environ once instead and keep the parsed
 * array for the lifetime of the mapped loader. */
static char **env_cache;
static char *env_cache_buf;

static char **get_environ(void) {
  if (env_cache != NULL)
    return env_cache;

  FILE *f = fopen("/proc/self/environ", "rb");
  if (f == NULL)
    return NULL;

  size_t cap = 4096;
  char *buf = (char *)malloc(cap);
  if (buf == NULL) {
    fclose(f);
    return NULL;
  }
  size_t len = 0;
  for (;;) {
    if (len == cap) {
      if (cap >= (1u << 20)) {
        free(buf);
        fclose(f);
        return NULL;
      }
      size_t next = cap * 2;
      char *grown = (char *)realloc(buf, next);
      if (grown == NULL) {
        free(buf);
        fclose(f);
        return NULL;
      }
      buf = grown;
      cap = next;
    }
    size_t n = fread(buf + len, 1, cap - len, f);
    if (n == 0)
      break;
    len += n;
  }
  int failed = ferror(f);
  fclose(f);
  if (failed || len == 0) {
    free(buf);
    return NULL;
  }
  if (buf[len - 1] != '\0') {
    if (len == cap) {
      char *grown = (char *)realloc(buf, cap + 1);
      if (grown == NULL) {
        free(buf);
        return NULL;
      }
      buf = grown;
      cap++;
    }
    buf[len++] = '\0';
  }

  size_t count = 0;
  for (size_t i = 0; i < len; i++) {
    if (buf[i] == '\0' && i + 1 < len && buf[i + 1] != '\0')
      count++;
  }
  char **out = (char **)calloc(count + 2, sizeof(char *));
  if (out == NULL) {
    free(buf);
    return NULL;
  }
  size_t n = 0;
  out[n++] = buf;
  for (size_t i = 0; i + 1 < len; i++) {
    if (buf[i] == '\0' && buf[i + 1] != '\0')
      out[n++] = buf + i + 1;
  }
  out[n] = NULL;

  env_cache = out;
  env_cache_buf = buf;
  return env_cache;
}

/* Release the parsed environment after a BOF run. The loader image is mapped
 * per execution, so keeping it tied to the run avoids leaking one copy per
 * invocation in the agent process. */
void beacon_env_reset(void) {
  free(env_cache);
  free(env_cache_buf);
  env_cache = NULL;
  env_cache_buf = NULL;
}
static const char *get_os_name(void) {
  return "lin";
}

/* ------------------------------------------------------------------------- */
/* Optional host primitives for file-transfer BOFs                            */
/* ------------------------------------------------------------------------- */

typedef int (*host_read_fn)(void *ctx, const char *path, unsigned char **out,
                            unsigned long *len, char *err, int err_cap);
typedef int (*host_write_fn)(void *ctx, const char *path,
                             const unsigned char *data, unsigned long len,
                             char *err, int err_cap);
typedef int (*host_upload_fn)(void *ctx, const char *token, const char *path,
                              unsigned long offset, char *err, int err_cap);
typedef int (*host_sha256_fn)(void *ctx, const unsigned char *data,
                              unsigned long len, char *hex,
                              unsigned long hex_cap, char *err, int err_cap);

static void *host_ctx;
static host_read_fn host_read;
static host_write_fn host_write;
static host_upload_fn host_upload;
static host_sha256_fn host_sha256;

static void set_host_err(char *err, int err_cap, const char *msg) {
  if (err == NULL || err_cap <= 0)
    return;
  snprintf(err, (size_t)err_cap, "%s", msg != NULL ? msg : "unavailable");
}

__attribute__((visibility("default"))) void
SetHostBridge(void *ctx, host_read_fn read, host_write_fn write,
              host_upload_fn upload, host_sha256_fn sha256) {
  host_ctx = ctx;
  host_read = read;
  host_write = write;
  host_upload = upload;
  host_sha256 = sha256;
}

int ReadFile(const char *path, unsigned char **out, unsigned long *len,
             char *err, int err_cap) {
  if (host_read == NULL) {
    set_host_err(err, err_cap, "ReadFile unavailable");
    return -9;
  }
  return host_read(host_ctx, path, out, len, err, err_cap);
}

int WriteFile(const char *path, const unsigned char *data, unsigned long len,
              char *err, int err_cap) {
  if (host_write == NULL) {
    set_host_err(err, err_cap, "WriteFile unavailable");
    return -9;
  }
  return host_write(host_ctx, path, data, len, err, err_cap);
}

int UploadFile(const char *token, const char *path, unsigned long offset,
               char *err, int err_cap) {
  if (host_upload == NULL) {
    set_host_err(err, err_cap, "UploadFile unavailable");
    return -9;
  }
  return host_upload(host_ctx, token, path, offset, err, err_cap);
}

int Sha256Hex(const unsigned char *data, unsigned long len, char *hex,
              unsigned long hex_cap, char *err, int err_cap) {
  if (host_sha256 == NULL) {
    set_host_err(err, err_cap, "Sha256Hex unavailable");
    return -9;
  }
  return host_sha256(host_ctx, data, len, hex, hex_cap, err, err_cap);
}

static const struct {
  const char *name;
  void *fn;
} beacon_apis[] = {
    {"BeaconPrintf", (void *)BeaconPrintf},
    {"BeaconOutput", (void *)BeaconOutput},
    {"BeaconDataParse", (void *)BeaconDataParse},
    {"BeaconDataInt", (void *)BeaconDataInt},
    {"BeaconDataShort", (void *)BeaconDataShort},
    {"BeaconDataLength", (void *)BeaconDataLength},
    {"BeaconDataExtract", (void *)BeaconDataExtract},
    {"BeaconFormatAlloc", (void *)BeaconFormatAlloc},
    {"BeaconFormatReset", (void *)BeaconFormatReset},
    {"BeaconFormatFree", (void *)BeaconFormatFree},
    {"BeaconFormatAppend", (void *)BeaconFormatAppend},
    {"BeaconFormatPrintf", (void *)BeaconFormatPrintf},
    {"BeaconFormatToString", (void *)BeaconFormatToString},
    {"BeaconFormatInt", (void *)BeaconFormatInt},
    {"BeaconIsAdmin", (void *)BeaconIsAdmin},
    {"swap_endianess", (void *)swap_endianess},
    {"getEnviron", (void *)get_environ},
    {"getOSName", (void *)get_os_name},
    {"ReadFile", (void *)ReadFile},
    {"WriteFile", (void *)WriteFile},
    {"UploadFile", (void *)UploadFile},
    {"Sha256Hex", (void *)Sha256Hex},
};

void *beacon_api_lookup(const char *name) {
  if (name == NULL)
    return NULL;
  for (size_t i = 0; i < sizeof(beacon_apis) / sizeof(beacon_apis[0]); i++) {
    if (strcmp(name, beacon_apis[i].name) == 0)
      return beacon_apis[i].fn;
  }
  return NULL;
}
