/* RV32 musl guest entry. The interpreter loads the linked executable, writes
 * the argument block into the reserved .rvhdr section, and starts at musl's
 * _start. */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;
int go(char *args, int len);

/* The interpreter writes this section before the guest starts. Keep the field
 * order in sync with rv_exec_hdr() in core/modules/rvvm/rvvm.c. */
struct rv_hdr {
  char *args;
  int len;
  char **env;
};
struct rv_hdr rv_bof_hdr __attribute__((section(".rvhdr"), used));

void BeaconPrintf(int type, const char *fmt, ...) {
  (void)type;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stdout, fmt, ap);
  va_end(ap);
  fputc('\n', stdout);
}

void BeaconOutput(int type, const char *data, int len) {
  (void)type;
  if (len > 0)
    fwrite(data, 1, (size_t)len, stdout);
}

char *getOSName(void) { return "lin"; }

char **getEnviron(void) {
  /* musl normally fills environ from the initial stack. Fall back to the
   * interpreter-provided pointer when a guest starts without envp. */
  if (environ != NULL && environ[0] != NULL)
    return environ;
  return rv_bof_hdr.env;
}

/* Host file-transfer primitives installed by the C agent. */
#define RV_SYS_XFER_READ 0x40000001u
#define RV_SYS_XFER_WRITE 0x40000002u
#define RV_SYS_XFER_UPLOAD 0x40000004u
#define RV_SYS_XFER_SHA256 0x40000005u

/* 32-byte SHA-256 digest written as hex, NUL terminated (the guest has no
 * access to the agent's common.h constants). */
#define RV_SHA256_HEX_BYTES 65

static void guest_clear_err(char *err, int err_cap) {
  if (err != NULL && err_cap > 0)
    err[0] = '\0';
}

/* ReadFile asks the host for the size first, then for the bytes, because the
 * host places them in guest memory and the guest owns its heap. */
int ReadFile(const char *path, unsigned char **out, unsigned long *len,
             char *err, int err_cap) {
  guest_clear_err(err, err_cap);
  if (path == NULL || out == NULL || len == NULL)
    return -22;
  *out = NULL;
  *len = 0;
  long need = syscall(RV_SYS_XFER_READ, path, NULL, 0);
  if (need < 0)
    return (int)need;
  unsigned char *buf = malloc(need > 0 ? (size_t)need : 1);
  if (buf == NULL)
    return -2;
  long got = syscall(RV_SYS_XFER_READ, path, buf, (unsigned long)need);
  if (got != need) {
    free(buf);
    return got < 0 ? (int)got : -5;
  }
  *out = buf;
  *len = (unsigned long)got;
  return 0;
}

int WriteFile(const char *path, const unsigned char *data, unsigned long len,
              char *err, int err_cap) {
  guest_clear_err(err, err_cap);
  return (int)syscall(RV_SYS_XFER_WRITE, path, data, len);
}

int UploadFile(const char *token, const char *path, unsigned long offset,
               char *err, int err_cap) {
  guest_clear_err(err, err_cap);
  return (int)syscall(RV_SYS_XFER_UPLOAD, token, path, offset);
}

int Sha256Hex(const unsigned char *data, unsigned long len, char *hex,
              unsigned long hex_cap, char *err, int err_cap) {
  guest_clear_err(err, err_cap);
  if (hex == NULL || hex_cap < RV_SHA256_HEX_BYTES)
    return -22;
  return (int)syscall(RV_SYS_XFER_SHA256, data, len, hex, hex_cap);
}

/* glibc-era BOFs call the versioned stat entry point directly. musl exposes
 * stat(), so keep the source-compatible symbol inside the guest. */
int __xstat(int ver, const char *path, struct stat *buf) {
  (void)ver;
  return stat(path, buf);
}

typedef struct {
  char *original;
  char *buffer;
  int length;
  int size;
} datap;
typedef datap formatp;

void BeaconDataParse(datap *parser, char *buffer, int size) {
  if (parser == NULL)
    return;
  parser->original = buffer;
  parser->buffer = buffer;
  parser->length = 0;
  parser->size = 0;
  if (buffer == NULL || size < 4)
    return;
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
  int v;
  memcpy(&v, parser->buffer, 4);
  parser->buffer += 4;
  parser->length -= 4;
  return v;
}

short BeaconDataShort(datap *parser) {
  if (parser == NULL || parser->length < 2)
    return 0;
  short v;
  memcpy(&v, parser->buffer, 2);
  parser->buffer += 2;
  parser->length -= 2;
  return v;
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
  if (format == NULL || text == NULL || len <= 0)
    return;
  if (format->length + len > format->size)
    return;
  memcpy(format->buffer + format->length, text, (size_t)len);
  format->length += len;
}

void BeaconFormatPrintf(formatp *format, char *fmt, ...) {
  if (format == NULL || fmt == NULL)
    return;
  va_list ap;
  va_start(ap, fmt);
  int room = format->size - format->length;
  int n = room > 0 ? vsnprintf(format->buffer + format->length, (size_t)room,
                               fmt, ap)
                   : 0;
  va_end(ap);
  if (n > 0) {
    format->length += n < room ? n : room - 1;
  }
}

char *BeaconFormatToString(formatp *format, int *size) {
  if (size != NULL)
    *size = format != NULL ? format->length : 0;
  if (format == NULL || format->original == NULL)
    return NULL;
  if (format->size > 0)
    format->original[format->length < format->size ? format->length
                                                   : format->size - 1] = '\0';
  return format->original;
}

void BeaconFormatInt(formatp *format, int value) {
  if (format == NULL || format->length + 4 > format->size)
    return;
  memcpy(format->buffer + format->length, &value, 4);
  format->length += 4;
}

int BeaconIsAdmin(void) { return 0; }

uint32_t swap_endianess(uint32_t indata) {
  return ((indata & 0x000000ffu) << 24) | ((indata & 0x0000ff00u) << 8) |
         ((indata & 0x00ff0000u) >> 8) | ((indata & 0xff000000u) >> 24);
}

char *BeaconGetOutputData(int *outsize) {
  if (outsize != NULL)
    *outsize = 0;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  return go(rv_bof_hdr.args, rv_bof_hdr.len);
}
