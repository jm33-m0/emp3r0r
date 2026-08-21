/*
 * pico-runner.c — standalone EXE that invokes LoadAndRun from
 * wrapper/crystal-loader.c to load and run a Crystal Palace PICO blob.
 *
 * Build (single self-contained exe, no DLL needed):
 *   x86_64-w64-mingw32-gcc -O2 -Wall -DBUILD_DLL \
 *       pico-runner.c ../wrapper/crystal-loader.c \
 *       ../wrapper/beacon_compatibility.c -o pico-runner.exe
 *
 * Usage:
 *   pico-runner.exe --file <pico.bin> [--args <runtime args>]
 *   pico-runner.exe <pico.bin> [args...]
 *
 * The PICO is packed into the same COFFLoader LoadAndRun wire format used by
 * core/lib/coffloader/dll_windows.go (buildLoadAndRunBuffer / packBOFArgs).
 */

#define WIN32_LEAN_AND_MEAN
// clang-format off
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// clang-format on

extern int __cdecl LoadAndRun(char *argsBuffer, uint32_t bufferSize,
                              int (*callback)(char *, int));

static int console_callback(char *data, int len) {
  if (data != NULL && len > 0) {
    fwrite(data, 1, (size_t)len, stdout);
    fflush(stdout);
  }
  return 0;
}

/* Report a native exception from a malformed PICO instead of crashing with no
 * context. LoadAndRun itself does not install a crash gate. */
static LONG WINAPI crash_veh(PEXCEPTION_POINTERS ep) {
  char msg[160];
  int n = snprintf(msg, sizeof(msg),
                   "[-] PICO raised native exception 0x%08lX at 0x%p\r\n",
                   ep->ExceptionRecord->ExceptionCode,
                   ep->ExceptionRecord->ExceptionAddress);
  if (n > 0) {
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    if (err != NULL && err != INVALID_HANDLE_VALUE) {
      DWORD written = 0;
      WriteFile(err, msg, (DWORD)n, &written, NULL);
    }
  }
  ExitProcess(1);
}

/* --- wire-format buffer -------------------------------------------------- */
typedef struct {
  unsigned char *data;
  size_t len;
  size_t cap;
} wbuf;

static int wbuf_reserve(wbuf *b, size_t extra) {
  if (b->len + extra <= b->cap)
    return 0;
  size_t ncap = b->cap ? b->cap : 256;
  while (ncap < b->len + extra)
    ncap *= 2;
  unsigned char *nd = (unsigned char *)realloc(b->data, ncap);
  if (nd == NULL)
    return -1;
  b->data = nd;
  b->cap = ncap;
  return 0;
}

static int wbuf_u32(wbuf *b, uint32_t v) {
  if (wbuf_reserve(b, 4))
    return -1;
  b->data[b->len++] = (unsigned char)(v & 0xff);
  b->data[b->len++] = (unsigned char)((v >> 8) & 0xff);
  b->data[b->len++] = (unsigned char)((v >> 16) & 0xff);
  b->data[b->len++] = (unsigned char)((v >> 24) & 0xff);
  return 0;
}

static int wbuf_bytes(wbuf *b, const void *p, size_t n) {
  if (n == 0)
    return 0;
  if (wbuf_reserve(b, n))
    return -1;
  memcpy(b->data + b->len, p, n);
  b->len += n;
  return 0;
}

/* [4-byte length][bytes] */
static int wbuf_blob(wbuf *b, const void *p, size_t n) {
  if (wbuf_u32(b, (uint32_t)n))
    return -1;
  return wbuf_bytes(b, p, n);
}

static unsigned char *read_file(const char *path, size_t *out_len) {
  HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return NULL;

  LARGE_INTEGER sz;
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 0x7fffffffLL) {
    CloseHandle(h);
    return NULL;
  }

  size_t len = (size_t)sz.QuadPart;
  unsigned char *buf = (unsigned char *)malloc(len);
  if (buf == NULL) {
    CloseHandle(h);
    return NULL;
  }

  DWORD done = 0;
  BOOL ok = ReadFile(h, buf, (DWORD)len, &done, NULL);
  CloseHandle(h);
  if (!ok || done != (DWORD)len) {
    free(buf);
    return NULL;
  }
  *out_len = len;
  return buf;
}

int main(int argc, char **argv) {
  const char *file = NULL;
  const char *args = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
      file = argv[++i];
    } else if (strcmp(argv[i], "--args") == 0 && i + 1 < argc) {
      args = argv[++i];
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      printf("usage: pico-runner.exe --file <pico.bin> [--args <runtime args>]\n"
             "       pico-runner.exe <pico.bin> [args...]\n");
      return 0;
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "unknown option: %s\n", argv[i]);
      return 2;
    } else if (file == NULL) {
      file = argv[i];
    } else if (args == NULL) {
      args = argv[i];
    }
  }

  if (file == NULL) {
    fprintf(stderr, "usage: pico-runner.exe --file <pico.bin> [--args <args>]\n");
    return 2;
  }

  size_t pico_len = 0;
  unsigned char *pico = read_file(file, &pico_len);
  if (pico == NULL) {
    fprintf(stderr, "[-] cannot read PICO file: %s\n", file);
    return 1;
  }

  wbuf buf = {0};
  int failed = 0;

  /* 4-byte header skipped by BeaconDataParse. */
  failed |= wbuf_u32(&buf, 0);

  /* entry "go", NUL-terminated + padded to a 4-byte boundary. */
  unsigned char mode[4] = {'g', 'o', 0, 0};
  failed |= wbuf_blob(&buf, mode, sizeof(mode));

  /* PICO blob. */
  failed |= wbuf_blob(&buf, pico, pico_len);

  /* Packed BOF args: packBlob(packBOFArgs(args)). */
  if (args != NULL) {
    size_t cstr_len = strlen(args) + 1;
    failed |= wbuf_u32(&buf, (uint32_t)(4 + 4 + cstr_len)); /* blob len */
    failed |= wbuf_u32(&buf, (uint32_t)(4 + cstr_len));     /* total len */
    failed |= wbuf_blob(&buf, args, cstr_len);              /* z-string */
  } else {
    failed |= wbuf_u32(&buf, 4); /* blob len */
    failed |= wbuf_u32(&buf, 0); /* total len (no args) */
  }

  if (failed) {
    fprintf(stderr, "[-] out of memory building buffer\n");
    free(pico);
    return 1;
  }

  AddVectoredExceptionHandler(1, crash_veh);

  fprintf(stderr, "[*] running PICO (%zu bytes)%s%s\n", pico_len,
          args ? " with args: " : "", args ? args : "");

  int ret = LoadAndRun((char *)buf.data, (uint32_t)buf.len, console_callback);
  fprintf(stderr, "\n[*] LoadAndRun returned %d\n", ret);

  free(pico);
  free(buf.data);
  return ret != 0;
}
