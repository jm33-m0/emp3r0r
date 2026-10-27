/*
 * fuzz_runner.c — dependency-free fallback driver for the fuzz targets.
 *
 * With clang + libFuzzer (make CC=clang HOSTCC=clang FUZZER=libfuzzer) this
 * file is not linked and libFuzzer supplies main + coverage feedback. Otherwise
 * this mutational loop runs the targets under ASan/UBSan, which still catches
 * memory-safety and undefined-behaviour bugs.
 *
 * Usage:
 *   ./fuzz_<target> [seed-file ...]
 *
 * The Makefile passes every file under fuzz/corpus/<target>/ as a seed, so the
 * fuzzer starts from real protocol samples rather than empty input.
 *
 * Environment:
 *   FUZZ_ITERS        iterations (default 200000)
 *   FUZZ_SEED         PRNG seed
 *   FUZZ_CRASH        file to write the crashing input to (default crash.bin)
 *   FUZZ_CORPUS_OUT   directory to persist newly discovered corpus entries
 *
 * Exit code is 0 on completion; a target that trips an invariant or a
 * sanitizer abort writes the current input to FUZZ_CRASH and terminates
 * non-zero, so the crash is always reproducible.
 */

#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAX_INPUT 65536
#define MAX_CORPUS 256

typedef struct {
  uint8_t data[MAX_INPUT];
  size_t len;
} corpus_entry;

static corpus_entry g_corpus[MAX_CORPUS];
static size_t g_corpus_len;
static const char *g_corpus_out;
static const char *g_crash_path = "crash.bin";

/* The input currently being executed, so a signal handler can dump it. The
 * buffer lives for the whole run and is only reassigned between iterations. */
static const uint8_t *g_current;
static size_t g_current_len;

static uint64_t g_rng = 0x2545f4914f6cdd1dULL;

static uint32_t rng(void) {
  g_rng ^= g_rng << 13;
  g_rng ^= g_rng >> 7;
  g_rng ^= g_rng << 17;
  return (uint32_t)(g_rng >> 32);
}

/* Async-signal-safe: open/write/close only. */
static void dump_current(void) {
  if (g_current == NULL || g_current_len == 0)
    return;
  int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    return;
  size_t off = 0;
  while (off < g_current_len) {
    ssize_t n = write(fd, g_current + off, g_current_len - off);
    if (n <= 0)
      break;
    off += (size_t)n;
  }
  close(fd);
}

static void on_signal(int sig) {
  dump_current();
  signal(sig, SIG_DFL);
  raise(sig);
}

static void install_crash_handlers(void) {
  const int sigs[] = {SIGABRT, SIGSEGV, SIGBUS, SIGFPE, SIGILL};
  for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
    signal(sigs[i], on_signal);
}

static int corpus_has(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < g_corpus_len; i++) {
    if (g_corpus[i].len == len &&
        (len == 0 || memcmp(g_corpus[i].data, data, len) == 0))
      return 1;
  }
  return 0;
}

static void persist(const uint8_t *data, size_t len) {
  if (g_corpus_out == NULL || len == 0)
    return;
  char path[1024];
  snprintf(path, sizeof(path), "%s/id_%06zu", g_corpus_out, (size_t)rng());
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
  if (fd < 0)
    return;
  size_t off = 0;
  while (off < len) {
    ssize_t n = write(fd, data + off, len - off);
    if (n <= 0)
      break;
    off += (size_t)n;
  }
  close(fd);
}

static void corpus_add(const uint8_t *data, size_t len) {
  if (g_corpus_len >= MAX_CORPUS || len == 0 || len > MAX_INPUT)
    return;
  if (corpus_has(data, len))
    return;
  memcpy(g_corpus[g_corpus_len].data, data, len);
  g_corpus[g_corpus_len].len = len;
  g_corpus_len++;
  persist(data, len);
}

static size_t mutate(uint8_t *buf, size_t len) {
  unsigned rounds = 1 + rng() % 8;
  for (unsigned i = 0; i < rounds && len > 0; i++) {
    switch (rng() % 5) {
    case 0: /* bit flip */
      buf[rng() % len] ^= (uint8_t)(1u << (rng() % 8));
      break;
    case 1: /* random byte */
      buf[rng() % len] = (uint8_t)rng();
      break;
    case 2: /* insert */
      if (len < MAX_INPUT) {
        size_t at = rng() % (len + 1);
        memmove(buf + at + 1, buf + at, len - at);
        buf[at] = (uint8_t)rng();
        len++;
      }
      break;
    case 3: /* erase */
      if (len > 1) {
        size_t at = rng() % len;
        memmove(buf + at, buf + at + 1, len - at - 1);
        len--;
      }
      break;
    case 4: /* duplicate a span */
      if (len < MAX_INPUT && len >= 1) {
        size_t span = 1 + rng() % len;
        size_t src = rng() % (len - span + 1);
        size_t at = rng() % (len + 1);
        if (span > MAX_INPUT - len)
          span = MAX_INPUT - len;
        memmove(buf + at + span, buf + at, len - at);
        /* After the shift, a source beyond the insert point moved right. */
        size_t copy_src = (src >= at) ? src + span : src;
        memmove(buf + at, buf + copy_src, span);
        len += span;
      }
      break;
    }
  }
  return len;
}

int main(int argc, char **argv) {
  size_t iters = 200000;
  const char *env;

  if ((env = getenv("FUZZ_ITERS")) != NULL)
    iters = (size_t)strtoull(env, NULL, 0);
  if ((env = getenv("FUZZ_SEED")) != NULL)
    g_rng = strtoull(env, NULL, 0);
  if ((env = getenv("FUZZ_CRASH")) != NULL)
    g_crash_path = env;
  g_corpus_out = getenv("FUZZ_CORPUS_OUT");

  install_crash_handlers();

  for (int i = 1; i < argc; i++) {
    FILE *fp = fopen(argv[i], "rb");
    if (!fp)
      continue;
    uint8_t buf[MAX_INPUT];
    size_t n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    corpus_add(buf, n);
  }
  if (g_corpus_len == 0) {
    static const uint8_t seeds[][8] = {{0},
                                       {0xff},
                                       {1, 2, 3, 4, 5},
                                       {'s', 'e', 'c', 'r', 'e', 't'},
                                       {0x7f, 0, 0, 1},
                                       {0x01, 0x02, 0x03, 0x04, 0x05}};
    for (size_t i = 0; i < sizeof(seeds) / sizeof(seeds[0]); i++)
      corpus_add(seeds[i], sizeof(seeds[i]));
  }

  uint8_t work[MAX_INPUT];
  for (size_t i = 0; i < iters; i++) {
    size_t base = rng() % g_corpus_len;
    size_t len = g_corpus[base].len;
    memcpy(work, g_corpus[base].data, len);
    len = mutate(work, len);

    g_current = work;
    g_current_len = len;
    LLVMFuzzerTestOneInput(work, len);
    g_current = NULL;
    g_current_len = 0;

    if ((i & 255) == 0)
      corpus_add(work, len);
  }

  printf("fuzz_runner: %zu iterations, corpus=%zu\n", iters, g_corpus_len);
  return 0;
}
