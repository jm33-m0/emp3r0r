#include "util/dynload.h"

#include "test.h"

#include <stdint.h>
#include <string.h>

/* Little-endian field writers for the synthetic module below. */
static void put16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v) {
  for (int i = 0; i < 4; i++)
    p[i] = (uint8_t)(v >> (8 * i));
}

static void put64(uint8_t *p, uint64_t v) {
  for (int i = 0; i < 8; i++)
    p[i] = (uint8_t)(v >> (8 * i));
}

/*
 * Minimal valid ET_DYN image: one PT_LOAD covering everything, a PT_DYNAMIC, a
 * SysV hash table and a defined "malloc" symbol at MOD_MALLOC_OFF.
 */
#define MOD_DYN_OFF 0xB0
#define MOD_HASH_OFF 0xF0
#define MOD_SYM_OFF 0x104
#define MOD_STR_OFF 0x134
#define MOD_TOTAL 0x141
#define MOD_MALLOC_OFF 0x70

static size_t build_module(uint8_t *b, size_t cap) {
  if (cap < MOD_TOTAL)
    return 0;
  memset(b, 0, MOD_TOTAL);
  b[0] = 0x7f;
  b[1] = 'E';
  b[2] = 'L';
  b[3] = 'F';
  b[4] = 2;            /* ELFCLASS64 */
  b[5] = 1;            /* ELFDATA2LSB */
  b[6] = 1;            /* EV_CURRENT */
  put16(b + 16, 3);    /* e_type ET_DYN */
  put16(b + 18, 0x3e); /* e_machine x86-64 */
  put32(b + 20, 1);    /* e_version */
  put64(b + 32, 64);   /* e_phoff */
  put16(b + 52, 64);   /* e_ehsize */
  put16(b + 54, 56);   /* e_phentsize */
  put16(b + 56, 2);    /* e_phnum */
  /* phdr[0] PT_LOAD */
  put32(b + 64, 1);
  put32(b + 68, 5);
  put64(b + 96, MOD_TOTAL); /* p_filesz */
  put64(b + 104, MOD_TOTAL);
  put64(b + 112, 0x1000);
  /* phdr[1] PT_DYNAMIC */
  put32(b + 120, 2);
  put32(b + 124, 6);
  put64(b + 128, MOD_DYN_OFF);
  put64(b + 136, MOD_DYN_OFF);
  put64(b + 144, MOD_DYN_OFF);
  put64(b + 152, 64);
  put64(b + 160, 64);
  put64(b + 168, 8);
  /* dynamic array */
  put64(b + MOD_DYN_OFF + 0, 5);
  put64(b + MOD_DYN_OFF + 8, MOD_STR_OFF); /* DT_STRTAB */
  put64(b + MOD_DYN_OFF + 16, 6);
  put64(b + MOD_DYN_OFF + 24, MOD_SYM_OFF); /* DT_SYMTAB */
  put64(b + MOD_DYN_OFF + 32, 4);
  put64(b + MOD_DYN_OFF + 40, MOD_HASH_OFF); /* DT_HASH */
  /* SysV hash: nbucket=1, nchain=2, buckets[0]=1, chains[] */
  put32(b + MOD_HASH_OFF + 0, 1);
  put32(b + MOD_HASH_OFF + 4, 2);
  put32(b + MOD_HASH_OFF + 8, 1);
  /* symtab[1] = malloc */
  put32(b + MOD_SYM_OFF + 24, 1); /* st_name */
  b[MOD_SYM_OFF + 28] = 0x12;     /* st_info GLOBAL FUNC */
  put16(b + MOD_SYM_OFF + 30, 1); /* st_shndx */
  put64(b + MOD_SYM_OFF + 32, MOD_MALLOC_OFF);
  /* strtab */
  memcpy(b + MOD_STR_OFF, "\0malloc\0free\0", 13);
  return MOD_TOTAL;
}

int main(void) {
  /* Real modules resolve through the bounds-checked path, using the trusted
   * mapping range from /proc/self/maps. */
  unsigned long end = 0;
  unsigned long libc = dynload_find_libc(&end);
  CHECK(libc != 0);
  if (libc == 0)
    TEST_DONE();

  CHECK(end > libc);
  size_t llen = (size_t)(end - libc);
  CHECK(dynload_resolve_module((const void *)libc, llen, "malloc") != NULL);
  CHECK(dynload_resolve_module((const void *)libc, llen, "free") != NULL);
  CHECK(dynload_resolve_module((const void *)libc, llen,
                               "no_such_symbol_xyz") == NULL);

  /* /proc/self/maps parser (shared by the file-backed finders and the
   * stager): the module's mapping run spans all of its lines. */
  {
    static const char maps[] =
        "55d0f000-55d10000 r-xp 00000000 08:01 1 /usr/bin/test\n"
        "7f0000000000-7f0000020000 r--p 00000000 08:01 2 /lib/libc.so.6\n"
        "7f0000020000-7f0000200000 r-xp 00020000 08:01 2 /lib/libc.so.6\n"
        "7f0000200000-7f0000204000 r--p 00200000 08:01 2 /lib/libc.so.6\n"
        "7f0000300000-7f0000301000 rw-p 00000000 08:01 3 /lib/libz.so.1\n";
    size_t mlen = sizeof(maps) - 1; /* excludes the trailing NUL */
    unsigned long mend = 0;
    CHECK(dynload_maps_find(maps, mlen, "libc.so", &mend) == 0x7f0000000000UL);
    CHECK(mend == 0x7f0000204000UL);
    CHECK(dynload_maps_find(maps, mlen, "libz.so", &mend) == 0x7f0000300000UL);
    CHECK(dynload_maps_find(maps, mlen, "no_such_lib", &mend) == 0);
    CHECK(dynload_maps_find(NULL, mlen, "libc.so", &mend) == 0);
    CHECK(dynload_maps_find(maps, mlen, NULL, &mend) == 0);
    /* Truncated mid-line, no newline and no NUL. */
    CHECK(dynload_maps_find(maps, 20, "libc.so", &mend) == 0);
  }

  /* Regression: the full path used to be searched for "libc", so an agent
   * named .../glibc-2.17/... was selected as libc. Match the basename only. */
  {
    static const char agent_maps[] =
        "55d0f000-55d10000 r-xp 00000000 08:01 1 "
        "/tmp/c_agent_linux_amd64_exe_glibc-2.17_libcurl_openssl_miniz_"
        "libc-dl_11111111\n"
        "5600f000-56010000 r-xp 00000000 08:01 2 "
        "/tmp/agent_linux_amd64_exe_glibc-2.17_11111111\n";
    size_t alen = sizeof(agent_maps) - 1;
    unsigned long aend = 0;
    CHECK(dynload_maps_find(agent_maps, alen, "libc.so", &aend) == 0);
    CHECK(dynload_maps_find(agent_maps, alen, "libc-", &aend) == 0);
    CHECK(dynload_maps_find(agent_maps, alen, "libc.musl", &aend) == 0);
  }
  {
    static const char libc_dash_maps[] =
        "7f0000000000-7f0000020000 r-xp 00000000 08:01 2 "
        "/lib/x86_64-linux-gnu/libc-2.31.so\n";
    size_t lmlen = sizeof(libc_dash_maps) - 1;
    unsigned long lmend = 0;
    CHECK(dynload_maps_find(libc_dash_maps, lmlen, "libc-", &lmend) ==
          0x7f0000000000UL);
    CHECK(lmend == 0x7f0000020000UL);
  }

  /* A synthetic, fully valid image resolves the defined symbol. */
  uint8_t mod[0x200];
  size_t mn = build_module(mod, sizeof(mod));
  CHECK(mn == MOD_TOTAL);
  CHECK(dynload_resolve_module(mod, mn, "malloc") ==
        (void *)(mod + MOD_MALLOC_OFF));
  CHECK(dynload_resolve_module(mod, mn, "free") == NULL);
  CHECK(dynload_resolve_module(mod, mn, "no_such_symbol_xyz") == NULL);

  /* Malformed images are rejected, never followed out of bounds. */
  CHECK(dynload_resolve_module(NULL, mn, "malloc") == NULL);
  CHECK(dynload_resolve_module(mod, 10, "malloc") == NULL);
  CHECK(dynload_resolve_module(mod, MOD_STR_OFF + 1, "malloc") == NULL);

  mod[1] = 'X'; /* bad magic */
  CHECK(dynload_resolve_module(mod, mn, "malloc") == NULL);
  mod[1] = 'E';

  mod[4] = 1; /* bad class */
  CHECK(dynload_resolve_module(mod, mn, "malloc") == NULL);
  mod[4] = 2;

  put16(mod + 54, 8); /* wrong e_phentsize */
  CHECK(dynload_resolve_module(mod, mn, "malloc") == NULL);
  put16(mod + 54, 56);

  put16(mod + 56, 0); /* no program headers */
  CHECK(dynload_resolve_module(mod, mn, "malloc") == NULL);
  put16(mod + 56, 2);

  put64(mod + 32, 0xffffffff); /* e_phoff past the image */
  CHECK(dynload_resolve_module(mod, mn, "malloc") == NULL);
  put64(mod + 32, 64);

  put64(mod + MOD_DYN_OFF + 8, 0xffffff); /* DT_STRTAB out of range */
  CHECK(dynload_resolve_module(mod, mn, "malloc") == NULL);
  put64(mod + MOD_DYN_OFF + 8, MOD_STR_OFF);
  CHECK(dynload_resolve_module(mod, mn, "malloc") ==
        (void *)(mod + MOD_MALLOC_OFF));

  dynload *dl = dynload_hosted();
  CHECK(dynload_resolve(dl) == 0);
  CHECK(dynload_resolve(dl) == 0); /* idempotent */

  void *h = dynload_open(dl, "libc.so.6", RTLD_NOW | RTLD_LOCAL);
  CHECK(h != NULL);
  CHECK(dynload_sym(dl, h, "malloc") != NULL);
  CHECK(dynload_sym(dl, h, "no_such_symbol_xyz") == NULL);
  CHECK(dynload_close(dl, h) == 0);

  dynload_reset(dl);
  CHECK(dl->open == NULL && dl->sym == NULL && dl->close == NULL);
  CHECK(dynload_resolve(dl) == 0);

  TEST_DONE();
}
