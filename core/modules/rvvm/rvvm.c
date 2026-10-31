/*
 * rvvm.c — loadable RV32IMA interpreter module with a portable BOF loader.
 *
 * The payload is an RV32 relocatable object (ET_REL), i.e. a BOF compiled for
 * RISC-V. The module maps the embedded guest runtime (rv_bof_runtime.o, Beacon
 * API and the libc subset BOFs need), loads and relocates the object against
 * it, and calls the requested export with the packed BOF argument buffer.
 *
 * The interpreter core is the vendored single-header mini-rv32ima
 * (vendor/mini-rv32ima/, MIT). It is used unmodified; this file adapts it to
 * the module ABI:
 *
 *   - maps guest images into a private RV32 arena,
 *   - overrides the memory bus macros with alignment-safe, bounds-checked
 *     accessors,
 *   - implements MMIO host calls (console, block write, exit) and a host-call
 *     mailbox used by the guest runtime for file/process services,
 *   - resolves RV32 ET_REL relocations for BOF payloads,
 *   - enforces an instruction budget and reports guest traps.
 *
 * The images are untrusted: they are never mapped executable and are only
 * ever read through the guest bus helpers. Guest and host meet at the MMIO
 * hooks and the mailbox, which copy from the guest arena with explicit bounds
 * checks.
 *
 * Exported ABI (everything else is hidden):
 *
 *   char *rv_run(const uint8_t *image, size_t len, const char *entry,
 *                const struct rv_bof_args *args);
 *   const char *rv_last_error(void);
 *   int rv_exit_code(void);
 *   void rv_free(char *out);
 *
 * rv_bof_args carries the packed BOF argument block. The module is
 * single-threaded: one call at a time.
 */

#include <stddef.h>
#include <stdint.h>

#include "rv_host.h"

#if defined(_WIN32)
#define RV_EXPORT __declspec(dllexport)
#else
#define RV_EXPORT __attribute__((visibility("default")))
#endif

#ifndef RV_RAM_SIZE
#define RV_RAM_SIZE RV_RAM_SIZE_DEFAULT
#endif

/* Instructions per run. A guest that spins is stopped instead of wedging the
 * agent's job thread. */
#ifndef RV_MAX_INSNS
#define RV_MAX_INSNS (64u << 20)
#endif

#define RV_RAM_END (RV_RAM_BASE + RV_RAM_SIZE)
#define RV_TRAP_PC RV_RAM_END

/* Guest memory layout:
 *   0x80000000  BOF sections (max 512 KiB)
 *   0x80080000  guest runtime (Beacon + libc subset + 1 MiB heap)
 *   0x801ff000  host-call mailbox
 *   0x80800000  stack top
 */
#define RV_BOF_BASE 0x80000000u
#define RV_BOF_MAX 0x00080000u
#define RV_RT_BASE 0x80080000u
#define RV_RT_MAX 0x00180000u
#define RV_LIB_BASE 0x80200000u
#define RV_LIB_STRIDE 0x00180000u
#define RV_LIBS_MAX 3u
#define RV_STACK_RESERVE (128u << 10)

/* Never decode more than this many instructions before checking exit/trap. */
#define RV_CHUNK 4096u

#define RV_OUT_CAP (1u << 20)
#define RV_BOF_ARGS_MAX (1u << 20)

/* MMIO registers: the guest only needs to exit and to ring the host-call
 * doorbell. Everything is inside MINIRV32_MMIO_RANGE. */
#define RV_HC_EXIT 0x10001000u

#define RV_ELFCLASS32 1
#define RV_ELFDATA2LSB 1
#define RV_EV_CURRENT 1
#define RV_ET_REL 1
#define RV_EM_RISCV 243

#define RV_SHT_SYMTAB 2
#define RV_SHT_STRTAB 3
#define RV_SHT_RELA 4
#define RV_SHT_NOBITS 8
#define RV_SHF_ALLOC 0x2
#define RV_SHN_UNDEF 0
#define RV_SHN_ABS 0xfff1
#define RV_SHN_COMMON 0xfff2

#define RV_ELF32_EHDR 52
#define RV_ELF32_SHDR 40
#define RV_ELF32_SYM 16
#define RV_ELF32_RELA 12

#define RV_R_RISCV_NONE 0
#define RV_R_RISCV_32 1
#define RV_R_RISCV_BRANCH 16
#define RV_R_RISCV_JAL 17
#define RV_R_RISCV_CALL 18
#define RV_R_RISCV_CALL_PLT 19
#define RV_R_RISCV_HI20 26
#define RV_R_RISCV_LO12_I 27
#define RV_R_RISCV_LO12_S 28
#define RV_R_RISCV_ALIGN 43
#define RV_R_RISCV_RELAX 51
#define RV_R_RISCV_32_PCREL 57

static void rv_mmio_store(uint32_t addr, uint32_t val);
static uint32_t rv_mmio_load(uint32_t addr);

/* Delivered RISC-V libraries (module companion files, memfs only). */
struct rv_lib {
  const uint8_t *buf;
  size_t len;
};

/* Keep this layout in sync with core/c_agent/src/rvvm.c and the Go runner. */
struct rv_bof_args {
  const uint8_t *buf; /* packed COFF argument buffer */
  size_t len;
  const struct rv_lib *libs;
  size_t nlibs;
};

/* Guest runtime linked at RV_RT_BASE, generated into rv_bof_runtime_blob.c
 * by the Makefile (a C array, not .incbin, so the compiler cache sees the
 * dependency when the runtime changes). */
extern const uint8_t rv_bof_runtime_image[];
extern const unsigned int rv_bof_runtime_image_len;

static uint8_t rv_ram[RV_RAM_SIZE + 8] __attribute__((aligned(16)));
static char rv_out[RV_OUT_CAP];
static size_t rv_out_len;
static char rv_err[160];
static int rv_guest_status;
static int rv_stopped;
static int rv_bad_bus;

static void rv_memzero(void *dst, size_t n);
static void rv_memcpy(void *dst, const void *src, size_t n);

/* Per-run bump arena for loader symbol tables. Keeping the loader free of
 * malloc/free lets the same code build against the Win32 API without libc. */
#define RV_ARENA_SIZE (256u << 10)
static uint8_t rv_arena[RV_ARENA_SIZE] __attribute__((aligned(16)));
static size_t rv_arena_used;

static void *rv_alloc(size_t n) {
  size_t aligned = (n + 15u) & ~(size_t)15u;
  if (aligned < n || rv_arena_used + aligned > RV_ARENA_SIZE) {
    rv_set_err("out of memory");
    return NULL;
  }
  void *p = rv_arena + rv_arena_used;
  rv_memzero(p, aligned);
  rv_arena_used += aligned;
  return p;
}

void rv_set_err(const char *msg) {
  size_t i = 0;
  if (rv_err[0] != '\0')
    return;
  while (msg[i] != '\0' && i < sizeof(rv_err) - 1) {
    rv_err[i] = msg[i];
    i++;
  }
  rv_err[i] = '\0';
}

int rv_out_append(const void *data, size_t len) {
  if (len > RV_OUT_CAP - 1u - rv_out_len) {
    rv_set_err("output limit reached");
    rv_stopped = 1;
    return -1;
  }
  if (len > 0)
    rv_memcpy(rv_out + rv_out_len, data, len);
  rv_out_len += len;
  rv_out[rv_out_len] = '\0';
  return 0;
}

/* Local byte helpers. The module imports libc only for host services; keeping
 * the guest copy/zero paths free of libc means a loader that resolves memcpy
 * or memset through an IFUNC resolver cannot corrupt guest images. */
static void rv_memzero(void *dst, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  for (size_t i = 0; i < n; i++)
    d[i] = 0;
}

static void rv_memcpy(void *dst, const void *src, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  const unsigned char *s = (const unsigned char *)src;
  for (size_t i = 0; i < n; i++)
    d[i] = s[i];
}

/* ---- guest memory bus ---------------------------------------------------- */
/* mini-rv32ima bounds-checks data accesses before calling these, but the
 * instruction fetch only checks `ofs < RAM_SIZE`, so the helpers check again
 * and latch a fault instead of reading past the arena. Byte-wise access keeps
 * unaligned guest loads legal and avoids host alignment UB. */

static int rv_in_ram(uint32_t off, uint32_t n) {
  return off <= RV_RAM_SIZE && n <= RV_RAM_SIZE - off;
}

static uint8_t rv_rd8(uint32_t off) {
  if (!rv_in_ram(off, 1)) {
    rv_bad_bus = 1;
    return 0;
  }
  return rv_ram[off];
}

static uint16_t rv_rd16(uint32_t off) {
  if (!rv_in_ram(off, 2)) {
    rv_bad_bus = 1;
    return 0;
  }
  return (uint16_t)(rv_ram[off] | ((uint16_t)rv_ram[off + 1] << 8));
}

static uint32_t rv_rd32(uint32_t off) {
  if (!rv_in_ram(off, 4)) {
    rv_bad_bus = 1;
    return 0;
  }
  return (uint32_t)rv_ram[off] | ((uint32_t)rv_ram[off + 1] << 8) |
         ((uint32_t)rv_ram[off + 2] << 16) | ((uint32_t)rv_ram[off + 3] << 24);
}

static void rv_wr8(uint32_t off, uint8_t v) {
  if (!rv_in_ram(off, 1)) {
    rv_bad_bus = 1;
    return;
  }
  rv_ram[off] = v;
}

static void rv_wr16(uint32_t off, uint16_t v) {
  if (!rv_in_ram(off, 2)) {
    rv_bad_bus = 1;
    return;
  }
  rv_ram[off] = (uint8_t)v;
  rv_ram[off + 1] = (uint8_t)(v >> 8);
}

static void rv_wr32(uint32_t off, uint32_t v) {
  if (!rv_in_ram(off, 4)) {
    rv_bad_bus = 1;
    return;
  }
  rv_ram[off] = (uint8_t)v;
  rv_ram[off + 1] = (uint8_t)(v >> 8);
  rv_ram[off + 2] = (uint8_t)(v >> 16);
  rv_ram[off + 3] = (uint8_t)(v >> 24);
}

/* Map a validated guest address to a host pointer inside rv_ram. */
uint8_t *rv_gptr(uint32_t addr, uint32_t len) {
  if (addr < RV_RAM_BASE || !rv_in_ram(addr - RV_RAM_BASE, len))
    return NULL;
  return rv_ram + (addr - RV_RAM_BASE);
}

/* Copy a NUL-terminated guest string into a host buffer. */
int rv_guest_cstr(uint32_t addr, char *out, size_t cap) {
  if (cap == 0)
    return -1;
  for (size_t i = 0; i < cap; i++) {
    uint8_t *p = rv_gptr(addr + (uint32_t)i, 1);
    if (p == NULL)
      return -1;
    out[i] = (char)*p;
    if (out[i] == '\0')
      return 0;
  }
  out[cap - 1] = '\0';
  return -1;
}

static void rv_mmio_store(uint32_t addr, uint32_t val) {
  switch (addr) {
  case RV_HC_EXIT:
    rv_guest_status = (int)val;
    rv_stopped = 1;
    return;
  case RV_HC_DOORBELL:
    if (val == RV_HC_MAGIC)
      rv_host_dispatch((struct rv_hc_req *)(rv_ram + RV_HC_OFFSET));
    else
      rv_set_err("bad host-call magic");
    return;
  default:
    rv_set_err("bad mmio store");
    rv_stopped = 1;
    return;
  }
}

static uint32_t rv_mmio_load(uint32_t addr) {
  (void)addr;
  rv_set_err("bad mmio load");
  rv_stopped = 1;
  return 0;
}

/* ---- interpreter core (vendored, unmodified) ----------------------------- */

#define MINI_RV32_RAM_SIZE RV_RAM_SIZE
#define MINIRV32_RAM_IMAGE_OFFSET RV_RAM_BASE
#define MINIRV32WARN(...) ((void)0)
#define MINIRV32_HANDLE_MEM_STORE_CONTROL(a, v)                                \
  rv_mmio_store((uint32_t)(a), (uint32_t)(v))
#define MINIRV32_HANDLE_MEM_LOAD_CONTROL(a, v)                                 \
  ((v) = rv_mmio_load((uint32_t)(a)))
#define MINIRV32_CUSTOM_MEMORY_BUS 1
#define MINIRV32_STORE1(ofs, val) rv_wr8((uint32_t)(ofs), (uint8_t)(val))
#define MINIRV32_STORE2(ofs, val) rv_wr16((uint32_t)(ofs), (uint16_t)(val))
#define MINIRV32_STORE4(ofs, val) rv_wr32((uint32_t)(ofs), (uint32_t)(val))
#define MINIRV32_LOAD1(ofs) rv_rd8((uint32_t)(ofs))
#define MINIRV32_LOAD2(ofs) rv_rd16((uint32_t)(ofs))
#define MINIRV32_LOAD4(ofs) rv_rd32((uint32_t)(ofs))
#define MINIRV32_LOAD1_SIGNED(ofs) ((int8_t)rv_rd8((uint32_t)(ofs)))
#define MINIRV32_LOAD2_SIGNED(ofs) ((int16_t)rv_rd16((uint32_t)(ofs)))
#define MINIRV32_POSTEXEC(pc, ir, trap) ((void)0)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#define MINIRV32_IMPLEMENTATION
#include "vendor/mini-rv32ima/mini-rv32ima.h"
#pragma GCC diagnostic pop

/* ---- ELF helpers --------------------------------------------------------- */

static uint16_t rv_le16(const uint8_t *p) {
  return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rv_le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static int rv_range_ok(size_t off, size_t len, size_t total) {
  return off <= total && len <= total - off;
}

static int rv_elf_header_ok(const uint8_t *img, size_t len) {
  if (len < RV_ELF32_EHDR) {
    rv_set_err("image too small");
    return 0;
  }
  if (img[0] != 0x7f || img[1] != 'E' || img[2] != 'L' || img[3] != 'F') {
    rv_set_err("not an ELF image");
    return 0;
  }
  if (img[4] != RV_ELFCLASS32 || img[5] != RV_ELFDATA2LSB ||
      img[6] != RV_EV_CURRENT) {
    rv_set_err("not a little-endian ELF32 image");
    return 0;
  }
  if (rv_le16(img + 16) != RV_ET_REL) {
    rv_set_err("not a relocatable object");
    return 0;
  }
  if (rv_le16(img + 18) != RV_EM_RISCV) {
    rv_set_err("not a RISC-V image");
    return 0;
  }
  return 1;
}

/* ---- ET_REL (BOF) loader ------------------------------------------------- */

struct rv_rt_sym {
  const char *name;
  size_t len;
  uint32_t value;
};

struct rv_sec {
  uint32_t addr;
  uint32_t size;
  uint32_t align;
  uint32_t offset;
  uint32_t type;
  uint32_t flags;
};

struct rv_obj {
  const uint8_t *img;
  size_t len;
  uint32_t shoff;
  uint16_t shnum;
  struct rv_sec *secs;
  uint32_t *symval;
  size_t nsym;
  const uint8_t *symtab;
  size_t symtab_size;
  const uint8_t *strtab;
  size_t strtab_size;
};

static uint32_t rv_align_up(uint32_t v, uint32_t a) {
  if (a <= 1)
    return v;
  return (v + a - 1) & ~(a - 1);
}

/* Compare two bounded names (no assumption about NUL terminators). */
static int rv_name_eq(const char *a, size_t alen, const char *b, size_t blen) {
  if (alen != blen)
    return 0;
  for (size_t i = 0; i < alen; i++) {
    if (a[i] != b[i])
      return 0;
  }
  return 1;
}

/* Length of a name within `avail` bytes, stopping at NUL. */
static size_t rv_name_len(const char *s, size_t avail) {
  size_t n = 0;
  while (n < avail && s[n] != '\0')
    n++;
  return n;
}

/* Strip the Windows BOF module prefix (KERNEL32$VirtualAlloc -> VirtualAlloc). */
static const char *rv_strip_module(const char *name, size_t avail,
                                   size_t *out) {
  for (size_t i = 0; i < avail; i++) {
    if (name[i] == '$' && i + 1 < avail) {
      *out = avail - i - 1;
      return name + i + 1;
    }
  }
  *out = avail;
  return name;
}

/* Place an ET_REL object's SHF_ALLOC sections at `base`. Fills defined symbol
 * values; undefined symbols are left for rv_obj_resolve. */
static int rv_obj_place(const uint8_t *img, size_t len, uint32_t base,
                        uint32_t max, struct rv_obj *o, size_t *globals) {
  rv_memzero(o, sizeof(*o));
  *globals = 0;
  if (!rv_elf_header_ok(img, len))
    return -1;

  uint32_t shoff = rv_le32(img + 32);
  uint16_t shentsize = rv_le16(img + 46);
  uint16_t shnum = rv_le16(img + 48);
  if (shnum == 0 || shnum > 128 || shentsize != RV_ELF32_SHDR ||
      !rv_range_ok(shoff, (size_t)shnum * RV_ELF32_SHDR, len)) {
    rv_set_err("bad section headers");
    return -1;
  }

  o->img = img;
  o->len = len;
  o->shoff = shoff;
  o->shnum = shnum;
  o->secs = (struct rv_sec *)rv_alloc((size_t)shnum * sizeof(*o->secs));
  if (o->secs == NULL)
    return -1;

  uint32_t cur = base;
  for (uint16_t i = 0; i < shnum; i++) {
    const uint8_t *sh = img + shoff + (size_t)i * RV_ELF32_SHDR;
    struct rv_sec *sc = &o->secs[i];
    sc->type = rv_le32(sh + 4);
    sc->flags = rv_le32(sh + 8);
    sc->offset = rv_le32(sh + 16);
    sc->size = rv_le32(sh + 20);
    sc->align = rv_le32(sh + 32);
    if (!(sc->flags & RV_SHF_ALLOC) || sc->size == 0)
      continue;
    if (sc->align > 16 || (sc->align & (sc->align - 1)) != 0) {
      rv_set_err("bad section alignment");
      return -1;
    }
    cur = rv_align_up(cur, sc->align);
    if (cur < base || (uint64_t)cur + sc->size > (uint64_t)base + max) {
      rv_set_err("image does not fit in guest RAM");
      return -1;
    }
    sc->addr = cur;
    if (sc->type != RV_SHT_NOBITS) {
      if (!rv_range_ok(sc->offset, sc->size, len)) {
        rv_set_err("bad section payload");
        return -1;
      }
      rv_memcpy(rv_ram + (cur - RV_RAM_BASE), img + sc->offset, sc->size);
    }
    cur += sc->size;
  }

  const uint8_t *symtab = NULL;
  size_t symtab_size = 0;
  const uint8_t *strtab = NULL;
  size_t strtab_size = 0;
  for (uint16_t i = 0; i < shnum; i++) {
    const uint8_t *sh = img + shoff + (size_t)i * RV_ELF32_SHDR;
    if (rv_le32(sh + 4) != RV_SHT_SYMTAB)
      continue;
    uint32_t link = rv_le32(sh + 24);
    uint32_t off = rv_le32(sh + 16);
    uint32_t size = rv_le32(sh + 20);
    if (link >= shnum || !rv_range_ok(off, size, len))
      continue;
    const uint8_t *lsh = img + shoff + (size_t)link * RV_ELF32_SHDR;
    if (rv_le32(lsh + 4) != RV_SHT_STRTAB)
      continue;
    uint32_t soff = rv_le32(lsh + 16);
    uint32_t ssize = rv_le32(lsh + 20);
    if (!rv_range_ok(soff, ssize, len))
      continue;
    symtab = img + off;
    symtab_size = size;
    strtab = img + soff;
    strtab_size = ssize;
    break;
  }
  if (symtab == NULL || symtab_size == 0 || symtab_size % RV_ELF32_SYM != 0) {
    rv_set_err("object has no symbol table");
    return -1;
  }
  o->symtab = symtab;
  o->symtab_size = symtab_size;
  o->strtab = strtab;
  o->strtab_size = strtab_size;
  o->nsym = symtab_size / RV_ELF32_SYM;
  o->symval = (uint32_t *)rv_alloc(o->nsym * sizeof(*o->symval));
  if (o->symval == NULL)
    return -1;

  for (size_t i = 1; i < o->nsym; i++) {
    const uint8_t *sym = symtab + i * RV_ELF32_SYM;
    uint32_t value = rv_le32(sym + 4);
    uint16_t shndx = rv_le16(sym + 14);
    uint8_t info = sym[12];
    if (shndx == RV_SHN_UNDEF)
      continue;
    if (shndx == RV_SHN_ABS) {
      o->symval[i] = value;
    } else if (shndx == RV_SHN_COMMON) {
      rv_set_err("common symbols are not supported");
      return -1;
    } else if (shndx < shnum && o->secs[shndx].addr != 0) {
      o->symval[i] = o->secs[shndx].addr + value;
    } else {
      o->symval[i] = 0;
      continue;
    }
    unsigned bind = info >> 4;
    if (o->symval[i] != 0 && (bind == 1 || bind == 2) && rv_le32(sym) != 0)
      (*globals)++;
  }
  return 0;
}
static int rv_obj_add_symbols(const struct rv_obj *o, struct rv_rt_sym *tab,
                              size_t cap, size_t *used) {
  for (size_t i = 1; i < o->nsym; i++) {
    if (o->symval[i] == 0)
      continue;
    const uint8_t *sym = o->symtab + i * RV_ELF32_SYM;
    uint32_t name = rv_le32(sym);
    uint8_t info = sym[12];
    unsigned bind = info >> 4;
    if (name == 0 || (bind != 1 && bind != 2))
      continue;
    if (name >= o->strtab_size)
      continue;
    if (*used >= cap) {
      rv_set_err("too many symbols");
      return -1;
    }
    tab[*used].name = (const char *)(o->strtab + name);
    tab[*used].len = rv_name_len(tab[*used].name, o->strtab_size - name);
    tab[*used].value = o->symval[i];
    (*used)++;
  }
  return 0;
}

static int rv_obj_resolve(struct rv_obj *o, const struct rv_rt_sym *tab,
                          size_t n) {
  for (size_t i = 1; i < o->nsym; i++) {
    const uint8_t *sym = o->symtab + i * RV_ELF32_SYM;
    uint16_t shndx = rv_le16(sym + 14);
    if (shndx != RV_SHN_UNDEF)
      continue;
    uint32_t name = rv_le32(sym);
    if (name >= o->strtab_size) {
      rv_set_err("bad symbol name");
      return -1;
    }
    const char *sname = (const char *)(o->strtab + name);
    size_t left = o->strtab_size - name;
    const char *lookup = rv_strip_module(sname, left, &left);
    left = rv_name_len(lookup, left);
    int found = 0;
    for (size_t k = 0; k < n; k++) {
      if (rv_name_eq(lookup, left, tab[k].name, tab[k].len)) {
        o->symval[i] = tab[k].value;
        found = 1;
        break;
      }
    }
    if (!found) {
      char msg[160];
      size_t p = 0;
      static const char prefix[] = "unresolved symbol ";
      for (size_t k = 0; k < sizeof(prefix) - 1; k++)
        msg[p++] = prefix[k];
      for (size_t k = 0; k < left && p < sizeof(msg) - 1; k++) {
        if (lookup[k] == '\0')
          break;
        msg[p++] = lookup[k];
      }
      msg[p] = '\0';
      rv_set_err(msg);
      return -1;
    }
  }
  return 0;
}

static int rv_obj_reloc(struct rv_obj *o) {
  for (uint16_t i = 0; i < o->shnum; i++) {
    const uint8_t *sh = o->img + o->shoff + (size_t)i * RV_ELF32_SHDR;
    if (rv_le32(sh + 4) != RV_SHT_RELA)
      continue;
    uint32_t target = rv_le32(sh + 28);
    uint32_t off = rv_le32(sh + 16);
    uint32_t size = rv_le32(sh + 20);
    if (target >= o->shnum || o->secs[target].addr == 0)
      continue;
    if (size % RV_ELF32_RELA != 0 || !rv_range_ok(off, size, o->len)) {
      rv_set_err("bad relocation section");
      return -1;
    }
    for (uint32_t r = 0; r < size; r += RV_ELF32_RELA) {
      const uint8_t *rel = o->img + off + r;
      uint32_t r_off = rv_le32(rel);
      uint32_t info = rv_le32(rel + 4);
      int32_t addend = (int32_t)rv_le32(rel + 8);
      uint32_t type = info & 0xffu;
      uint32_t sym = info >> 8;
      if (sym >= o->nsym) {
        rv_set_err("bad relocation symbol");
        return -1;
      }
      if (r_off > o->secs[target].size || o->secs[target].size - r_off < 4) {
        rv_set_err("relocation outside section");
        return -1;
      }
      uint32_t P = o->secs[target].addr + r_off;
      uint32_t S = o->symval[sym];
      uint32_t A = (uint32_t)addend;
      uint32_t V = S + A;
      uint32_t pcrel = V - P;
      uint32_t insn, hi, lo;

      switch (type) {
      case RV_R_RISCV_NONE:
      case RV_R_RISCV_RELAX:
      case RV_R_RISCV_ALIGN:
        break;
      case RV_R_RISCV_32:
        rv_wr32(P - RV_RAM_BASE, V);
        break;
      case RV_R_RISCV_32_PCREL:
        rv_wr32(P - RV_RAM_BASE, pcrel);
        break;
      case RV_R_RISCV_HI20:
        insn = rv_rd32(P - RV_RAM_BASE);
        hi = ((V + 0x800u) >> 12) & 0xfffffu;
        rv_wr32(P - RV_RAM_BASE, (insn & 0xfffu) | (hi << 12));
        break;
      case RV_R_RISCV_LO12_I:
        insn = rv_rd32(P - RV_RAM_BASE);
        lo = V & 0xfffu;
        rv_wr32(P - RV_RAM_BASE, (insn & 0xfffffu) | (lo << 20));
        break;
      case RV_R_RISCV_LO12_S:
        insn = rv_rd32(P - RV_RAM_BASE);
        lo = V & 0xfffu;
        rv_wr32(P - RV_RAM_BASE, (insn & ~0xfe000f80u) | ((lo & 0xfe0u) << 20) |
                                     ((lo & 0x1fu) << 7));
        break;
      case RV_R_RISCV_CALL:
      case RV_R_RISCV_CALL_PLT:
        if (o->secs[target].size - r_off < 8) {
          rv_set_err("relocation outside section");
          return -1;
        }
        insn = rv_rd32(P - RV_RAM_BASE);
        hi = ((pcrel + 0x800u) >> 12) & 0xfffffu;
        rv_wr32(P - RV_RAM_BASE, (insn & 0xfffu) | (hi << 12));
        insn = rv_rd32((P + 4) - RV_RAM_BASE);
        lo = pcrel & 0xfffu;
        rv_wr32((P + 4) - RV_RAM_BASE, (insn & 0xfffffu) | (lo << 20));
        break;
      case RV_R_RISCV_BRANCH:
        insn = rv_rd32(P - RV_RAM_BASE);
        rv_wr32(P - RV_RAM_BASE,
                (insn & ~0xfe000f80u) | (((pcrel >> 12) & 1u) << 31) |
                    (((pcrel >> 5) & 0x3fu) << 25) |
                    (((pcrel >> 1) & 0xfu) << 8) | (((pcrel >> 11) & 1u) << 7));
        break;
      case RV_R_RISCV_JAL:
        insn = rv_rd32(P - RV_RAM_BASE);
        rv_wr32(P - RV_RAM_BASE, (insn & 0xfffu) |
                                     (((pcrel >> 20) & 1u) << 31) |
                                     (((pcrel >> 1) & 0x3ffu) << 21) |
                                     (((pcrel >> 11) & 1u) << 20) |
                                     (((pcrel >> 12) & 0xffu) << 12));
        break;
      default: {
        char msg[64];
        size_t p = 0;
        static const char prefix[] = "unsupported relocation type ";
        for (size_t k = 0; k < sizeof(prefix) - 1; k++)
          msg[p++] = prefix[k];
        char num[12];
        int n = 0;
        unsigned v = type;
        do {
          num[n++] = (char)('0' + v % 10);
          v /= 10;
        } while (v != 0 && n < (int)sizeof(num));
        while (n > 0 && p < sizeof(msg) - 1)
          msg[p++] = num[--n];
        msg[p] = '\0';
        rv_set_err(msg);
        return -1;
      }
      }
    }
  }
  return 0;
}

static uint32_t rv_obj_find(const struct rv_obj *o, const char *name) {
  size_t nlen = 0;
  while (name[nlen] != '\0')
    nlen++;
  for (size_t i = 1; i < o->nsym; i++) {
    if (o->symval[i] == 0)
      continue;
    const uint8_t *sym = o->symtab + i * RV_ELF32_SYM;
    uint32_t name_off = rv_le32(sym);
    if (name_off >= o->strtab_size)
      continue;
    const char *sname = (const char *)(o->strtab + name_off);
    size_t slen = rv_name_len(sname, o->strtab_size - name_off);
    if (rv_name_eq(sname, slen, name, nlen))
      return o->symval[i];
  }
  return 0;
}

static const char *rv_trap_name(uint32_t cause) {
  switch (cause) {
  case 0:
    return "instruction address misaligned";
  case 1:
    return "instruction access fault";
  case 2:
    return "illegal instruction";
  case 3:
    return "breakpoint";
  case 5:
    return "load access fault";
  case 7:
    return "store access fault";
  case 8:
    return "environment call from U-mode";
  case 11:
    return "environment call from M-mode";
  default:
    return "guest trap";
  }
}

static int rv_run_state(struct MiniRV32IMAState *state) {
  uint32_t remaining = RV_MAX_INSNS;
  while (remaining > 0 && !rv_stopped && rv_err[0] == '\0') {
    uint32_t n = remaining < RV_CHUNK ? remaining : RV_CHUNK;
    (void)MiniRV32IMAStep(state, rv_ram, 0, 0, (int)n);
    remaining -= n;

    if (rv_bad_bus) {
      rv_set_err("guest memory access out of range");
      return -1;
    }
    if (state->pc == RV_TRAP_PC) {
      char msg[96];
      size_t p = 0;
      const char *name = rv_trap_name(state->mcause);
      while (name[p] != '\0' && p < sizeof(msg) - 16)
        msg[p] = name[p], p++;
      static const char at[] = " at 0x";
      for (size_t k = 0; k < sizeof(at) - 1; k++)
        msg[p++] = at[k];
      static const char hex[] = "0123456789abcdef";
      for (int shift = 28; shift >= 0; shift -= 4)
        msg[p++] = hex[(state->mepc >> shift) & 0xf];
      msg[p] = '\0';
      rv_set_err(msg);
      return -1;
    }
  }
  if (rv_err[0] != '\0')
    return -1;
  if (remaining == 0 && !rv_stopped) {
    rv_set_err("instruction budget exceeded");
    return -1;
  }
  return 0;
}

static void rv_reset(void) {
  rv_out_len = 0;
  rv_out[0] = '\0';
  rv_err[0] = '\0';
  rv_guest_status = 0;
  rv_stopped = 0;
  rv_bad_bus = 0;
  rv_host_reset();
  rv_arena_used = 0;
  rv_memzero(rv_ram, sizeof(rv_ram));
}

/* Run an ET_REL BOF: load the embedded runtime and any delivered RISC-V
 * libraries, relocate everything as one image, then call the runtime's
 * rv_bof_invoke(entry, args, len). */
static int rv_run_bof(const uint8_t *image, size_t len, const char *entry_name,
                      const struct rv_bof_args *args) {
  static struct MiniRV32IMAState state;
  struct rv_obj runtime_obj;
  struct rv_obj bof_obj;
  struct rv_obj *libs = NULL;
  size_t nlibs = args != NULL ? args->nlibs : 0;
  struct rv_rt_sym *tab = NULL;
  size_t ntab = 0, ntab_cap = 0, used = 0;
  uint32_t args_ptr = 0;
  uint32_t entry = 0;
  uint32_t invoke;

  if (nlibs > RV_LIBS_MAX) {
    rv_set_err("too many RISC-V libraries");
    return -1;
  }
  if (nlibs > 0 && args->libs == NULL) {
    rv_set_err("bad RISC-V library list");
    return -1;
  }
  if (entry_name == NULL || entry_name[0] == '\0')
    entry_name = "go";

  if (rv_obj_place(rv_bof_runtime_image, rv_bof_runtime_image_len, RV_RT_BASE,
                   RV_RT_MAX, &runtime_obj, &ntab_cap) != 0)
    return -1;

  if (nlibs > 0) {
    libs = (struct rv_obj *)rv_alloc(nlibs * sizeof(*libs));
    if (libs == NULL)
      return -1;
    for (size_t i = 0; i < nlibs; i++) {
      size_t g = 0;
      if (args->libs[i].len == 0 || args->libs[i].buf == NULL) {
        rv_set_err("bad RISC-V library image");
        return -1;
      }
      if (rv_obj_place(args->libs[i].buf, args->libs[i].len,
                       RV_LIB_BASE + (uint32_t)i * RV_LIB_STRIDE, RV_LIB_STRIDE,
                       &libs[i], &g) != 0)
        return -1;
      ntab_cap += g;
    }
  }

  if (rv_obj_place(image, len, RV_BOF_BASE, RV_BOF_MAX, &bof_obj, &used) != 0)
    return -1;
  ntab_cap += used;

  tab = (struct rv_rt_sym *)rv_alloc(ntab_cap * sizeof(*tab));
  if (tab == NULL)
    return -1;
  used = 0;
  if (rv_obj_add_symbols(&runtime_obj, tab, ntab_cap, &used) != 0)
    return -1;
  for (size_t i = 0; i < nlibs; i++) {
    if (rv_obj_add_symbols(&libs[i], tab, ntab_cap, &used) != 0)
      return -1;
  }
  ntab = used;

  if (rv_obj_resolve(&runtime_obj, tab, ntab) != 0 ||
      rv_obj_reloc(&runtime_obj) != 0)
    return -1;
  for (size_t i = 0; i < nlibs; i++) {
    if (rv_obj_resolve(&libs[i], tab, ntab) != 0 || rv_obj_reloc(&libs[i]) != 0)
      return -1;
  }
  if (rv_obj_resolve(&bof_obj, tab, ntab) != 0 || rv_obj_reloc(&bof_obj) != 0)
    return -1;

  invoke = rv_obj_find(&runtime_obj, "rv_bof_invoke");
  if (invoke == 0) {
    rv_set_err("guest runtime has no entry trampoline");
    return -1;
  }
  entry = rv_obj_find(&bof_obj, entry_name);
  if (entry == 0) {
    rv_set_err("BOF export not found");
    return -1;
  }

  if (args != NULL && args->len > 0) {
    if (args->buf == NULL || args->len > RV_BOF_ARGS_MAX) {
      rv_set_err("bad BOF argument block");
      return -1;
    }
    uint32_t top = RV_RAM_END - RV_STACK_RESERVE;
    args_ptr = (top - (uint32_t)args->len) & ~15u;
    uint32_t floor = RV_LIB_BASE + (uint32_t)nlibs * RV_LIB_STRIDE;
    if (args_ptr < floor) {
      rv_set_err("BOF arguments do not fit in guest RAM");
      return -1;
    }
    rv_memcpy(rv_ram + (args_ptr - RV_RAM_BASE), args->buf, args->len);
  }

  rv_memzero(&state, sizeof(state));
  state.pc = invoke;
  state.regs[2] = RV_RAM_END - 16;
  state.regs[10] = entry;    /* a0 = entry function */
  state.regs[11] = args_ptr; /* a1 = packed args */
  state.regs[12] = args != NULL ? (uint32_t)args->len : 0; /* a2 */
  state.mtvec = RV_TRAP_PC;
  state.extraflags = 3; /* machine mode */

  return rv_run_state(&state);
}

RV_EXPORT char *rv_run(const uint8_t *image, size_t len, const char *entry,
                       const struct rv_bof_args *args) {
  rv_reset();

  if (image == NULL || len == 0) {
    rv_set_err("empty image");
    return NULL;
  }
  if (rv_run_bof(image, len, entry, args) != 0)
    return NULL;
  return rv_out;
}

RV_EXPORT const char *rv_last_error(void) {
  return rv_err;
}

RV_EXPORT int rv_exit_code(void) {
  return rv_guest_status;
}

RV_EXPORT void rv_free(char *out) {
  (void)out; /* the output buffer is static */
}
