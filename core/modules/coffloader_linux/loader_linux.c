#define _GNU_SOURCE
#include <elf.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "beacon_compat.h"

static int set_err(char **err_out, const char *msg) {
  if (!err_out || *err_out) {
    return -1;
  }
  size_t len = strlen(msg) + 1;
  *err_out = (char *)malloc(len);
  if (!*err_out) {
    return -1;
  }
  memcpy(*err_out, msg, len);
  return -1;
}

static int set_errf(char **err_out, const char *fmt, ...) {
  if (!err_out || *err_out) {
    return -1;
  }
  va_list ap;
  va_start(ap, fmt);
  int needed = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);

  if (needed < 0) {
    return set_err(err_out, "format error");
  }

  *err_out = (char *)malloc((size_t)needed + 1);
  if (!*err_out) {
    return -1;
  }

  va_start(ap, fmt);
  vsnprintf(*err_out, (size_t)needed + 1, fmt, ap);
  va_end(ap);

  return -1;
}

static uint64_t align_up(uint64_t val, uint64_t align) {
  if (align <= 1) {
    return val;
  }
  return (val + align - 1) & ~(align - 1);
}

/* True when [off, off+len) lies inside a buffer of `total` bytes. */
static int range_ok(uint64_t off, uint64_t len, size_t total) {
  return off <= (uint64_t)total && len <= (uint64_t)total - off;
}

/* Upper bound for the mapped image. BOFs are small; a crafted object with a
 * huge NOBITS section must not be able to reserve an arbitrary mapping. */
#define BOF_IMAGE_MAX (64u << 20)

/* True when a NUL-terminated string at `off` terminates within the table. */
static int cstr_ok(const char *base, size_t total, uint64_t off) {
  if (base == NULL || off >= (uint64_t)total) {
    return 0;
  }
  return memchr(base + off, 0, total - (size_t)off) != NULL;
}

// Serialize BOF execution and protect signal handler state. A byte-sized
// atomic keeps the image free of a libpthread dependency, which the in-memory
// loader does not provide on glibc < 2.34.
static volatile int bof_lock;

static void bof_lock_acquire(void) {
  while (__atomic_exchange_n(&bof_lock, 1, __ATOMIC_ACQUIRE)) {
    while (__atomic_load_n(&bof_lock, __ATOMIC_RELAXED)) {
    }
  }
}

static void bof_lock_release(void) {
  __atomic_store_n(&bof_lock, 0, __ATOMIC_RELEASE);
}

// Saved signal handlers
static struct sigaction old_sa[32];
static int handled_sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE};
#define NUM_HANDLED_SIGS (sizeof(handled_sigs) / sizeof(handled_sigs[0]))

// Crash-recovery state. bof_run serializes every execution with bof_lock, so
// a single (non-TLS) slot is enough; avoiding __thread keeps the image free of
// the dynamic TLS relocations the Go agent's in-memory loader cannot apply.
static sigjmp_buf bof_env;
static volatile sig_atomic_t is_in_bof = 0;

static void bof_signal_handler(int sig, siginfo_t *info, void *ctx) {
  if (is_in_bof) {
    siglongjmp(bof_env, 1);
  }

  // Chain to original handler if not in BOF or if handler exists
  // Note: We only save old_sa when we take the lock.
  // Since we are in the handler, we assume old_sa is valid for the chained
  // call.
  if (sig >= 0 && sig < 32) {
    if (old_sa[sig].sa_flags & SA_SIGINFO) {
      if (old_sa[sig].sa_sigaction)
        old_sa[sig].sa_sigaction(sig, info, ctx);
    } else {
      if (old_sa[sig].sa_handler != SIG_IGN &&
          old_sa[sig].sa_handler != SIG_DFL)
        old_sa[sig].sa_handler(sig);
      else if (old_sa[sig].sa_handler == SIG_DFL) {
        // If default, we need to unblock and re-raise or let it crash.
        // Ideally we restore specific handler and raise.
        // For now, minimal implementation: do nothing implies return/ignore?
        // No, SIGSEGV return won't fix cause.
        // But since we are here, likely Go Runtime installed a handler.
      }
    }
  }
}

enum {
  BOF_SEG_RX = 0, /* executable */
  BOF_SEG_RO,     /* read-only data */
  BOF_SEG_RW,     /* writable data */
  BOF_SEG_COUNT
};

static int bof_seg_for(const Elf64_Shdr *sh) {
  if (sh->sh_flags & SHF_EXECINSTR)
    return BOF_SEG_RX;
  if (sh->sh_flags & SHF_WRITE)
    return BOF_SEG_RW;
  return BOF_SEG_RO;
}

// bof_run_impl loads an x86_64 ELF ET_REL object and executes the requested
// symbol. It is internal; the exported Run() wraps it with a stable,
// machine-callable ABI (see below).
//
// Sections are packed into three page-aligned segments by protection (RX, R,
// RW), like a normal shared object, instead of one page per section. That keeps
// the mapping compact, gives it ordinary segment boundaries, and guarantees
// there is never a writable and executable mapping.
static int bof_run_impl(const uint8_t *obj_buf, size_t object_size,
                        const char *func_name, const uint8_t *args_buf,
                        int args_len, char **out_buf, char **err_buf) {

  uint8_t *mem_base = NULL;
  uintptr_t *sec_offsets = NULL;
  uint64_t total_size = 0;

  // Serialize access
  bof_lock_acquire();

  if (!obj_buf || object_size < sizeof(Elf64_Ehdr)) {
    set_err(err_buf, "invalid object buffer");
    goto fail;
  }

  const char *entry_name = (func_name && func_name[0]) ? func_name : "go";

  uint8_t empty_args[4] = {0};
  if (!args_buf || args_len <= 0) {
    args_buf = empty_args;
    args_len = (int)sizeof(empty_args);
  }

  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)obj_buf;
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
      ehdr->e_ident[EI_CLASS] != ELFCLASS64 || ehdr->e_machine != EM_X86_64 ||
      ehdr->e_type != ET_REL) {
    set_err(err_buf, "unsupported image");
    goto fail;
  }

  /* The section header table is walked by index throughout, so validate it
   * once instead of trusting e_shoff/e_shnum. */
  if (ehdr->e_shentsize != sizeof(Elf64_Shdr) || ehdr->e_shnum == 0 ||
      !range_ok(ehdr->e_shoff, (uint64_t)ehdr->e_shnum * sizeof(Elf64_Shdr),
                object_size)) {
    set_err(err_buf, "invalid section header table");
    goto fail;
  }

  Elf64_Shdr *shdrs = (Elf64_Shdr *)(obj_buf + ehdr->e_shoff);

  sec_offsets = (uintptr_t *)calloc(ehdr->e_shnum, sizeof(uintptr_t));
  if (!sec_offsets) {
    set_err(err_buf, "out of memory");
    goto fail;
  }

  uint64_t seg_size[BOF_SEG_COUNT] = {0};
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (!(shdrs[i].sh_flags & SHF_ALLOC)) {
      continue;
    }
    if ((shdrs[i].sh_flags & (SHF_WRITE | SHF_EXECINSTR)) ==
        (SHF_WRITE | SHF_EXECINSTR)) {
      set_err(err_buf, "writable executable section");
      goto fail;
    }
    uint64_t align = shdrs[i].sh_addralign;
    if (align == 0) {
      align = 1;
    }
    if ((align & (align - 1)) != 0 || align > 65536) {
      set_err(err_buf, "bad section alignment");
      goto fail;
    }
    int seg = bof_seg_for(&shdrs[i]);
    uint64_t off = align_up(seg_size[seg], align);
    if (off < seg_size[seg] || off > UINT64_MAX - shdrs[i].sh_size) {
      set_err(err_buf, "section size overflow");
      goto fail;
    }
    sec_offsets[i] = (uintptr_t)off;
    seg_size[seg] = off + shdrs[i].sh_size;
  }

  if (seg_size[BOF_SEG_RX] == 0 && seg_size[BOF_SEG_RO] == 0 &&
      seg_size[BOF_SEG_RW] == 0) {
    set_err(err_buf, "empty image");
    goto fail;
  }

  /* The trampoline page sits at the end of the executable segment, so code
   * and trampolines share one RX mapping. 256 trampolines fit in one page. */
  uint64_t tramp_local = align_up(seg_size[BOF_SEG_RX], 16);
  if (tramp_local > UINT64_MAX - 4096) {
    set_err(err_buf, "section size overflow");
    goto fail;
  }
  seg_size[BOF_SEG_RX] = tramp_local + 4096;

  uint64_t seg_base[BOF_SEG_COUNT];
  seg_base[BOF_SEG_RX] = 0;
  seg_base[BOF_SEG_RO] = align_up(seg_size[BOF_SEG_RX], 4096);
  if (seg_base[BOF_SEG_RO] < seg_size[BOF_SEG_RX] ||
      seg_size[BOF_SEG_RO] > UINT64_MAX - seg_base[BOF_SEG_RO]) {
    set_err(err_buf, "section size overflow");
    goto fail;
  }
  seg_base[BOF_SEG_RW] =
      align_up(seg_base[BOF_SEG_RO] + seg_size[BOF_SEG_RO], 4096);
  if (seg_base[BOF_SEG_RW] < seg_base[BOF_SEG_RO] ||
      seg_size[BOF_SEG_RW] > UINT64_MAX - seg_base[BOF_SEG_RW]) {
    set_err(err_buf, "section size overflow");
    goto fail;
  }
  total_size = align_up(seg_base[BOF_SEG_RW] + seg_size[BOF_SEG_RW], 4096);
  if (total_size == 0 || total_size < seg_base[BOF_SEG_RW] ||
      total_size > SIZE_MAX) {
    set_err(err_buf, "section size overflow");
    goto fail;
  }
  if (total_size > BOF_IMAGE_MAX) {
    set_err(err_buf, "image too large");
    goto fail;
  }

  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (!(shdrs[i].sh_flags & SHF_ALLOC)) {
      continue;
    }
    sec_offsets[i] += (uintptr_t)seg_base[bof_seg_for(&shdrs[i])];
  }
  uintptr_t trampoline_offset = (uintptr_t)(seg_base[BOF_SEG_RX] + tramp_local);

  // Writable initially for loading
  mem_base = mmap(NULL, (size_t)total_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem_base == MAP_FAILED) {
    mem_base = NULL;
    set_err(err_buf, "mmap failed");
    goto fail;
  }

  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (!(shdrs[i].sh_flags & SHF_ALLOC)) {
      continue;
    }
    if (shdrs[i].sh_type != SHT_NOBITS) {
      if (!range_ok(shdrs[i].sh_offset, shdrs[i].sh_size, object_size)) {
        set_err(err_buf, "section out of bounds");
        goto fail;
      }
      memcpy(mem_base + sec_offsets[i], obj_buf + shdrs[i].sh_offset,
             shdrs[i].sh_size);
    }
  }

  Elf64_Sym *symtab = NULL;
  const char *strtab = NULL;
  size_t strtab_size = 0;
  int num_syms = 0;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdrs[i].sh_type == SHT_SYMTAB) {
      if (shdrs[i].sh_link >= ehdr->e_shnum ||
          shdrs[i].sh_size % sizeof(Elf64_Sym) != 0 ||
          !range_ok(shdrs[i].sh_offset, shdrs[i].sh_size, object_size)) {
        set_err(err_buf, "invalid symtab");
        goto fail;
      }
      Elf64_Shdr *str_sh = &shdrs[shdrs[i].sh_link];
      if (str_sh->sh_type != SHT_STRTAB || str_sh->sh_size == 0 ||
          !range_ok(str_sh->sh_offset, str_sh->sh_size, object_size)) {
        set_err(err_buf, "invalid strtab");
        goto fail;
      }
      symtab = (Elf64_Sym *)(obj_buf + shdrs[i].sh_offset);
      num_syms = (int)(shdrs[i].sh_size / sizeof(Elf64_Sym));
      strtab = (const char *)(obj_buf + str_sh->sh_offset);
      strtab_size = str_sh->sh_size;
      break;
    }
  }

  if (!symtab || !strtab) {
    set_err(err_buf, "missing symtab");
    goto fail;
  }

  int next_trampoline = 0;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdrs[i].sh_type != SHT_RELA) {
      continue;
    }

    uint32_t target_sec_idx = shdrs[i].sh_info;
    if (target_sec_idx >= (uint32_t)ehdr->e_shnum) {
      set_err(err_buf, "invalid relocation target");
      goto fail;
    }

    uintptr_t target_base_offset = sec_offsets[target_sec_idx];
    if (!(shdrs[target_sec_idx].sh_flags & SHF_ALLOC)) {
      continue;
    }

    if (shdrs[i].sh_size % sizeof(Elf64_Rela) != 0 ||
        !range_ok(shdrs[i].sh_offset, shdrs[i].sh_size, object_size)) {
      set_err(err_buf, "invalid rela section");
      goto fail;
    }

    int num_rels = (int)(shdrs[i].sh_size / sizeof(Elf64_Rela));
    Elf64_Rela *rels = (Elf64_Rela *)(obj_buf + shdrs[i].sh_offset);

    for (int r = 0; r < num_rels; r++) {
      Elf64_Rela rel = rels[r];
      uint32_t sym_idx = ELF64_R_SYM(rel.r_info);
      uint32_t type = ELF64_R_TYPE(rel.r_info);

      /* The patch must fit inside the target section, otherwise we would
       * scribble over the neighbouring section (or outside the mapping). */
      uint64_t patch_size = (type == R_X86_64_64) ? 8 : 4;
      if (rel.r_offset > shdrs[target_sec_idx].sh_size ||
          patch_size > shdrs[target_sec_idx].sh_size - rel.r_offset) {
        set_err(err_buf, "relocation out of bounds");
        goto fail;
      }

      uintptr_t patch_addr =
          (uintptr_t)mem_base + target_base_offset + rel.r_offset;

      if (sym_idx >= (uint32_t)num_syms) {
        set_err(err_buf, "rel sym out of range");
        goto fail;
      }

      Elf64_Sym sym = symtab[sym_idx];
      uintptr_t sym_addr = 0;
      if (!cstr_ok(strtab, strtab_size, sym.st_name)) {
        set_err(err_buf, "invalid symbol name");
        goto fail;
      }
      const char *sym_name = strtab + sym.st_name;

      if (sym.st_shndx == SHN_UNDEF) {
        void *handle = beacon_api_lookup(sym_name);
        if (!handle) {
          handle = beacon_host_dlsym(sym_name);
        }
        if (!handle) {
          set_errf(err_buf, "unresolved symbol: %s", sym_name);
          goto fail;
        }

        if (next_trampoline >= 256) {
          set_err(err_buf, "too many undefined symbols for trampoline limit");
          goto fail;
        }
        uint8_t *tramp = mem_base + trampoline_offset + (next_trampoline * 16);
        next_trampoline++;
        tramp[0] = 0x49;
        tramp[1] = 0xbb; // movabs r11, ...
        *(uint64_t *)(tramp + 2) = (uint64_t)handle;
        tramp[10] = 0x41;
        tramp[11] = 0xff;
        tramp[12] = 0xe3; // jmp r11

        sym_addr = (uintptr_t)tramp;
      } else if (sym.st_shndx == SHN_ABS) {
        sym_addr = sym.st_value;
      } else {
        if (sym.st_shndx >= ehdr->e_shnum ||
            !(shdrs[sym.st_shndx].sh_flags & SHF_ALLOC) ||
            sym.st_value > shdrs[sym.st_shndx].sh_size) {
          set_err(err_buf, "invalid symbol section");
          goto fail;
        }
        sym_addr =
            (uintptr_t)mem_base + sec_offsets[sym.st_shndx] + sym.st_value;
      }

      switch (type) {
      case R_X86_64_64:
        *(uint64_t *)patch_addr = sym_addr + rel.r_addend;
        break;
      case R_X86_64_32:
        *(uint32_t *)patch_addr = (uint32_t)(sym_addr + rel.r_addend);
        break;
      case R_X86_64_32S:
        *(int32_t *)patch_addr = (int32_t)(sym_addr + rel.r_addend);
        break;
      case R_X86_64_PC32:
      case R_X86_64_PLT32: {
        int64_t val = (int64_t)sym_addr + rel.r_addend - (int64_t)patch_addr;
        if (val > 2147483647L || val < -2147483648L) {
          set_errf(err_buf,
                   "relocation overflow for symbol %s (type %u): "
                   "distance %ld exceeds 32 bits",
                   sym_name, type, val);
          goto fail;
        }
        *(uint32_t *)patch_addr = (uint32_t)val;
        break;
      }
      default:
        set_errf(err_buf, "unsupported relocation %u for symbol %s", type,
                 sym_name);
        goto fail;
      }
    }
  }

  /* Apply protection (W^X): the executable segment also holds the
   * trampolines, and no section may end up writable and executable. */
  if (mprotect(mem_base, (size_t)align_up(seg_size[BOF_SEG_RX], 4096),
               PROT_READ | PROT_EXEC) < 0) {
    set_err(err_buf, "mprotect failed");
    goto fail;
  }
  if (seg_size[BOF_SEG_RO] != 0 &&
      mprotect(mem_base + seg_base[BOF_SEG_RO],
               (size_t)align_up(seg_size[BOF_SEG_RO], 4096), PROT_READ) < 0) {
    set_err(err_buf, "mprotect failed");
    goto fail;
  }
  if (seg_size[BOF_SEG_RW] != 0 &&
      mprotect(mem_base + seg_base[BOF_SEG_RW],
               (size_t)align_up(seg_size[BOF_SEG_RW], 4096),
               PROT_READ | PROT_WRITE) < 0) {
    set_err(err_buf, "mprotect failed");
    goto fail;
  }

  uintptr_t entry_addr = 0;
  for (int i = 0; i < num_syms; i++) {
    if (!cstr_ok(strtab, strtab_size, symtab[i].st_name))
      break;
    const char *name = strtab + symtab[i].st_name;
    if (strcmp(name, entry_name) == 0) {
      if (symtab[i].st_shndx == SHN_UNDEF) {
        continue;
      }
      if (symtab[i].st_shndx == SHN_ABS) {
        entry_addr = symtab[i].st_value;
        break;
      }
      if (symtab[i].st_shndx >= ehdr->e_shnum ||
          !(shdrs[symtab[i].st_shndx].sh_flags & SHF_ALLOC) ||
          symtab[i].st_value > shdrs[symtab[i].st_shndx].sh_size) {
        set_err(err_buf, "invalid entry symbol");
        goto fail;
      }
      entry_addr = (uintptr_t)mem_base + sec_offsets[symtab[i].st_shndx] +
                   symtab[i].st_value;
      break;
    }
  }

  if (!entry_addr) {
    set_errf(err_buf, "function %s not found", entry_name);
    goto fail;
  }

  // Install signal handlers
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = bof_signal_handler;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;

  for (size_t i = 0; i < NUM_HANDLED_SIGS; i++) {
    sigaction(handled_sigs[i], &sa, &old_sa[handled_sigs[i]]);
  }

  typedef void (*func_ptr)(uint8_t *, int);
  int status = 0;

  beacon_output_reset();

  if (sigsetjmp(bof_env, 1) == 0) {
    is_in_bof = 1;
    func_ptr f = (func_ptr)entry_addr;
    f((uint8_t *)args_buf, args_len);
    is_in_bof = 0;
  } else {
    is_in_bof = 0;
    status = -1;
    set_err(err_buf, "guest execution fault");
  }

  // Restore signal handlers
  for (size_t i = 0; i < NUM_HANDLED_SIGS; i++) {
    sigaction(handled_sigs[i], &old_sa[handled_sigs[i]], NULL);
  }

  if (status == 0 && out_buf != NULL) {
    char *captured = beacon_output_take();
    if (captured != NULL) {
      *out_buf = captured;
    } else {
      *out_buf = (char *)malloc(1);
      if (*out_buf != NULL)
        (*out_buf)[0] = '\0';
    }
  } else {
    beacon_output_reset();
  }

  beacon_env_reset();
  beacon_host_dlsym_reset();
  munmap(mem_base, (size_t)total_size);
  free(sec_offsets);
  bof_lock_release();
  return status;

fail:
  beacon_env_reset();
  beacon_host_dlsym_reset();
  if (mem_base != NULL) {
    munmap(mem_base, (size_t)total_size);
  }
  free(sec_offsets);
  bof_lock_release();
  return -1;
}

/* Public ABI. Kept to five machine-word arguments so it can be called by the
 * Go agent's in-memory loader (memmod supports at most five) as well as by the
 * C agent's dynload. The output is a malloc'd, NUL-terminated buffer on
 * success and NULL on failure; LastError() then describes the error. Free the
 * returned buffer with Free(). */
static char bof_err_buf[512];

__attribute__((visibility("default"))) char *
Run(const uint8_t *obj_buf, size_t object_size, const char *func_name,
    const uint8_t *args_buf, int args_len) {
  char *out = NULL;
  char *err = NULL;

  int rc = bof_run_impl(obj_buf, object_size, func_name, args_buf, args_len,
                        &out, &err);
  if (rc != 0) {
    if (err != NULL) {
      snprintf(bof_err_buf, sizeof(bof_err_buf), "%s", err);
      free(err);
    } else {
      bof_err_buf[0] = '\0';
    }
    free(out);
    return NULL;
  }

  bof_err_buf[0] = '\0';
  if (out == NULL) {
    out = (char *)malloc(1);
    if (out != NULL) {
      out[0] = '\0';
    }
  }
  return out;
}

__attribute__((visibility("default"))) const char *LastError(void) {
  return bof_err_buf;
}

__attribute__((visibility("default"))) void Free(char *p) {
  free(p);
}
