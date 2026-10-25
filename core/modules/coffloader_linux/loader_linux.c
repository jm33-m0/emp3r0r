#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <pthread.h>
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

#pragma GCC visibility push(hidden)

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

/* True when a NUL-terminated string at `off` terminates within the table. */
static int cstr_ok(const char *base, size_t total, uint64_t off) {
  if (base == NULL || off >= (uint64_t)total) {
    return 0;
  }
  return memchr(base + off, 0, total - (size_t)off) != NULL;
}

// Global mutex to serialize BOF execution and protect signal handler state
static pthread_mutex_t bof_lock = PTHREAD_MUTEX_INITIALIZER;

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

// bof_run_impl loads an x86_64 ELF ET_REL object and executes the requested
// symbol. It is internal; the exported bof_run() wraps it with a stable,
// machine-callable ABI (see below).
static int
bof_run_impl(const uint8_t *obj_buf, size_t object_size, const char *func_name,
             const uint8_t *args_buf, int args_len, char **out_buf,
             char **err_buf) {

  // Serialize access
  pthread_mutex_lock(&bof_lock);

  if (!obj_buf || object_size < sizeof(Elf64_Ehdr)) {
    pthread_mutex_unlock(&bof_lock);
    return set_err(err_buf, "invalid object buffer");
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
    pthread_mutex_unlock(&bof_lock);
    return set_err(err_buf, "object is not x86_64 ET_REL");
  }

  /* The section header table is walked by index throughout, so validate it
   * once instead of trusting e_shoff/e_shnum. */
  if (ehdr->e_shentsize != sizeof(Elf64_Shdr) || ehdr->e_shnum == 0 ||
      !range_ok(ehdr->e_shoff, (uint64_t)ehdr->e_shnum * sizeof(Elf64_Shdr),
                object_size)) {
    pthread_mutex_unlock(&bof_lock);
    return set_err(err_buf, "invalid section header table");
  }

  Elf64_Shdr *shdrs = (Elf64_Shdr *)(obj_buf + ehdr->e_shoff);

  uintptr_t *sec_offsets =
      (uintptr_t *)calloc(ehdr->e_shnum, sizeof(uintptr_t));
  if (!sec_offsets) {
    pthread_mutex_unlock(&bof_lock);
    return set_err(err_buf, "calloc sec_offsets failed");
  }

  uint64_t total_size = 0;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (!(shdrs[i].sh_flags & SHF_ALLOC)) {
      continue;
    }
    // Force page alignment for all sections to allow granular mprotect
    uint64_t align = 4096;
    total_size = align_up(total_size, align);
    sec_offsets[i] = total_size;
    if (total_size > UINT64_MAX - shdrs[i].sh_size) {
      free(sec_offsets);
      pthread_mutex_unlock(&bof_lock);
      return set_err(err_buf, "section size overflow");
    }
    total_size += shdrs[i].sh_size;
  }

  total_size = align_up(total_size, 4096);
  uintptr_t trampoline_offset = total_size;
  total_size += 4096; // Space for up to 256 trampolines

  if (total_size == 0) {
    free(sec_offsets);
    pthread_mutex_unlock(&bof_lock);
    return set_err(err_buf, "no alloc sections");
  }

  // Writable initially for loading
  uint8_t *mem_base = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem_base == MAP_FAILED) {
    free(sec_offsets);
    pthread_mutex_unlock(&bof_lock);
    return set_err(err_buf, "mmap failed");
  }

  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (!(shdrs[i].sh_flags & SHF_ALLOC)) {
      continue;
    }
    if (shdrs[i].sh_type != SHT_NOBITS) {
      if (!range_ok(shdrs[i].sh_offset, shdrs[i].sh_size, object_size)) {
        munmap(mem_base, total_size);
        free(sec_offsets);
        pthread_mutex_unlock(&bof_lock);
        return set_err(err_buf, "section out of bounds");
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
        munmap(mem_base, total_size);
        free(sec_offsets);
        pthread_mutex_unlock(&bof_lock);
        return set_err(err_buf, "invalid symtab");
      }
      Elf64_Shdr *str_sh = &shdrs[shdrs[i].sh_link];
      if (str_sh->sh_type != SHT_STRTAB || str_sh->sh_size == 0 ||
          !range_ok(str_sh->sh_offset, str_sh->sh_size, object_size)) {
        munmap(mem_base, total_size);
        free(sec_offsets);
        pthread_mutex_unlock(&bof_lock);
        return set_err(err_buf, "invalid strtab");
      }
      symtab = (Elf64_Sym *)(obj_buf + shdrs[i].sh_offset);
      num_syms = (int)(shdrs[i].sh_size / sizeof(Elf64_Sym));
      strtab = (const char *)(obj_buf + str_sh->sh_offset);
      strtab_size = str_sh->sh_size;
      break;
    }
  }

  if (!symtab || !strtab) {
    munmap(mem_base, total_size);
    free(sec_offsets);
    pthread_mutex_unlock(&bof_lock);
    return set_err(err_buf, "missing symtab");
  }

  int next_trampoline = 0;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdrs[i].sh_type != SHT_RELA) {
      continue;
    }

    uint32_t target_sec_idx = shdrs[i].sh_info;
    if (target_sec_idx >= (uint32_t)ehdr->e_shnum) {
      munmap(mem_base, total_size);
      free(sec_offsets);
      pthread_mutex_unlock(&bof_lock);
      return set_err(err_buf, "invalid relocation target");
    }

    uintptr_t target_base_offset = sec_offsets[target_sec_idx];
    if (!(shdrs[target_sec_idx].sh_flags & SHF_ALLOC)) {
      continue;
    }

    if (shdrs[i].sh_size % sizeof(Elf64_Rela) != 0 ||
        !range_ok(shdrs[i].sh_offset, shdrs[i].sh_size, object_size)) {
      munmap(mem_base, total_size);
      free(sec_offsets);
      pthread_mutex_unlock(&bof_lock);
      return set_err(err_buf, "invalid rela section");
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
        munmap(mem_base, total_size);
        free(sec_offsets);
        pthread_mutex_unlock(&bof_lock);
        return set_err(err_buf, "relocation out of bounds");
      }

      uintptr_t patch_addr =
          (uintptr_t)mem_base + target_base_offset + rel.r_offset;

      if (sym_idx >= (uint32_t)num_syms) {
        munmap(mem_base, total_size);
        free(sec_offsets);
        pthread_mutex_unlock(&bof_lock);
        return set_err(err_buf, "rel sym out of range");
      }

      Elf64_Sym sym = symtab[sym_idx];
      uintptr_t sym_addr = 0;
      if (!cstr_ok(strtab, strtab_size, sym.st_name)) {
        munmap(mem_base, total_size);
        free(sec_offsets);
        pthread_mutex_unlock(&bof_lock);
        return set_err(err_buf, "invalid symbol name");
      }
      const char *sym_name = strtab + sym.st_name;

      if (sym.st_shndx == SHN_UNDEF) {
        void *handle = beacon_api_lookup(sym_name);
        if (!handle) {
          handle = dlsym(RTLD_DEFAULT, sym_name);
        }
        if (!handle) {
          munmap(mem_base, total_size);
          free(sec_offsets);
          pthread_mutex_unlock(&bof_lock);
          return set_errf(err_buf, "unresolved symbol: %s", sym_name);
        }

        if (next_trampoline >= 256) {
          munmap(mem_base, total_size);
          free(sec_offsets);
          pthread_mutex_unlock(&bof_lock);
          return set_err(err_buf,
                         "too many undefined symbols for trampoline limit");
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
          munmap(mem_base, total_size);
          free(sec_offsets);
          pthread_mutex_unlock(&bof_lock);
          return set_err(err_buf, "invalid symbol section");
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
          munmap(mem_base, total_size);
          free(sec_offsets);
          pthread_mutex_unlock(&bof_lock);
          return set_errf(err_buf,
                          "relocation overflow for symbol %s (type %u): "
                          "distance %ld exceeds 32 bits",
                          sym_name, type, val);
        }
        *(uint32_t *)patch_addr = (uint32_t)val;
        break;
      }
      default:
        munmap(mem_base, total_size);
        free(sec_offsets);
        pthread_mutex_unlock(&bof_lock);
        return set_errf(err_buf, "unsupported relocation %u for symbol %s",
                        type, sym_name);
      }
    }
  }

  mprotect(mem_base + trampoline_offset, 4096, PROT_READ | PROT_EXEC);

  // Apply protection (W^X)
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (!(shdrs[i].sh_flags & SHF_ALLOC)) {
      continue;
    }
    uintptr_t start = (uintptr_t)mem_base + sec_offsets[i];
    uint64_t size = shdrs[i].sh_size;
    if (size == 0)
      continue;

    uint64_t prot_len = align_up(size, 4096);

    int prot = PROT_READ;
    // Map data as RW, code as RX
    if (shdrs[i].sh_flags & SHF_WRITE)
      prot |= PROT_WRITE;
    if (shdrs[i].sh_flags & SHF_EXECINSTR)
      prot |= PROT_EXEC;

    if (mprotect((void *)start, prot_len, prot) < 0) {
      munmap(mem_base, total_size);
      free(sec_offsets);
      pthread_mutex_unlock(&bof_lock);
      return set_err(err_buf, "mprotect failed");
    }
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
        munmap(mem_base, total_size);
        free(sec_offsets);
        pthread_mutex_unlock(&bof_lock);
        return set_err(err_buf, "invalid entry symbol");
      }
      entry_addr = (uintptr_t)mem_base + sec_offsets[symtab[i].st_shndx] +
                   symtab[i].st_value;
      break;
    }
  }

  if (!entry_addr) {
    munmap(mem_base, total_size);
    free(sec_offsets);
    pthread_mutex_unlock(&bof_lock);
    return set_errf(err_buf, "function %s not found", entry_name);
  }

  // Install signal handlers
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = bof_signal_handler;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;

  for (int i = 0; i < NUM_HANDLED_SIGS; i++) {
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
    status = -1; // Specific status for crash?
    set_err(err_buf, "BOF Crashed (SIGSEGV/SIGBUS/etc caught)");
  }

  // Restore signal handlers
  for (int i = 0; i < NUM_HANDLED_SIGS; i++) {
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

  munmap(mem_base, total_size);
  free(sec_offsets);
  pthread_mutex_unlock(&bof_lock);
  return status;
}

/* Public ABI. Kept to five machine-word arguments so it can be called by the
 * Go agent's in-memory loader (memmod supports at most five) as well as by the
 * C agent's dynload. The output is a malloc'd, NUL-terminated buffer on
 * success and NULL on failure; bof_last_error() then describes the error.
 * Free the returned buffer with bof_free(). */
static char bof_err_buf[512];

__attribute__((visibility("default"))) char *
bof_run(const uint8_t *obj_buf, size_t object_size, const char *func_name,
        const uint8_t *args_buf, int args_len) {
  char *out = NULL;
  char *err = NULL;

  if (bof_run_impl(obj_buf, object_size, func_name, args_buf, args_len, &out,
                   &err) != 0) {
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

__attribute__((visibility("default"))) const char *bof_last_error(void) {
  return bof_err_buf;
}

__attribute__((visibility("default"))) void bof_free(char *p) { free(p); }

#pragma GCC visibility pop
