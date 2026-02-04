#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>
#include <unistd.h>

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

// Global mutex to serialize BOF execution and protect signal handler state
static pthread_mutex_t bof_lock = PTHREAD_MUTEX_INITIALIZER;

// Saved signal handlers
static struct sigaction old_sa[32]; 
static int handled_sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE};
#define NUM_HANDLED_SIGS (sizeof(handled_sigs) / sizeof(handled_sigs[0]))

// Thread-local state for crash recovery
static __thread sigjmp_buf bof_env;
static __thread volatile int is_in_bof = 0;

static void bof_signal_handler(int sig, siginfo_t *info, void *ctx) {
    if (is_in_bof) {
        siglongjmp(bof_env, 1);
    }
    
    // Chain to original handler if not in BOF or if handler exists
    // Note: We only save old_sa when we take the lock.
    // Since we are in the handler, we assume old_sa is valid for the chained call.
    if (sig >= 0 && sig < 32) {
        if (old_sa[sig].sa_flags & SA_SIGINFO) {
            if (old_sa[sig].sa_sigaction)
                old_sa[sig].sa_sigaction(sig, info, ctx);
        } else {
             if (old_sa[sig].sa_handler != SIG_IGN && old_sa[sig].sa_handler != SIG_DFL)
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

// bof_run loads an x86_64 ELF ET_REL object and executes the requested symbol.
__attribute__((visibility("default"))) int
bof_run(const uint8_t *obj_buf, size_t object_size, const char *func_name,
        const uint8_t *args_buf, int args_len, char **out_buf, char **err_buf) {
  
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
    total_size += shdrs[i].sh_size;
  }

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
      memcpy(mem_base + sec_offsets[i], obj_buf + shdrs[i].sh_offset,
             shdrs[i].sh_size);
    }
  }

  Elf64_Sym *symtab = NULL;
  const char *strtab = NULL;
  int num_syms = 0;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdrs[i].sh_type == SHT_SYMTAB) {
      symtab = (Elf64_Sym *)(obj_buf + shdrs[i].sh_offset);
      num_syms = shdrs[i].sh_size / (int)sizeof(Elf64_Sym);
      strtab = (const char *)(obj_buf + shdrs[shdrs[i].sh_link].sh_offset);
      break;
    }
  }

  if (!symtab || !strtab) {
    munmap(mem_base, total_size);
    free(sec_offsets);
    pthread_mutex_unlock(&bof_lock);
    return set_err(err_buf, "missing symtab");
  }

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

    int num_rels = shdrs[i].sh_size / (int)sizeof(Elf64_Rela);
    Elf64_Rela *rels = (Elf64_Rela *)(obj_buf + shdrs[i].sh_offset);

    for (int r = 0; r < num_rels; r++) {
      Elf64_Rela rel = rels[r];
      uint32_t sym_idx = ELF64_R_SYM(rel.r_info);
      uint32_t type = ELF64_R_TYPE(rel.r_info);

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
      const char *sym_name = strtab + sym.st_name;

      if (sym.st_shndx == SHN_UNDEF) {
        void *handle = dlsym(RTLD_DEFAULT, sym_name);
        if (!handle) {
          munmap(mem_base, total_size);
          free(sec_offsets);
          pthread_mutex_unlock(&bof_lock);
          return set_errf(err_buf, "unresolved symbol: %s", sym_name);
        }
        sym_addr = (uintptr_t)handle;
      } else if (sym.st_shndx == SHN_ABS) {
        sym_addr = sym.st_value;
      } else {
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
             return set_errf(err_buf, "relocation overflow for symbol %s (type %u): distance %ld exceeds 32 bits", sym_name, type, val);
        }
        *(uint32_t *)patch_addr = (uint32_t)val;
        break;
      }
      default:
        munmap(mem_base, total_size);
        free(sec_offsets);
        pthread_mutex_unlock(&bof_lock);
        return set_errf(err_buf, "unsupported relocation %u for symbol %s", type, sym_name);
      }
    }
  }

  // Apply protection (W^X)
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (!(shdrs[i].sh_flags & SHF_ALLOC)) {
      continue;
    }
    uintptr_t start = (uintptr_t)mem_base + sec_offsets[i];
    uint64_t size = shdrs[i].sh_size;
    if (size == 0) continue;
    
    uint64_t prot_len = align_up(size, 4096);

    int prot = PROT_READ;
    // Map data as RW, code as RX
    if (shdrs[i].sh_flags & SHF_WRITE) prot |= PROT_WRITE;
    if (shdrs[i].sh_flags & SHF_EXECINSTR) prot |= PROT_EXEC;

    if (mprotect((void *)start, prot_len, prot) < 0) {
        munmap(mem_base, total_size);
        free(sec_offsets);
        pthread_mutex_unlock(&bof_lock);
        return set_err(err_buf, "mprotect failed");
    }
  }

  uintptr_t entry_addr = 0;
  for (int i = 0; i < num_syms; i++) {
    const char *name = strtab + symtab[i].st_name;
    if (strcmp(name, entry_name) == 0) {
      if (symtab[i].st_shndx == SHN_UNDEF) {
        continue;
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

  for(int i=0; i<NUM_HANDLED_SIGS; i++) {
      sigaction(handled_sigs[i], &sa, &old_sa[handled_sigs[i]]);
  }

  typedef char *(*func_ptr)(uint8_t *, int);
  char *result = NULL;
  int status = 0;

  if (sigsetjmp(bof_env, 1) == 0) {
      is_in_bof = 1;
      func_ptr f = (func_ptr)entry_addr;
      result = f((uint8_t *)args_buf, args_len);
      is_in_bof = 0;
  } else {
      is_in_bof = 0;
      status = -1; // Specific status for crash?
      set_err(err_buf, "BOF Crashed (SIGSEGV/SIGBUS/etc caught)");
  }

  // Restore signal handlers
  for(int i=0; i<NUM_HANDLED_SIGS; i++) {
      sigaction(handled_sigs[i], &old_sa[handled_sigs[i]], NULL);
  }

  if (status == 0) {
      if (out_buf) {
        if (result) {
          size_t len = strlen(result) + 1;
          *out_buf = (char *)malloc(len);
          if (*out_buf) {
            memcpy(*out_buf, result, len);
          }
        } else {
          *out_buf = (char *)malloc(1);
          if (*out_buf) {
            (*out_buf)[0] = '\0';
          }
        }
      }
  }

  munmap(mem_base, total_size);
  free(sec_offsets);
  pthread_mutex_unlock(&bof_lock);
  return status;
}

#pragma GCC visibility pop

