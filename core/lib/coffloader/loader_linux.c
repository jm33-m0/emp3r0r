#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

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

// bof_run loads an x86_64 ELF ET_REL object and executes the requested symbol.
__attribute__((visibility("default"))) int
bof_run(const uint8_t *obj_buf, size_t object_size, const char *func_name,
        const uint8_t *args_buf, int args_len, char **out_buf, char **err_buf) {
  if (!obj_buf || object_size < sizeof(Elf64_Ehdr)) {
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
    return set_err(err_buf, "object is not x86_64 ET_REL");
  }

  Elf64_Shdr *shdrs = (Elf64_Shdr *)(obj_buf + ehdr->e_shoff);

  uintptr_t *sec_offsets =
      (uintptr_t *)calloc(ehdr->e_shnum, sizeof(uintptr_t));
  if (!sec_offsets) {
    return set_err(err_buf, "calloc sec_offsets failed");
  }

  uint64_t total_size = 0;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (!(shdrs[i].sh_flags & SHF_ALLOC)) {
      continue;
    }
    uint64_t align = shdrs[i].sh_addralign;
    total_size = align_up(total_size, align);
    sec_offsets[i] = total_size;
    total_size += shdrs[i].sh_size;
  }

  if (total_size == 0) {
    free(sec_offsets);
    return set_err(err_buf, "no alloc sections");
  }

  uint8_t *mem_base = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem_base == MAP_FAILED) {
    free(sec_offsets);
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
      return set_err(err_buf, "invalid relocation target");
    }

    uintptr_t target_base_offset = sec_offsets[target_sec_idx];
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
        return set_err(err_buf, "rel sym out of range");
      }

      Elf64_Sym sym = symtab[sym_idx];
      uintptr_t sym_addr = 0;

      if (sym.st_shndx == SHN_UNDEF) {
        const char *name = strtab + sym.st_name;
        void *handle = dlsym(RTLD_DEFAULT, name);
        if (!handle) {
          munmap(mem_base, total_size);
          free(sec_offsets);
          return set_errf(err_buf, "unresolved symbol: %s", name);
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
        *(uint32_t *)patch_addr = (uint32_t)val;
        break;
      }
      default:
        munmap(mem_base, total_size);
        free(sec_offsets);
        return set_errf(err_buf, "unsupported relocation %u", type);
      }
    }
  }

  if (mprotect(mem_base, total_size, PROT_READ | PROT_EXEC) < 0) {
    munmap(mem_base, total_size);
    free(sec_offsets);
    return set_err(err_buf, "mprotect failed");
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
    return set_errf(err_buf, "function %s not found", entry_name);
  }

  typedef char *(*func_ptr)(uint8_t *, int);
  func_ptr f = (func_ptr)entry_addr;
  char *result = f((uint8_t *)args_buf, args_len);

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

  munmap(mem_base, total_size);
  free(sec_offsets);
  return 0;
}

#pragma GCC visibility pop
