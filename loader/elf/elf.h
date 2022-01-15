#ifndef _ELF_LOADER_H_
#define _ELF_LOADER_H_

#if defined(NAKED)
#include <system/syscall.h>
#else
#include <unistd.h>

#if !defined(PAGE_SIZE)
#define PAGE_SIZE (sysconf(_SC_PAGESIZE))
#endif

#define cacheflush(a1, a2, a3) __builtin___clear_cache(a1, a1 + a2)
#endif

#include <elf.h>

#if !defined(OS_FREEBSD)
//
// FreeBSD has this already defined
//
#if INTPTR_MAX == INT32_MAX
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Rel Elf_Rel;
typedef Elf32_Word Elf_Word;
#define ELF_R_SYM(x) ELF32_R_SYM(x)
#define ELF_R_TYPE(x) ELF32_R_TYPE(x)
#elif INTPTR_MAX == INT64_MAX
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Sym Elf_Sym;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Rel Elf_Rel;
typedef Elf64_Word Elf_Word;
#define ELF_R_SYM(x) ELF64_R_SYM(x)
#define ELF_R_TYPE(x) ELF64_R_TYPE(x)
#else
#error("Are you a wizard?")
#endif
#endif

#define STACK_SIZE (8 * 1024 * 1024)
#define STACK_STORAGE_SIZE 0x5000
#define STACK_STRING_SIZE 0x5000

#define ROUND_UP(v, s) ((v + s - 1) & -s)
#define ROUND_DOWN(v, s) (v & -s)

// Not all archs have this one defined
#ifndef AT_RANDOM
#define AT_RANDOM 25
#endif

struct ATENTRY {
    size_t id;
    size_t value;
} __attribute__((packed));

/*!
 * \brief Find ELF section by name.
 */
Elf_Shdr* elf_get_section(char* name, void* elf_start);

/*!
 * \brief Find ELF symbol by name.
 */
void* elf_get_symbol(void* elf_start, char* sym_name);

/*!
 * \brief Map the ELF into memory.
 */
void elf_load(char* elf_start, void* stack, int stack_size, size_t* base_addr, size_t* entry);

/*!
 * \brief Map the ELF into memory and run it with the provided arguments.
 */
void elf_run(void* buf, char** argv, char** env);

#endif // _ELF_LOADER_H_
