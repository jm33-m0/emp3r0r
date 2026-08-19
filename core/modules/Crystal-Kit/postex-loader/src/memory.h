#define MAX_HEAP_RECORDS 32
#define MAX_SECTIONS     16

typedef struct {
    PVOID Data;
    PVOID Code;
} PICO_MEMORY;

typedef struct { 
    PVOID  Address;
    SIZE_T Size;
} HEAP_RECORD;

typedef struct {
    HEAP_RECORD Records [ MAX_HEAP_RECORDS ];
    SIZE_T      Count;
} HEAP_MEMORY;

typedef struct {
    PVOID  BaseAddress;
    SIZE_T Size;
    DWORD  CurrentProtect;
    DWORD  PreviousProtect;
} MEMORY_SECTION;

typedef struct {
    PVOID          BaseAddress;
    SIZE_T         Size;
    MEMORY_SECTION Sections [ MAX_SECTIONS ];
    SIZE_T         Count;
} DLL_MEMORY;

typedef struct {
    PICO_MEMORY Pico;
    DLL_MEMORY  Dll;
    HEAP_MEMORY Heap;
} MEMORY_LAYOUT;
