#pragma once
#include <windows.h>
#include <ntstatus.h>

#define NTDLL_PATH "%SystemRoot%\\system32\\NTDLL.dll"

typedef struct _intPEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PSLIST_HEADER AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1; // REDSTONE5
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    struct API_SET_NAMESPACE * ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase; 
    PVOID SharedData; // HotpatchInformation
    PVOID *ReadOnlyStaticServerData;
    PVOID AnsiCodePageData; // PCPTABLEINFO
    PVOID OemCodePageData; // PCPTABLEINFO
    PVOID UnicodeCaseTableData; // PNLSTABLEINFO
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    ULARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID *ProcessHeaps; // PHEAP
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PRTL_CRITICAL_SECTION LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ActiveProcessAffinityMask;
    struct GDI_HANDLE_BUFFER * GdiHandleBuffer;
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA
    UNICODE_STRING CSDVersion;
    PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
    PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
    SIZE_T MinimumStackCommit;
    PVOID SparePointers[4]; // 19H1 (previously FlsCallback to FlsHighIndex)
    ULONG SpareUlongs[5]; // 19H1
    //PVOID* FlsCallback;
    //LIST_ENTRY FlsListHead;
    //PVOID FlsBitmap;
    //ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    //ULONG FlsHighIndex;
    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pUnused; // pContextData
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    PRTL_CRITICAL_SECTION TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[128];
    PVOID TelemetryCoverageHeader; // REDSTONE3
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags; // REDSTONE4
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    struct _LEAP_SECOND_DATA *LeapSecondData; // REDSTONE5
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
} intPEB, *intPPEB;

typedef enum _MEMORY_INFORMATION_CLASS {
  MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;



typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

typedef NTSTATUS (NTAPI *NtQueryVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

typedef NTSTATUS (NTAPI *NtReadVirtualMemory_t)(
    HANDLE ProcessHandle, 
    PVOID BaseAddress, 
    PVOID Buffer, 
    SIZE_T BufferSize, 
    PSIZE_T NumberOfBytesRead
);
  
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE hProcess,
    PVOID lpBaseAddress,
    PVOID lpBuffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);
  
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    PHANDLE ThreadHandle, 
    ACCESS_MASK DesiredAccess, 
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, 
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument OPTIONAL,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits, 
    SIZE_T StackSize OPTIONAL,
    SIZE_T MaximumStackSize OPTIONAL, 
    PVOID AttributeList OPTIONAL
);
    
typedef NTSTATUS (NTAPI *NtWaitForSingleObject_t)(
    HANDLE ObjectHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER TimeOut OPTIONAL
);
  
typedef NTSTATUS (NTAPI *NtClose_t)(
    HANDLE ObjectHandle
);

/* Section map options */
typedef enum _SECTION_INHERIT {
  ViewShare = 1,
  ViewUnmap = 2
} SECTION_INHERIT;

typedef NTSTATUS (NTAPI *NtCreateSection_t)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);

typedef NTSTATUS (NTAPI *NtMapViewOfSection_t)(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Protect
);

typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress OPTIONAL
);

typedef NTSTATUS (NTAPI *NtQueueApcThread_t)(
    IN HANDLE ThreadHandle,
    IN PAPCFUNC ApcRoutine,
    IN PVOID SystemArgument1 OPTIONAL,
    IN PVOID SystemArgument2 OPTIONAL,
    IN PVOID SystemArgument3 OPTIONAL
);

typedef NTSTATUS (NTAPI *NtResumeThread_t)(
    IN HANDLE hThread,
    OUT PULONG PreviousSuspendCount
);

typedef NTSTATUS (NTAPI *NtSuspendThread_t)(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL
);

typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *NtOpenProcess_t)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

typedef NTSTATUS (NTAPI *NtClose_t)(
    HANDLE Handle
);