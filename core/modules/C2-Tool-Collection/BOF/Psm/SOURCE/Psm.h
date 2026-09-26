#pragma once

#include <windows.h>

#define STATUS_SUCCESS 0
#define STATUS_UNSUCCESSFUL 0xC0000001
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#define STATUS_BUFFER_OVERFLOW 0x80000005L
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define OBJ_INHERIT 0x00000002L

#define FILE_SHARE_READ 0x00000001
#define FILE_SHARE_VALID_FLAGS 0x00000007
#define FILE_OPEN 0x00000001
#define FILE_CREATE 0x00000002
#define FILE_OPEN_IF 0x00000003
#define FILE_OVERWRITE 0x00000004
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_WRITE_THROUGH 0x00000002
#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_DIRECTORY_FILE   0x00000001
#define FILE_NON_DIRECTORY_FILE 0x00000040

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )
#define NtCurrentSession() ( (HANDLE)(LONG_PTR) -3 )

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef LONG KPRIORITY;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _UNICODE_STRING_WOW64 {
	USHORT Length;
	USHORT MaximumLength;
	ULONG64 Buffer;
} UNICODE_STRING_WOW64;

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING, OEM_STRING, *POEM_STRING;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemProcessIdInformation = 88
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

// Partial PROCESSINFOCLASS
typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize, // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // (kernel-mode only)
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,
	ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask, // s: KAFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information // q: ULONG_PTR
} PROCESSINFOCLASS;

enum IntegLevel {
	Untrusted = 0,
	LowIntegrity = 1,
	MediumIntegrity = 2,
	HighIntegrity = 3,
	SystemIntegrity = 4,
	ProtectedProcess = 5
};

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _SYSTEM_PROCESS_ID_INFORMATION {
	HANDLE ProcessId;
	UNICODE_STRING ImageName;
} SYSTEM_PROCESS_ID_INFORMATION, * PSYSTEM_PROCESS_ID_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION {
	LONG ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION_WOW64 {
	NTSTATUS ExitStatus;
	ULONG64 PebBaseAddress;
	ULONG64 AffinityMask;
	KPRIORITY BasePriority;
	ULONG64 UniqueProcessId;
	ULONG64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_WOW64, *PPROCESS_BASIC_INFORMATION_WOW64;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB_LDR_DATA64 {
    ULONG Length;
    BOOLEAN Initialized;
    ULONG64 SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	union
	{
		LIST_ENTRY64 InInitializationOrderLinks;
		LIST_ENTRY64 InProgressLinks;
	};
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING_WOW64 FullDllName;
	UNICODE_STRING_WOW64 BaseDllName;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

typedef struct _API_SET_NAMESPACE {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

typedef struct _CURDIR64 {
	UNICODE_STRING_WOW64 DosPath;
	HANDLE Handle;
} CURDIR64, *PCURDIR64;

typedef struct _RTL_USER_PROCESS_PARAMETERS64 {
	ULONG MaximumLength;
	ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    ULONG64 ConsoleHandle;
    ULONG ConsoleFlags;
    ULONG64 StandardInput;
    ULONG64 StandardOutput;
    ULONG64 StandardError;
    CURDIR64 CurrentDirectory;
    UNICODE_STRING_WOW64 DllPath;
    UNICODE_STRING_WOW64 ImagePathName;
    UNICODE_STRING_WOW64 CommandLine;
} RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;

// Partial PEB64
typedef struct _PEB64 {
    BYTE Reserved[16];
    ULONG64 ImageBaseAddress;
    ULONG64 Ldr;
    ULONG64 ProcessParameters;
} PEB64, *PPEB64;

// Partial PEB
typedef struct _PEB {
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
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID IFEOKey;
	PSLIST_HEADER AtlThunkSListPtr;
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
			ULONG ProcessImagesHotPatched : 1;
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
	PAPI_SET_NAMESPACE ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData;
	PVOID *ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	ULARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID *ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
} PEB, *PPEB;

//KERNEL32
WINBASEAPI int WINAPI KERNEL32$FileTimeToLocalFileTime(CONST FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
WINBASEAPI int WINAPI KERNEL32$FileTimeToSystemTime(CONST FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI BOOL WINAPI KERNEL32$SystemTimeToTzSpecificLocalTime(const TIME_ZONE_INFORMATION *lpTimeZoneInformation, const SYSTEMTIME *lpUniversalTime, LPSYSTEMTIME lpLocalTime);
WINBASEAPI BOOL WINAPI KERNEL32$ProcessIdToSessionId(DWORD dwProcessId, DWORD *pSessionId);
WINBASEAPI DWORD WINAPI KERNEL32$FormatMessageW(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize, va_list *Arguments);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI void WINAPI KERNEL32$OutputDebugStringW(LPCWSTR lpOutputString);
WINBASEAPI DWORD WINAPI KERNEL32$GetFinalPathNameByHandleW(HANDLE hFile, LPWSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags);
WINBASEAPI BOOL WINAPI KERNEL32$GetBinaryTypeW(LPCWSTR lpApplicationName, LPDWORD lpBinaryType);

//MSVCRT
WINBASEAPI int __cdecl MSVCRT$swprintf_s(wchar_t *buffer, size_t sizeOfBuffer, const wchar_t *format, ...);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
WINBASEAPI errno_t __cdecl MSVCRT$wcscpy_s(wchar_t *_Dst, rsize_t _DstSize, const wchar_t *_Src);
WINBASEAPI errno_t __cdecl MSVCRT$strcpy_s(char *dest, rsize_t dest_size, const char *src);
WINBASEAPI errno_t __cdecl MSVCRT$strcat_s(char *strDestination, size_t numberOfElements, const char *strSource);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void *dest, const void *src, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1, const wchar_t *_Str2);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char *string1, const char *string2);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcstok_s(wchar_t* str, const wchar_t* delimiters, wchar_t** context);
WINBASEAPI int __cdecl MSVCRT$_vsnwprintf_s(wchar_t *buffer, size_t sizeOfBuffer, size_t count, const wchar_t *format, va_list argptr);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);

//OLE32
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CreateStreamOnHGlobal(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM *ppstm);

//ADVAPI32
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);

//SHLWAPI
WINBASEAPI PCWSTR WINAPI SHLWAPI$StrStrIW(PCWSTR pszFirst, PCWSTR pszSrch);

//VERSION
WINBASEAPI DWORD WINAPI VERSION$GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle);
WINBASEAPI BOOL WINAPI VERSION$GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID  lpData);
WINBASEAPI BOOL WINAPI VERSION$VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen);

//IPHLPAPI
WINBASEAPI ULONG WINAPI IPHLPAPI$GetTcpTable2(PMIB_TCPTABLE2 TcpTable, PULONG SizePointer, BOOL Order);
WINBASEAPI ULONG WINAPI IPHLPAPI$GetTcp6Table2(PMIB_TCP6TABLE2 TcpTable, PULONG SizePointer, BOOL Order);

//WS2_32
DECLSPEC_IMPORT u_short __stdcall WS2_32$ntohs(u_short netshort);

EXTERN_C NTSTATUS ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

EXTERN_C NTSTATUS ZwQueryInformationProcess(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

EXTERN_C NTSTATUS ZwOpenProcess(
	PHANDLE ProcessHandle, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	PCLIENT_ID ClientId
	);

EXTERN_C NTSTATUS ZwQueryInformationToken(
	HANDLE TokenHandle,
	TOKEN_INFORMATION_CLASS TokenInformationClass,
	PVOID TokenInformation,
	ULONG TokenInformationLength,
	PULONG ReturnLength
	);

EXTERN_C NTSTATUS ZwAdjustPrivilegesToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES TokenPrivileges,
	IN ULONG PreviousPrivilegesLength,
	OUT PTOKEN_PRIVILEGES PreviousPrivileges OPTIONAL,
	OUT PULONG RequiredLength OPTIONAL
	);

EXTERN_C NTSTATUS ZwAllocateVirtualMemory(
	HANDLE ProcessHandle, 
	PVOID *BaseAddress, 
	ULONG_PTR ZeroBits, 
	PSIZE_T RegionSize, 
	ULONG AllocationType, 
	ULONG Protect
	);

EXTERN_C NTSTATUS ZwFreeVirtualMemory(
	HANDLE ProcessHandle, 
	PVOID *BaseAddress, 
	IN OUT PSIZE_T RegionSize, 
	ULONG FreeType
	);

EXTERN_C NTSTATUS ZwReadVirtualMemory(
	HANDLE hProcess, 
	PVOID lpBaseAddress, 
	PVOID lpBuffer, 
	SIZE_T NumberOfBytesToRead, 
	PSIZE_T NumberOfBytesRead
	);

EXTERN_C NTSTATUS ZwWriteVirtualMemory(
	HANDLE hProcess, 
	PVOID lpBaseAddress, 
	PVOID lpBuffer, 
	SIZE_T NumberOfBytesToWrite, 
	PSIZE_T NumberOfBytesWrite
	);

EXTERN_C NTSTATUS ZwCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
);

EXTERN_C NTSTATUS ZwClose(
	IN HANDLE KeyHandle
    );

typedef NTSTATUS(NTAPI* _NtOpenProcessToken)(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle
	);

typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef void(WINAPI* _RtlFreeUnicodeString)(
	PUNICODE_STRING UnicodeString
	);

typedef void (WINAPI* _RtlInitAnsiString)(
	PANSI_STRING DestinationString,
	PSTR SourceString
	);

typedef NTSTATUS(NTAPI* _RtlAnsiStringToUnicodeString)(
	PUNICODE_STRING DestinationString,
	PANSI_STRING SourceString,
	BOOLEAN AllocateDestinationString
	);

typedef BOOLEAN(NTAPI* _RtlEqualUnicodeString)(
	PUNICODE_STRING String1,
	PCUNICODE_STRING String2,
	BOOLEAN CaseInSensitive
	);

typedef NTSTATUS(NTAPI *_RtlWow64EnableFsRedirectionEx)(
	_In_ PVOID DisableFsRedirection,
	_Out_ PVOID *OldFsRedirectionLevel
	);

typedef NTSTATUS(NTAPI *_NtWow64QueryInformationProcess64) (
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

typedef NTSTATUS(NTAPI *_NtWow64ReadVirtualMemory64)(
	IN HANDLE ProcessHandle,
	IN ULONG64 BaseAddress,
	OUT PVOID Buffer,
	IN ULONG64 Size,
	OUT PULONG64 NumberOfBytesRead
	);

typedef PULONG(NTAPI *_RtlSubAuthoritySid)(
	PSID  Sid,
	ULONG SubAuthority
	);

typedef PUCHAR(NTAPI *_RtlSubAuthorityCountSid)(
	_In_ PSID Sid
	);

typedef PWSTR(NTAPI *_RtlIpv4AddressToStringW)(
	struct in_addr *Addr,
	PWSTR S
	);

typedef PWSTR(NTAPI *_RtlIpv6AddressToStringW)(
	struct in6_addr *Addr,
	PWSTR S
	);
