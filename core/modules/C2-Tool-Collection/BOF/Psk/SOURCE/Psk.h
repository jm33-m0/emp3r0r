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

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

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

typedef struct _SECPROD {
	WCHAR wcCompany[MAX_PATH];
	WCHAR wcDescription[MAX_PATH];
} SECPROD, *PSECPROD;

typedef struct _SECCOMP {
	WCHAR wcCompany[64];
} SECCOMP, *PSECCOMP;

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

//SHLWAPI
WINBASEAPI PCWSTR WINAPI SHLWAPI$StrStrIW(PCWSTR pszFirst, PCWSTR pszSrch);

//VERSION
WINBASEAPI DWORD WINAPI VERSION$GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle);
WINBASEAPI BOOL WINAPI VERSION$GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID  lpData);
WINBASEAPI BOOL WINAPI VERSION$VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen);

EXTERN_C NTSTATUS ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
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
