#pragma once

#include <windows.h>

#define STATUS_SUCCESS 0
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )
#define NtCurrentSession() ( (HANDLE)(LONG_PTR) -3 )

typedef LONG KPRIORITY;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

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
	SystemModuleInformation
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

// MSVCRT
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);

//USER32
WINUSERAPI WINBOOL USER32$EnumWindows(WNDENUMPROC lpEnumFunc,LPARAM lParam);
WINUSERAPI WINBOOL USER32$IsWindowVisible(HWND hWnd);
WINUSERAPI LRESULT USER32$SendMessageA(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam);
WINUSERAPI DWORD   USER32$GetWindowThreadProcessId(HWND hWnd,LPDWORD lpdwProcessId);

//KERNEL32
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);

EXTERN_C NTSTATUS ZwAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

EXTERN_C NTSTATUS ZwFreeVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	ULONG FreeType
);

EXTERN_C NTSTATUS ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);
