#pragma once

#include <windows.h>
#include <activeds.h>


//MSVCRT
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
WINBASEAPI errno_t __cdecl MSVCRT$wcscpy_s(wchar_t *_Dst, rsize_t _DstSize, const wchar_t *_Src);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void *__cdecl MSVCRT$srand(unsigned int seed);
WINBASEAPI int __cdecl MSVCRT$rand( void );

//KERNEL32
WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount(VOID);
WINBASEAPI DWORD WINAPI KERNEL32$FormatMessageW(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize, va_list *Arguments);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);

//USER32
WINBASEAPI LPWSTR USER32$CharLowerW(LPWSTR lpsz);
WINBASEAPI LPWSTR USER32$CharUpperW(LPWSTR lpsz);

//OLE32
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(LPCOLESTR lpsz, LPIID lpiid);

//OLEAUT32
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantClear(VARIANTARG *pvarg);

//NETAPI32
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR ComputerName, LPCWSTR DomainName, GUID *DomainGuid, LPCWSTR SiteName, ULONG Flags, PDOMAIN_CONTROLLER_INFOW *DomainControllerInfo);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);

//ACTIVEDS
typedef HRESULT (WINAPI *_ADsOpenObject)(
	LPCWSTR lpszPathName, 
	LPCWSTR lpszUserName, 
	LPCWSTR lpszPassword, 
	DWORD dwReserved, 
	REFIID riid, 
	void **ppObject
	);

typedef BOOL (WINAPI *_FreeADsMem)(
	LPVOID pMem
	);
