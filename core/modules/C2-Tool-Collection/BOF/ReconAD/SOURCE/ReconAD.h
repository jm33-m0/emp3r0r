#pragma once

#include <windows.h>
#include <activeds.h>


//KERNEL32
WINBASEAPI int WINAPI KERNEL32$FileTimeToLocalFileTime(CONST FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
WINBASEAPI int WINAPI KERNEL32$FileTimeToSystemTime(CONST FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI DWORD WINAPI KERNEL32$FormatMessageW(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize, va_list *Arguments);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);

//MSVCRT
WINBASEAPI int __cdecl MSVCRT$swprintf_s(wchar_t *buffer, size_t sizeOfBuffer, const wchar_t *format, ...);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
WINBASEAPI errno_t __cdecl MSVCRT$wcscpy_s(wchar_t *_Dst, rsize_t _DstSize, const wchar_t *_Src);
WINBASEAPI errno_t __cdecl MSVCRT$strcpy_s(char *dest, rsize_t dest_size, const char *src);
WINBASEAPI errno_t __cdecl MSVCRT$strcat_s(char *strDestination, size_t numberOfElements, const char *strSource);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1, const wchar_t *_Str2);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char *string1, const char *string2);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcstok_s(wchar_t* str, const wchar_t* delimiters, wchar_t** context);
WINBASEAPI int __cdecl MSVCRT$_vsnwprintf_s(wchar_t *buffer, size_t sizeOfBuffer, size_t count, const wchar_t *format, va_list argptr);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);

//OLE32
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CreateStreamOnHGlobal(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM *ppstm);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(LPCOLESTR lpsz, LPIID lpiid);
DECLSPEC_IMPORT int WINAPI OLE32$StringFromGUID2 (REFGUID rguid, LPOLESTR lpsz, int cchMax);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance (REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);

//OLEAUT32
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantClear(VARIANTARG *pvarg);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantChangeType(VARIANTARG *pvargDest, const VARIANTARG *pvarSrc, USHORT wFlags, VARTYPE vt);
DECLSPEC_IMPORT INT WINAPI OLEAUT32$SystemTimeToVariantTime(LPSYSTEMTIME lpSystemTime, DOUBLE *pvtime);
DECLSPEC_IMPORT INT WINAPI OLEAUT32$VariantTimeToSystemTime(DOUBLE vtime, LPSYSTEMTIME lpSystemTime);
DECLSPEC_IMPORT void WINAPI OLEAUT32$SysFreeString(BSTR);

//ADVAPI32
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID Sid, LPWSTR *StringSid);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorW(PSECURITY_DESCRIPTOR SecurityDescriptor, DWORD RequestedStringSDRevision, SECURITY_INFORMATION SecurityInformation, LPWSTR *StringSecurityDescriptor, PULONG StringSecurityDescriptorLen);

//ACTIVEDS
typedef HRESULT (WINAPI *_ADsOpenObject)(
	LPCWSTR lpszPathName, 
	LPCWSTR lpszUserName, 
	LPCWSTR lpszPassword, 
	DWORD dwReserved, 
	REFIID riid, 
	void **ppObject
	);

typedef HRESULT (WINAPI *_ADsGetObject)(
	LPCWSTR lpszPathName,
	REFIID riid,
	VOID **ppObject
	);

typedef BOOL (WINAPI *_FreeADsMem)(
	LPVOID pMem
	);
