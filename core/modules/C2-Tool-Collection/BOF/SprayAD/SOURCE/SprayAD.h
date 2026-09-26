#pragma once

#include <windows.h>
#include <activeds.h>


#define MAX_RESULTS 500

typedef struct _USER_INFO {
	WCHAR chuserPrincipalName[MAX_RESULTS][MAX_PATH];
} USER_INFO, *PUSER_INFO;

//KERNEL32
WINBASEAPI int WINAPI KERNEL32$FileTimeToLocalFileTime(CONST FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
WINBASEAPI int WINAPI KERNEL32$FileTimeToSystemTime(CONST FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI DWORD WINAPI KERNEL32$FormatMessageW(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize, va_list *Arguments);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI WINBOOL WINAPI KERNEL32$QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);
WINBASEAPI WINBOOL WINAPI KERNEL32$QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
WINBASEAPI int WINAPI KERNEL32$lstrlenW(LPCWSTR lpString);

//MSVCRT
WINBASEAPI int __cdecl MSVCRT$swprintf_s(wchar_t *buffer, size_t sizeOfBuffer, const wchar_t *format, ...);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
WINBASEAPI errno_t __cdecl MSVCRT$wcscpy_s(wchar_t *_Dst, rsize_t _DstSize, const wchar_t *_Src);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1, const wchar_t *_Str2);
WINBASEAPI int __cdecl MSVCRT$_vsnwprintf_s(wchar_t *buffer, size_t sizeOfBuffer, size_t count, const wchar_t *format, va_list argptr);

//OLE32
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CreateStreamOnHGlobal(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM *ppstm);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(LPCOLESTR lpsz, LPIID lpiid);

//OLEAUT32
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantClear(VARIANTARG *pvarg);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantChangeType(VARIANTARG *pvargDest, const VARIANTARG *pvarSrc, USHORT wFlags, VARTYPE vt);
DECLSPEC_IMPORT INT WINAPI OLEAUT32$SystemTimeToVariantTime(LPSYSTEMTIME lpSystemTime, DOUBLE *pvtime);

//NETAPI32
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR ComputerName, LPCWSTR DomainName, GUID *DomainGuid, LPCWSTR SiteName, ULONG Flags, PDOMAIN_CONTROLLER_INFOW *DomainControllerInfo);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);

//SECUR32
WINBASEAPI BOOLEAN WINAPI SECUR32$GetUserNameExW(EXTENDED_NAME_FORMAT NameFormat, LPWSTR lpNameBuffer, PULONG nSize);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle phCredential);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$DeleteSecurityContext(PCtxtHandle phContext);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleW(
	LPWSTR pszPrincipal,
    LPWSTR pszPackage,
    ULONG fCredentialUse,
    PVOID pvLogonId,
    PVOID pAuthData,
    SEC_GET_KEY_FN pGetKeyFn,
    PVOID pvGetKeyArgument,
    PCredHandle phCredential,
    PTimeStamp ptsExpiry
    );

WINBASEAPI SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextW(
	PCredHandle phCredential,
	PCtxtHandle phContext,
	PSECURITY_STRING pTargetName,
	ULONG fContextReq,
	ULONG Reserved1,
	ULONG TargetDataRep,
	PSecBufferDesc pInput,
	ULONG Reserved2,
	PCtxtHandle phNewContext,
	PSecBufferDesc pOutput,
	ULONG *pfContextAttr,
	PTimeStamp ptsExpiry
);

WINBASEAPI SECURITY_STATUS WINAPI SECUR32$AcceptSecurityContext(
	PCredHandle phCredential,
	PCtxtHandle phContext,
	PSecBufferDesc pInput,
	ULONG fContextReq,
	ULONG TargetDataRep,
	PCtxtHandle phNewContext,
	PSecBufferDesc pOutput,
	ULONG *pfContextAttr,
	PTimeStamp ptsExpiry
);

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
