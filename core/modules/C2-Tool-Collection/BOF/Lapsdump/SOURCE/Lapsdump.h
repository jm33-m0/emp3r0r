#pragma once

#include <windows.h>
#include <activeds.h>


//KERNEL32
WINBASEAPI int WINAPI KERNEL32$FileTimeToLocalFileTime(CONST FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
WINBASEAPI int WINAPI KERNEL32$FileTimeToSystemTime(CONST FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);

//MSVCRT
WINBASEAPI int __cdecl MSVCRT$swprintf_s(wchar_t *buffer, size_t sizeOfBuffer, const wchar_t *format, ...);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
WINBASEAPI errno_t __cdecl MSVCRT$wcscpy_s(wchar_t *_Dst, rsize_t _DstSize, const wchar_t *_Src);

//OLE32
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(LPCOLESTR lpsz, LPIID lpiid);

//OLEAUT32
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantClear(VARIANTARG *pvarg);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantChangeType(VARIANTARG *pvargDest, const VARIANTARG *pvarSrc, USHORT wFlags, VARTYPE vt);
DECLSPEC_IMPORT INT WINAPI OLEAUT32$SystemTimeToVariantTime(LPSYSTEMTIME lpSystemTime, DOUBLE *pvtime);

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
