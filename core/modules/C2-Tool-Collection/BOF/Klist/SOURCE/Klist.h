#pragma once

#include <windows.h>

#define AddEtype(n) { n, TEXT(#n) }

#define KERB_ETYPE_AES128_CTS_HMAC_SHA1_96    17
#define KERB_ETYPE_AES256_CTS_HMAC_SHA1_96    18

typedef enum _KERB_PROTOCOL_MESSAGE_TYPE_BOF {
	KerbQueryTicketCacheEx3MessageBof = 25
} KERB_PROTOCOL_MESSAGE_TYPE_BOF, *PKERB_PROTOCOL_MESSAGE_TYPE_BOF;

typedef struct _KERB_TICKET_CACHE_INFO_EX3_BOF {
	UNICODE_STRING ClientName;
	UNICODE_STRING ClientRealm;
	UNICODE_STRING ServerName;
	UNICODE_STRING ServerRealm;
	LARGE_INTEGER StartTime;
	LARGE_INTEGER EndTime;
	LARGE_INTEGER RenewTime;
	LONG EncryptionType;
	ULONG TicketFlags;
	ULONG SessionKeyType;
	ULONG BranchId;
	ULONG CacheFlags;
	UNICODE_STRING KdcCalled;
} KERB_TICKET_CACHE_INFO_EX3_BOF, *PKERB_TICKET_CACHE_INFO_EX3_BOF;

typedef struct _KERB_QUERY_TKT_CACHE_EX3_RESPONSE_BOF {
	KERB_PROTOCOL_MESSAGE_TYPE MessageType;
	ULONG CountOfTickets;
	KERB_TICKET_CACHE_INFO_EX3_BOF Tickets[ANYSIZE_ARRAY];
} KERB_QUERY_TKT_CACHE_EX3_RESPONSE_BOF, *PKERB_QUERY_TKT_CACHE_EX3_RESPONSE_BOF;

typedef struct _ETYPE {
	INT etype;
	LPCWSTR ename;
} ETYPE;

//MSVCRT
WINBASEAPI int __cdecl MSVCRT$swprintf_s(wchar_t *buffer, size_t sizeOfBuffer, const wchar_t *format, ...);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
WINBASEAPI errno_t __cdecl MSVCRT$wcscpy_s(wchar_t *_Dst, rsize_t _DstSize, const wchar_t *_Src);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1, const wchar_t *_Str2);
WINBASEAPI int __cdecl MSVCRT$_vsnwprintf_s(wchar_t *buffer, size_t sizeOfBuffer, size_t count, const wchar_t *format, va_list argptr);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);

//KERNEL32
WINBASEAPI int WINAPI KERNEL32$FileTimeToLocalFileTime(CONST FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
WINBASEAPI int WINAPI KERNEL32$FileTimeToSystemTime(CONST FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI KERNEL32$FormatMessageW(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize, va_list *Arguments);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);

//OLE32
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CreateStreamOnHGlobal(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM *ppstm);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(LPCOLESTR lpsz, LPIID lpiid);

//ADVAPI32
WINADVAPI ULONG WINAPI ADVAPI32$LsaNtStatusToWinError(NTSTATUS Status);

//SECUR32
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaConnectUntrusted(PHANDLE LsaHandle);
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE LsaHandle, PLSA_STRING PackageName, PULONG AuthenticationPackage);
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaCallAuthenticationPackage(HANDLE LsaHandle, ULONG AuthenticationPackage, PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus);
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaFreeReturnBuffer(PVOID Buffer);
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaDeregisterLogonProcess(HANDLE LsaHandle);

typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);