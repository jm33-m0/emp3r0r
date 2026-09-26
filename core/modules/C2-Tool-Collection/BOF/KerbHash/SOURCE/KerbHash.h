#pragma once

#include <windows.h>

#define STATUS_SUCCESS 0
#define STATUS_UNSUCCESSFUL 0xC0000001
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), s }

#define KERB_ETYPE_DES_CBC_MD5 3
#define KERB_ETYPE_AES128_CTS_HMAC_SHA1_96 17
#define KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 18
#define KERB_ETYPE_RC4_HMAC_NT 23

//KERNEL32
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);

//USER32
WINBASEAPI LPWSTR USER32$CharLowerW(LPWSTR lpsz);
WINBASEAPI LPWSTR USER32$CharUpperW(LPWSTR lpsz);

//MSVCRT
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void *dest, const void *src, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI int __cdecl MSVCRT$_vsnwprintf_s(wchar_t *buffer, size_t sizeOfBuffer, size_t count, const wchar_t *format, va_list argptr);

//OLE32
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CreateStreamOnHGlobal(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM *ppstm);

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef NTSTATUS(NTAPI* _RtlUpcaseUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCUNICODE_STRING SourceString,
	BOOLEAN AllocateDestinationString
	);

typedef NTSTATUS(NTAPI* _RtlDowncaseUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCUNICODE_STRING SourceString,
	BOOLEAN AllocateDestinationString
	);

typedef NTSTATUS(NTAPI* _RtlAppendUnicodeStringToString)(
	PUNICODE_STRING  Destination,
	PCUNICODE_STRING Source
	);

typedef NTSTATUS(NTAPI* _RtlAppendUnicodeToString)(
	PUNICODE_STRING Destination,
	PWSTR Source
	);

typedef void(WINAPI* _RtlFreeUnicodeString)(
	PUNICODE_STRING UnicodeString
	);

// From Mimikatz source
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_INITIALIZE) (LPCVOID pbKey, ULONG KeySize, ULONG MessageType, PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_ENCRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_DECRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_FINISH) (PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_HASHPASSWORD_NT5) (PCUNICODE_STRING Password, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_HASHPASSWORD_NT6) (PCUNICODE_STRING Password, PCUNICODE_STRING Salt, ULONG Count, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_RANDOMKEY) (LPCVOID Seed, ULONG SeedLength, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_CONTROL) (ULONG Function, PVOID pContext, PUCHAR InputBuffer, ULONG InputBufferSize);

typedef struct _KERB_ECRYPT {
	ULONG EncryptionType;
	ULONG BlockSize;
	ULONG ExportableEncryptionType;
	ULONG KeySize;
	ULONG HeaderSize;
	ULONG PreferredCheckSum;
	ULONG Attributes;
	PCWSTR Name;
	PKERB_ECRYPT_INITIALIZE Initialize;
	PKERB_ECRYPT_ENCRYPT Encrypt;
	PKERB_ECRYPT_DECRYPT Decrypt;
	PKERB_ECRYPT_FINISH Finish;
	union {
		PKERB_ECRYPT_HASHPASSWORD_NT5 HashPassword_NT5;
		PKERB_ECRYPT_HASHPASSWORD_NT6 HashPassword_NT6;
	};
	PKERB_ECRYPT_RANDOMKEY RandomKey;
	PKERB_ECRYPT_CONTROL Control;
	PVOID unk0_null;
	PVOID unk1_null;
	PVOID unk2_null;
} KERB_ECRYPT, * PKERB_ECRYPT;

typedef NTSTATUS(WINAPI* _CDLocateCSystem)(
	ULONG Type,
	PKERB_ECRYPT* ppCSystem
	);
