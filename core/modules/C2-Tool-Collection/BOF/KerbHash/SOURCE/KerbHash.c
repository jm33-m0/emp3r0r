#include <windows.h>
#include <ntsecapi.h>

#include "KerbHash.h"
#include "beacon.h"

#define MIN_BUF 512
#define MAX_BUF 1024

INT iGarbage = 1;
LPSTREAM lpStream = (LPSTREAM)1;

HRESULT BeaconPrintToStreamW(_In_z_ LPCWSTR lpwFormat, ...) {
	HRESULT hr = S_OK;
	va_list argList;
	WCHAR chBuffer[1024];
	DWORD dwWritten = 0;

	if (lpStream <= (LPSTREAM)1) {
		hr = OLE32$CreateStreamOnHGlobal(NULL, TRUE, &lpStream);
		if (FAILED(hr)) {
			return hr;
		}
	}

	va_start(argList, lpwFormat);
	MSVCRT$memset(chBuffer, 0, sizeof(chBuffer));
	if (!MSVCRT$_vsnwprintf_s(chBuffer, _countof(chBuffer), _TRUNCATE, lpwFormat, argList)) {
		hr = E_FAIL;
		goto CleanUp;
	}

	if (FAILED(hr = lpStream->lpVtbl->Write(lpStream, chBuffer, (ULONG)MSVCRT$wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
		goto CleanUp;
	}

CleanUp:

	va_end(argList);
	return hr;
}

VOID BeaconOutputStreamW() {
	STATSTG ssStreamData = { 0 };
	SIZE_T cbSize = 0;
	ULONG cbRead = 0;
	LARGE_INTEGER pos;
	LPWSTR lpwOutput = NULL;

	if (FAILED(lpStream->lpVtbl->Stat(lpStream, &ssStreamData, STATFLAG_NONAME))) {
		return;
	}

	cbSize = ssStreamData.cbSize.LowPart;
	lpwOutput = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize + 1);
	if (lpwOutput != NULL) {
		pos.QuadPart = 0;
		if (FAILED(lpStream->lpVtbl->Seek(lpStream, pos, STREAM_SEEK_SET, NULL))) {
			goto CleanUp;
		}

		if (FAILED(lpStream->lpVtbl->Read(lpStream, lpwOutput, (ULONG)cbSize, &cbRead))) {		
			goto CleanUp;
		}

		BeaconPrintf(CALLBACK_OUTPUT, "%ls", lpwOutput);
	}

CleanUp:

	if (lpStream != NULL) {
		lpStream->lpVtbl->Release(lpStream);
		lpStream = NULL;
	}

	if (lpwOutput != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpwOutput);
	}

	return;
}

BOOL IsMachine(_In_z_ LPCWSTR lpszAccount) {
	if (lpszAccount) {
		SIZE_T Len = MSVCRT$wcslen(lpszAccount);
		if (lpszAccount[Len -1] == '$') {
			return TRUE;
		}
	}
	return FALSE;
}

NTSTATUS HashDataRaw(_In_ LONG keyType, _In_ PCUNICODE_STRING pString, _In_ PCUNICODE_STRING pSalt, _In_ DWORD count, _Inout_ PBYTE* buffer, _Inout_ DWORD* dwBuffer) {
	PKERB_ECRYPT pCSystem = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	_CDLocateCSystem CDLocateCSystem = (_CDLocateCSystem)GetProcAddress(GetModuleHandleA("cryptdll.dll"), "CDLocateCSystem");
	if (CDLocateCSystem == NULL) {
		return status;
	}

	status = CDLocateCSystem(keyType, &pCSystem);
	if (NT_SUCCESS(status)) {
		if (*buffer = (PBYTE)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, pCSystem->KeySize)) {
			*dwBuffer = pCSystem->KeySize;
			status = pCSystem->HashPassword_NT6(pString, pSalt, count, *buffer);
			if (!NT_SUCCESS(status)) {
				KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, *buffer);
				BeaconPrintf(CALLBACK_ERROR, "HashPassword : %08x\n", status);
			}
		}
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "CDLocateCSystem : %08x\n", status);
	}

	return status;
}

NTSTATUS HashData(_In_ LONG keyType, _In_ PCUNICODE_STRING pString, _In_ PCUNICODE_STRING pSalt, _In_ DWORD count) {
	PBYTE pBytes = NULL;
	DWORD dwSize = 0;

	NTSTATUS status = HashDataRaw(keyType, pString, pSalt, count, &pBytes, &dwSize);
	if (NT_SUCCESS(status)) {
		if (keyType == KERB_ETYPE_RC4_HMAC_NT) {
			BeaconPrintToStreamW(L"[+]\t rc4_hmac \t\t: ");
		}
		else if (keyType == KERB_ETYPE_AES128_CTS_HMAC_SHA1_96) {
			BeaconPrintToStreamW(L"[+]\t aes128_cts_hmac_sha1 \t: ");
		}
		else if (keyType == KERB_ETYPE_AES256_CTS_HMAC_SHA1_96) {
			BeaconPrintToStreamW(L"[+]\t aes256_cts_hmac_sha1 \t: ");
		}
		else if (keyType == KERB_ETYPE_DES_CBC_MD5) {
			BeaconPrintToStreamW(L"[+]\t des_cbc_md5 \t\t: ");
		}
		else {
			BeaconPrintToStreamW(L"[+]\t unknown \t\t: ");
		}

		for (DWORD i = 0; i < dwSize; i++) {
			BeaconPrintToStreamW(L"%02X", ((LPCBYTE)pBytes)[i]);
		}

		BeaconPrintToStreamW(L"\n");
	}

	if (pBytes != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pBytes);
	}

	return status;
}

VOID go(IN PCHAR Args, IN ULONG Length) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING uPassword = { 0, 0, NULL }, uUsername = { 0, 0, NULL }, uDomain = { 0, 0, NULL }, uDomainCase = { 0, 0, NULL }, uSalt = { 0, 0, NULL }, uPasswordWithSalt = { 0, 0, NULL };
	PUNICODE_STRING pString = NULL;
	DWORD count = 4096, i = 0;
	LONG kerbType[] = { KERB_ETYPE_RC4_HMAC_NT, KERB_ETYPE_AES128_CTS_HMAC_SHA1_96, KERB_ETYPE_AES256_CTS_HMAC_SHA1_96, KERB_ETYPE_DES_CBC_MD5 };
	WCHAR wcComputer[MIN_BUF] = { 0 };
    LPCWSTR lpwPassword = NULL;
	LPCWSTR lpwUsername = NULL;
    LPCWSTR lpwDomain = NULL;

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);
    
    lpwPassword = (WCHAR*)BeaconDataExtract(&parser, NULL);
	lpwUsername = (WCHAR*)BeaconDataExtract(&parser, NULL);
    lpwDomain = (WCHAR*)BeaconDataExtract(&parser, NULL);
    if (lpwPassword == NULL || lpwUsername == NULL || lpwDomain == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Missing argument.\n");
		return;
	}

    HINSTANCE hModule = LoadLibraryA("cryptdll.dll");
	if (hModule == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to load cryptdll.dll\n");
		return;
	}

    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.\n");
		return;
	}

	_RtlUpcaseUnicodeString RtlUpcaseUnicodeString = (_RtlUpcaseUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUpcaseUnicodeString");
	if (RtlUpcaseUnicodeString == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.\n");
		return;
	}

	_RtlDowncaseUnicodeString RtlDowncaseUnicodeString = (_RtlDowncaseUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlDowncaseUnicodeString");
	if (RtlDowncaseUnicodeString == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.\n");
		return;
	}

	_RtlAppendUnicodeStringToString RtlAppendUnicodeStringToString = (_RtlAppendUnicodeStringToString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAppendUnicodeStringToString");
	if (RtlAppendUnicodeStringToString == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.\n");
		return;
	}

	_RtlAppendUnicodeToString RtlAppendUnicodeToString = (_RtlAppendUnicodeToString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAppendUnicodeToString");
	if (RtlAppendUnicodeToString == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.\n");
		return;
	}

	_RtlFreeUnicodeString RtlFreeUnicodeString = (_RtlFreeUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlFreeUnicodeString");
	if (RtlFreeUnicodeString == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.\n");
		return;
	}

    BeaconPrintToStreamW(L"[+] Calculate Password Hashes\n\n");
	BeaconPrintToStreamW(L"[+] Input Password\t\t: %ls\n", lpwPassword);
	BeaconPrintToStreamW(L"[+] Input Username\t\t: %ls\n", lpwUsername);
	BeaconPrintToStreamW(L"[+] Input Domain\t\t\t: %ls\n", lpwDomain);

    RtlInitUnicodeString(&uPassword, lpwPassword);
	RtlInitUnicodeString(&uDomain, lpwDomain);

    uDomainCase.Buffer = NULL;
	RtlUpcaseUnicodeString(&uDomainCase, &uDomain, TRUE);

    uSalt.Buffer = NULL;
    uSalt.MaximumLength = MAX_BUF;
	uSalt.Buffer = (PWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_BUF);
    if (uSalt.Buffer != NULL) {
		RtlAppendUnicodeStringToString(&uSalt, &uDomainCase);
		
		if (IsMachine(lpwUsername)) {
			RtlAppendUnicodeToString(&uSalt, (PWSTR)L"host");

			MSVCRT$memcpy(wcComputer, lpwUsername, (MSVCRT$wcslen(lpwUsername) - 1) * sizeof(WCHAR));
			RtlAppendUnicodeToString(&uSalt, USER32$CharLowerW(wcComputer));
			RtlAppendUnicodeToString(&uSalt, (PWSTR)L".");

			RtlDowncaseUnicodeString(&uDomainCase, &uDomain, FALSE);
			RtlAppendUnicodeStringToString(&uSalt, &uDomainCase);
		}
		else {
			RtlInitUnicodeString(&uUsername, lpwUsername);
			RtlAppendUnicodeStringToString(&uSalt, &uUsername);
		}

        uSalt.MaximumLength = (USHORT)MSVCRT$wcslen(uSalt.Buffer) * sizeof(WCHAR);
		BeaconPrintToStreamW(L"[+] Salt\t\t\t\t: %wZ\n", &uSalt);

        uPasswordWithSalt.Buffer = NULL;
		uPasswordWithSalt.MaximumLength = uPassword.Length + uSalt.Length + sizeof(WCHAR);
		uPasswordWithSalt.Buffer = (PWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, uPasswordWithSalt.MaximumLength);
		if (uPasswordWithSalt.Buffer != NULL) {
			RtlAppendUnicodeStringToString(&uPasswordWithSalt, &uPassword);
			RtlAppendUnicodeStringToString(&uPasswordWithSalt, &uSalt);

			for (i = 0; i < ARRAYSIZE(kerbType); i++) {
				pString = (kerbType[i] != KERB_ETYPE_DES_CBC_MD5) ? &uPassword : &uPasswordWithSalt;
				status = HashData(kerbType[i], pString, &uSalt, count);
			}
		}
	}

    //Print final Output
    BeaconOutputStreamW();

    if (uDomainCase.Buffer != NULL) {
		RtlFreeUnicodeString(&uDomainCase);
	}

	if (uSalt.Buffer != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, uSalt.Buffer);
	}

	if (uPasswordWithSalt.Buffer != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, uPasswordWithSalt.Buffer);
	}

    return;
}
