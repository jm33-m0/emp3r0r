#include <windows.h>
#include <stdio.h>

#include "Winver.h"
#if defined(WOW64)
#include "Syscalls-WoW64.h"
#else
#include "Syscalls.h"
#endif
#include "beacon.h"


HANDLE OpenRegKeyHandle(INT DesiredAccess, PUNICODE_STRING RegistryKeyName) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE regKeyHandle = NULL;

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, RegistryKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = ZwOpenKey(&regKeyHandle, DesiredAccess, &ObjectAttributes);
	if (Status != STATUS_SUCCESS) {
		return NULL;
	}

	return regKeyHandle;
}

// Read UBR (Update Build Revision) from registry
DWORD ReadUBRFromRegistry() {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE regKeyHandle = NULL;
	UNICODE_STRING RegistryKeyName;	
	UNICODE_STRING KeyValueName;
	PKEY_VALUE_FULL_INFORMATION KeyValueInformation = NULL;
	ULONG KeyResultLength = 0;
	DWORD dwValueData = 0;

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return 0;
	}

	RtlInitUnicodeString(&RegistryKeyName, L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");
	RtlInitUnicodeString(&KeyValueName, L"UBR");

	regKeyHandle = OpenRegKeyHandle(KEY_QUERY_VALUE, &RegistryKeyName);
	if (regKeyHandle == NULL) {
		return 0;
	}

	Status = ZwQueryValueKey(regKeyHandle, &KeyValueName, KeyValueFullInformation, NULL, 0, &KeyResultLength);
	if (Status != STATUS_BUFFER_TOO_SMALL) {
		goto CleanUp;
	}

	KeyValueInformation = (PKEY_VALUE_FULL_INFORMATION)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, KeyResultLength);
	Status = ZwQueryValueKey(regKeyHandle, &KeyValueName, KeyValueFullInformation, KeyValueInformation, KeyResultLength, &KeyResultLength);
	if (Status != STATUS_SUCCESS) {
		goto CleanUp;
	}

	dwValueData = *((DWORD*)((PUCHAR)&KeyValueInformation[0] + KeyValueInformation[0].DataOffset));

CleanUp:

	if (regKeyHandle != NULL) {
		ZwClose(regKeyHandle);
	}

	if (KeyValueInformation != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, KeyValueInformation);
	}

	return dwValueData;
}

LPWSTR GetOSVersionAsString() {
	LPWSTR lpwOSName = NULL;

	HINSTANCE hModule = LoadLibraryA("winbrand.dll");
	if (hModule == NULL) {
		return NULL;
	}

	_BrandingFormatString BrandingFormatString = (_BrandingFormatString)
		GetProcAddress(GetModuleHandleA("winbrand.dll"), "BrandingFormatString");
	if (BrandingFormatString == NULL) {
		return NULL;
	}

	lpwOSName = BrandingFormatString(L"%WINDOWS_LONG%");
	FreeLibrary(hModule);

	if (MSVCRT$_wcsicmp(lpwOSName, L"%WINDOWS_LONG%") == 0) {
		return NULL;
	}

	return lpwOSName;
}

VOID go(IN PCHAR Args, IN ULONG Length) {
	WCHAR chOSMajorMinor[8];
	LPWSTR lpwOSName = NULL;
	PNT_TIB pTIB = NULL;
	PTEB pTEB = NULL;
	PPEB pPEB = NULL;
	DWORD dwUBR = 0;

	pTIB = (PNT_TIB)GetTEBAsm64();

	pTEB = (PTEB)pTIB->Self;
	pPEB = (PPEB)pTEB->ProcessEnvironmentBlock;
	if (pPEB == NULL) {
		return;
	}

	MSVCRT$swprintf_s(chOSMajorMinor, sizeof(chOSMajorMinor), L"%u.%u", pPEB->OSMajorVersion, pPEB->OSMinorVersion);

	lpwOSName = GetOSVersionAsString();
	dwUBR = ReadUBRFromRegistry();
	if (dwUBR != 0) {
		if (lpwOSName != NULL) {
			BeaconPrintf(CALLBACK_OUTPUT, "%ls, OS build number: %u.%u\n", lpwOSName, pPEB->OSBuildNumber, dwUBR);
		}
		else{
			BeaconPrintf(CALLBACK_OUTPUT, "Windows version: %ls, OS build number: %u.%u\n", chOSMajorMinor, pPEB->OSBuildNumber, dwUBR);
		}
	}
	else {
		if (lpwOSName != NULL) {
			BeaconPrintf(CALLBACK_OUTPUT, "%ls, OS build number: %u\n", lpwOSName, pPEB->OSBuildNumber);
		}
		else{
			BeaconPrintf(CALLBACK_OUTPUT, "Windows version: %ls, OS build number: %u\n", chOSMajorMinor, pPEB->OSBuildNumber);
		}
	}

	if (lpwOSName != NULL) {
		KERNEL32$GlobalFree((HGLOBAL)lpwOSName);
	}
	
	return;
}
