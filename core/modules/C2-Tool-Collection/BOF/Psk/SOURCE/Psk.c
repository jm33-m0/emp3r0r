#include <windows.h>

#if defined(WOW64)
#include "Syscalls-WoW64.h"
#else
#include "Syscalls.h"
#endif

#include "beacon.h"
#include "Psk.h"

#define MAX_SEC_PRD 20
#define MAX_STRING 8192

INT g_iGarbage = 1;
LPSTREAM g_lpStream = (LPSTREAM)1;
LPWSTR g_lpwPrintBuffer = (LPWSTR)1;
PSECPROD g_pSecProducts[MAX_SEC_PRD] = { (PSECPROD)1 };
DWORD g_dwMSMod = 1, g_dwNonMSMod = 1, g_dwSecModCount = 1, g_dwTotalMod = 1;

HRESULT BeaconPrintToStreamW(_In_z_ LPCWSTR lpwFormat, ...) {
	HRESULT hr = S_FALSE;
	va_list argList;
	DWORD dwWritten = 0;

	if (g_lpStream <= (LPSTREAM)1) {
		hr = OLE32$CreateStreamOnHGlobal(NULL, TRUE, &g_lpStream);
		if (FAILED(hr)) {
			return hr;
		}
	}

	// For BOF we need to avoid large stack buffers, so put print buffer on heap.
	if (g_lpwPrintBuffer <= (LPWSTR)1) { // Allocate once and free in BeaconOutputStreamW. 
		g_lpwPrintBuffer = (LPWSTR)MSVCRT$calloc(MAX_STRING, sizeof(WCHAR));
		if (g_lpwPrintBuffer == NULL) {
			hr = E_FAIL;
			goto CleanUp;
		}
	}

	va_start(argList, lpwFormat);
	if (!MSVCRT$_vsnwprintf_s(g_lpwPrintBuffer, MAX_STRING, MAX_STRING -1, lpwFormat, argList)) {
		hr = E_FAIL;
		goto CleanUp;
	}

	if (g_lpStream != NULL) {
		if (FAILED(hr = g_lpStream->lpVtbl->Write(g_lpStream, g_lpwPrintBuffer, (ULONG)MSVCRT$wcslen(g_lpwPrintBuffer) * sizeof(WCHAR), &dwWritten))) {
			goto CleanUp;
		}
	}

	hr = S_OK;

CleanUp:

	if (g_lpwPrintBuffer != NULL) {
		MSVCRT$memset(g_lpwPrintBuffer, 0, MAX_STRING * sizeof(WCHAR)); // Clear print buffer.
	}

	va_end(argList);
	return hr;
}

VOID BeaconOutputStreamW() {
	STATSTG ssStreamData = { 0 };
	SIZE_T cbSize = 0;
	ULONG cbRead = 0;
	LARGE_INTEGER pos;
	LPWSTR lpwOutput = NULL;

	if (FAILED(g_lpStream->lpVtbl->Stat(g_lpStream, &ssStreamData, STATFLAG_NONAME))) {
		return;
	}

	cbSize = ssStreamData.cbSize.LowPart;
	lpwOutput = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize + 1);
	if (lpwOutput != NULL) {
		pos.QuadPart = 0;
		if (FAILED(g_lpStream->lpVtbl->Seek(g_lpStream, pos, STREAM_SEEK_SET, NULL))) {
			goto CleanUp;
		}

		if (FAILED(g_lpStream->lpVtbl->Read(g_lpStream, lpwOutput, (ULONG)cbSize, &cbRead))) {		
			goto CleanUp;
		}

		BeaconPrintf(CALLBACK_OUTPUT, "%ls", lpwOutput);
	}

CleanUp:

	if (g_lpStream != NULL) {
		g_lpStream->lpVtbl->Release(g_lpStream);
		g_lpStream = NULL;
	}

	if (g_lpwPrintBuffer != NULL) {
		MSVCRT$free(g_lpwPrintBuffer); // Free print buffer.
		g_lpwPrintBuffer = NULL;
	}

	if (lpwOutput != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpwOutput);
	}

	return;
}

BOOL EnumSecurityProc(_In_ LPWSTR lpCompany, _In_ LPWSTR lpDescription) {
	LPCWSTR pwszCompany[27];
	pwszCompany[0] = L"ESET";
	pwszCompany[1] = L"McAfee";
	pwszCompany[2] = L"Symantec";
	pwszCompany[3] = L"Sophos";
	pwszCompany[4] = L"Panda";
	pwszCompany[5] = L"Bitdefender";
	pwszCompany[6] = L"Kaspersky";
	pwszCompany[7] = L"AVG";
	pwszCompany[8] = L"Avast";
	pwszCompany[9] = L"Trend Micro";
	pwszCompany[10] = L"F-Secure";
	pwszCompany[11] = L"Comodo";
	pwszCompany[12] = L"Cylance";
	pwszCompany[13] = L"CrowdStrike";
	pwszCompany[14] = L"Carbon Black";
	pwszCompany[15] = L"Palo Alto";
	pwszCompany[16] = L"Sentinel";
	pwszCompany[17] = L"Endgame";
	pwszCompany[18] = L"Cisco";
	pwszCompany[19] = L"Splunk";
	pwszCompany[20] = L"LogRhythm";
	pwszCompany[21] = L"Rapid7";
	pwszCompany[22] = L"Sysinternals";
	pwszCompany[23] = L"FireEye";
	pwszCompany[24] = L"Cybereason";
	pwszCompany[25] = L"Ivanti";
	pwszCompany[26] = L"Darktrace";

	const DWORD dwSize = _countof(pwszCompany);
	for (DWORD i = 0; i < dwSize && g_dwSecModCount < MAX_SEC_PRD; i++) {
		if (SHLWAPI$StrStrIW(lpCompany, pwszCompany[i])) {
			MSVCRT$memcpy(g_pSecProducts[g_dwSecModCount]->wcCompany, lpCompany, MSVCRT$wcslen(lpCompany) * sizeof(WCHAR));
			MSVCRT$memcpy(g_pSecProducts[g_dwSecModCount]->wcDescription, lpDescription, MSVCRT$wcslen(lpDescription) * sizeof(WCHAR));
			g_dwSecModCount++;
		}
	}

	if (g_dwSecModCount < MAX_SEC_PRD) {
		//Windows Defender (ATP)
		if (SHLWAPI$StrStrIW(lpDescription, L"Antimalware") || SHLWAPI$StrStrIW(lpDescription, L"Windows Defender")) {
			MSVCRT$memcpy(g_pSecProducts[g_dwSecModCount]->wcCompany, lpCompany, MSVCRT$wcslen(lpCompany) * sizeof(WCHAR));
			MSVCRT$memcpy(g_pSecProducts[g_dwSecModCount]->wcDescription, lpDescription, MSVCRT$wcslen(lpDescription) * sizeof(WCHAR));
			g_dwSecModCount++;
		}
	}

	if (g_dwSecModCount < MAX_SEC_PRD) {
		//Carbon Black
		if (SHLWAPI$StrStrIW(lpDescription, L"Carbon Black")) {
			MSVCRT$memcpy(g_pSecProducts[g_dwSecModCount]->wcCompany, lpCompany, MSVCRT$wcslen(lpCompany) * sizeof(WCHAR));
			MSVCRT$memcpy(g_pSecProducts[g_dwSecModCount]->wcDescription, lpDescription, MSVCRT$wcslen(lpDescription) * sizeof(WCHAR));
			g_dwSecModCount++;
		}
	}

	//MS
	if (SHLWAPI$StrStrIW(lpCompany, L"Microsoft")) {
		g_dwMSMod++;
	}
	else {
		g_dwNonMSMod++;
	}

	MSVCRT$memset(pwszCompany, 0, sizeof(pwszCompany));

	return TRUE;
}

BOOL PrintSummary() {
	if (g_dwSecModCount > 0) {
		BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");
		BeaconPrintToStreamW(L"[!] Security products found: %d\n", g_dwSecModCount);

		for (DWORD i = 0; i < g_dwSecModCount; i++) {
			BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Vendor:", g_pSecProducts[i]->wcCompany);
			BeaconPrintToStreamW(L"%-18ls %ls\n\n", L"    Product:", g_pSecProducts[i]->wcDescription);
		}
	}

	BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");
	BeaconPrintToStreamW(L"[S] Kernel Module summary:\n");
	BeaconPrintToStreamW(L"    Microsoft kernel modules:   %d\n", g_dwMSMod);
	BeaconPrintToStreamW(L"    Non Microsoft modules:      %d\n\n", g_dwNonMSMod);

	BeaconPrintToStreamW(L"    Total active Modules:       %d\n\n", g_dwTotalMod);

	return TRUE;
}

BOOL EnumFileProperties(_In_ DWORD dwCount, _In_ PUNICODE_STRING uProcImage, _In_opt_ LPVOID moduleBase, _In_ BOOL bEnumSecurityProc) {
	NTSTATUS status;
	IO_STATUS_BLOCK IoStatusBlock;
	OBJECT_ATTRIBUTES FileObjectAttributes;
	HANDLE hFile = NULL;
	DWORD dwBinaryType = SCS_32BIT_BINARY;
	PBYTE lpVerInfo = NULL;
	LPWSTR lpCompany = NULL;
	LPWSTR lpDescription = NULL;
	LPWSTR lpProductVersion = NULL;

	if (uProcImage != NULL){
		InitializeObjectAttributes(&FileObjectAttributes, uProcImage, OBJ_CASE_INSENSITIVE, NULL, NULL);
	}
	else{
		goto CleanUp;
	}

	MSVCRT$memset(&IoStatusBlock, 0, sizeof(IoStatusBlock));
	NTSTATUS Status = ZwCreateFile(&hFile, GENERIC_READ | SYNCHRONIZE, &FileObjectAttributes, &IoStatusBlock, 0,
		0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

	if (hFile == NULL && Status != STATUS_SUCCESS) {
		goto CleanUp;
	}
	else if (hFile == INVALID_HANDLE_VALUE && Status != STATUS_SUCCESS) {
		goto CleanUp;
	}

	WCHAR lpszFilePath[MAX_PATH] = { 0 };
	DWORD dwResult = KERNEL32$GetFinalPathNameByHandleW(hFile, lpszFilePath, _countof(lpszFilePath) - 1, VOLUME_NAME_DOS);
	if (dwResult == 0) {
		goto CleanUp;
	}
	else if (dwResult >= _countof(lpszFilePath)) {
		goto CleanUp;
	}

	LPWSTR pwszPath = NULL;
	LPWSTR pwszJunk = MSVCRT$wcstok_s(lpszFilePath, L"\\", &pwszPath);
	if (pwszJunk == NULL || pwszPath == NULL) {
		goto CleanUp;
	}

	if (dwCount == 0) {
		BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Path:", pwszPath);
	}
	else {
		BeaconPrintToStreamW(L"%-18ls %ls\n", L"[K] ModulePath:", pwszPath);
	}

#if !defined(WOW64)
	if (moduleBase != NULL){
		BeaconPrintToStreamW(L"%-18ls 0x%p \n", L"    BaseAddress:", moduleBase);
	}

	if (KERNEL32$GetBinaryTypeW(pwszPath, &dwBinaryType)) {
		if (dwBinaryType == SCS_64BIT_BINARY) {
			BeaconPrintToStreamW(L"%-18ls %ls\n", L"    ImageType:", L"64-bit");
		}
		else {
			BeaconPrintToStreamW(L"%-18ls %ls\n", L"    ImageType:", L"32-bit");
		}
	}
#endif

	DWORD dwHandle = 0;
	DWORD dwLen = VERSION$GetFileVersionInfoSizeW(pwszPath, &dwHandle);
	if (!dwLen) {
		goto CleanUp;
	}

	lpVerInfo = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen);
	if (lpVerInfo == NULL) {
		goto CleanUp;
	}

	if (!VERSION$GetFileVersionInfoW(pwszPath, 0L, dwLen, lpVerInfo)) {
		goto CleanUp;
	}

	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;

	WCHAR wcCodePage[MAX_PATH];
	MSVCRT$memset(&wcCodePage, 0, sizeof(wcCodePage));
	WCHAR wcCompanyName[MAX_PATH];
	MSVCRT$memset(&wcCompanyName, 0, sizeof(wcCompanyName));
	WCHAR wcDescription[MAX_PATH];
	MSVCRT$memset(&wcDescription, 0, sizeof(wcDescription));
	WCHAR wcProductVersion[MAX_PATH];
	MSVCRT$memset(&wcProductVersion, 0, sizeof(wcProductVersion));

	UINT uLen;
	if (VERSION$VerQueryValueW(lpVerInfo, L"\\VarFileInfo\\Translation", (void **)&lpTranslate, &uLen)) {
		MSVCRT$swprintf_s(wcCodePage, _countof(wcCodePage), L"%04x%04x", lpTranslate->wLanguage, lpTranslate->wCodePage);

		MSVCRT$wcscat_s(wcCompanyName, _countof(wcCompanyName), L"\\StringFileInfo\\");
		MSVCRT$wcscat_s(wcCompanyName, _countof(wcCompanyName), wcCodePage);
		MSVCRT$wcscat_s(wcCompanyName, _countof(wcCompanyName), L"\\CompanyName");

		MSVCRT$wcscat_s(wcDescription, _countof(wcDescription), L"\\StringFileInfo\\");
		MSVCRT$wcscat_s(wcDescription, _countof(wcDescription), wcCodePage);
		MSVCRT$wcscat_s(wcDescription, _countof(wcDescription), L"\\FileDescription");

		MSVCRT$wcscat_s(wcProductVersion, _countof(wcProductVersion), L"\\StringFileInfo\\");
		MSVCRT$wcscat_s(wcProductVersion, _countof(wcProductVersion), wcCodePage);
		MSVCRT$wcscat_s(wcProductVersion, _countof(wcProductVersion), L"\\ProductVersion");

		if (VERSION$VerQueryValueW(lpVerInfo, wcCompanyName, (void **)&lpCompany, &uLen)) {
			BeaconPrintToStreamW(L"%-18ls %ls\n", L"    CompanyName:", lpCompany);
		}
		if (VERSION$VerQueryValueW(lpVerInfo, wcDescription, (void **)&lpDescription, &uLen)) {
			BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Description:", lpDescription);
		}
		if (VERSION$VerQueryValueW(lpVerInfo, wcProductVersion, (void **)&lpProductVersion, &uLen)) {
			BeaconPrintToStreamW(L"%-18ls %ls\n\n", L"    Version:", lpProductVersion);
		}

		if (bEnumSecurityProc){
			EnumSecurityProc(lpCompany, lpDescription);
		}
	}

CleanUp:

	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		ZwClose(hFile);
	}

	if (lpVerInfo != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpVerInfo);
	}

	return TRUE;
}

BOOL EnumKernel() {
	NTSTATUS status;
	LPVOID pModInfoBuffer = NULL;
	SIZE_T modInfoSize = 0x10000;
	ULONG uReturnLength = 0;
	PSYSTEM_MODULE_INFORMATION pModuleInfo = NULL;
	ANSI_STRING aKernelModule;
	UNICODE_STRING uKernelModule;

	_RtlInitAnsiString RtlInitAnsiString = (_RtlInitAnsiString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitAnsiString");
	if (RtlInitAnsiString == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.\n");
		return FALSE;
	}

	_RtlAnsiStringToUnicodeString RtlAnsiStringToUnicodeString = (_RtlAnsiStringToUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAnsiStringToUnicodeString");
	if (RtlAnsiStringToUnicodeString == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.\n");
		return FALSE;
	}

	_RtlFreeUnicodeString RtlFreeUnicodeString = (_RtlFreeUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlFreeUnicodeString");
	if (RtlFreeUnicodeString == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.\n");
		return FALSE;
	}

	do {
		pModInfoBuffer = NULL;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pModInfoBuffer, 0, &modInfoSize, MEM_COMMIT, PAGE_READWRITE);
		if (status != STATUS_SUCCESS) {
			BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory.");
			return FALSE;
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, pModInfoBuffer, (ULONG)modInfoSize, &uReturnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ZwFreeVirtualMemory(NtCurrentProcess(), &pModInfoBuffer, &modInfoSize, MEM_RELEASE);
			modInfoSize += uReturnLength;
		}

	} while (status != STATUS_SUCCESS);

	pModuleInfo = (PSYSTEM_MODULE_INFORMATION)pModInfoBuffer;
	g_dwTotalMod = pModuleInfo->NumberOfModules;

	for (DWORD i = 0; i < pModuleInfo->NumberOfModules; i++) {
		RtlInitAnsiString(&aKernelModule, (PSTR)pModuleInfo->Module[i].FullPathName);
		RtlAnsiStringToUnicodeString(&uKernelModule, &aKernelModule, TRUE);
		if (uKernelModule.Buffer != NULL) {
			EnumFileProperties(i, &uKernelModule, pModuleInfo->Module[i].ImageBase, TRUE);
			RtlFreeUnicodeString(&uKernelModule);
			uKernelModule.Buffer = NULL;
		}
	}

CleanUp:

	if (pModInfoBuffer == NULL) {
		ZwFreeVirtualMemory(NtCurrentProcess(), &pModInfoBuffer, &modInfoSize, MEM_RELEASE);
	}

	return TRUE;
}

VOID go(_In_ PCHAR Args, _In_ ULONG Length) {
	NTSTATUS status;
	PSYSTEM_PROCESSES pProcInfo = NULL;
	LPVOID pProcInfoBuffer = NULL;
	SIZE_T procInfoSize = 0x10000;
	ULONG uReturnLength = 0;
	FILETIME ftCreate;
	SYSTEMTIME stUTC, stLocal;
	DWORD SessionID;
	g_dwMSMod = 0, g_dwNonMSMod = 0, g_dwSecModCount = 0, g_dwTotalMod = 0;

	for (DWORD i = 0; i < MAX_SEC_PRD; i++) {
		g_pSecProducts[i] = (PSECPROD)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECPROD));
	}

	do {
		pProcInfoBuffer = NULL;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, 0, &procInfoSize, MEM_COMMIT, PAGE_READWRITE);
		if (status != STATUS_SUCCESS) {
			BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory.");
			return;
		}

		status = ZwQuerySystemInformation(SystemProcessInformation, pProcInfoBuffer, (ULONG)procInfoSize, &uReturnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ZwFreeVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, &procInfoSize, MEM_RELEASE);
			procInfoSize += uReturnLength;
		}

	} while (status != STATUS_SUCCESS);

	pProcInfo = (PSYSTEM_PROCESSES)pProcInfoBuffer;
	do {
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

		BeaconPrintToStreamW(L"%-19ls %wZ\n", L"\n[I] ProcessName:", &pProcInfo->ProcessName);
		BeaconPrintToStreamW(L"%-18ls %lu\n", L"    ProcessID:", HandleToULong(pProcInfo->ProcessId));
		BeaconPrintToStreamW(L"%-18ls %lu ", L"    PPID:", HandleToULong(pProcInfo->InheritedFromProcessId));

		PSYSTEM_PROCESSES pParentInfo = (PSYSTEM_PROCESSES)pProcInfoBuffer;
		do {
			pParentInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pParentInfo) + pParentInfo->NextEntryDelta);

			if (HandleToULong(pParentInfo->ProcessId) == HandleToULong(pProcInfo->InheritedFromProcessId)) {
				BeaconPrintToStreamW(L"(%wZ)\n", &pParentInfo->ProcessName);
				break;
			}
			else if (pParentInfo->NextEntryDelta == 0) {
				BeaconPrintToStreamW(L"(Non-existent process)\n");
				break;
			}

		} while (pParentInfo);

		ftCreate.dwLowDateTime = pProcInfo->CreateTime.LowPart;
		ftCreate.dwHighDateTime = pProcInfo->CreateTime.HighPart;
		
		// Convert the Createtime to local time.
		KERNEL32$FileTimeToSystemTime(&ftCreate, &stUTC);
		if (KERNEL32$SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal)) {
			BeaconPrintToStreamW(L"%-18ls %02d/%02d/%d %02d:%02d\n", L"    CreateTime:", stLocal.wDay, stLocal.wMonth, stLocal.wYear, stLocal.wHour, stLocal.wMinute);
		}

		if (KERNEL32$ProcessIdToSessionId(HandleToULong(pProcInfo->ProcessId), &SessionID)) {
			BeaconPrintToStreamW(L"%-18ls %d\n", L"    SessionID:", SessionID);
		}

		if (HandleToULong(pProcInfo->ProcessId) == 4) {
			EnumKernel();
			break;
		}

		if (pProcInfo->NextEntryDelta == 0) {
			break;
		}

	} while (pProcInfo);

	PrintSummary();

CleanUp:

	if (pProcInfoBuffer != NULL) {
		ZwFreeVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, &procInfoSize, MEM_RELEASE);
	}

	if (g_pSecProducts[0] != NULL) {
		for (DWORD i = 0; i < MAX_SEC_PRD; i++) {
			KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, g_pSecProducts[i]);
		}
	}

	BeaconOutputStreamW();
	return;
}
