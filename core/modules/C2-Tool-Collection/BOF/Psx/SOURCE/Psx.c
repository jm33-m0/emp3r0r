#include <windows.h>

#if defined(WOW64)
#include "Syscalls-WoW64.h"
#else
#include "Syscalls.h"
#endif

#include "beacon.h"
#include "Psx.h"

#define MAX_SEC_PRD 20
#define MAX_NAME 256
#define MAX_STRING 18192

INT g_iGarbage = 1;
LPSTREAM g_lpStream = (LPSTREAM)1;
LPWSTR g_lpwPrintBuffer = (LPWSTR)1;
LPWSTR g_lpwReadBuf = (LPWSTR)1;
PSECPROD g_pSecProducts[MAX_SEC_PRD] = { (PSECPROD)1 };
DWORD g_dwMSProc = 1, g_dwNonMSProc = 1, g_dwSecProcCount = 1;

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

BOOL IsProcessWoW64(_In_ HANDLE hProcess) {
	NTSTATUS status;
	ULONG_PTR IsWow64 = 0;

	status = ZwQueryInformationProcess(hProcess, ProcessWow64Information, &IsWow64, sizeof(ULONG_PTR), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	if (IsWow64 == 0) {
		return FALSE;
	}

	return TRUE;
}

ULONG GetPid() {
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	
	NTSTATUS status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	if (status != STATUS_SUCCESS) {
		return 0;
	}

	return (ULONG)pbi.UniqueProcessId;
}

BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;

	_NtOpenProcessToken NtOpenProcessToken = (_NtOpenProcessToken)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcessToken");
	if (NtOpenProcessToken == NULL) {
		return FALSE;
	}

	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken);
	if (status == STATUS_SUCCESS) {
		TOKEN_ELEVATION Elevation = { 0 };
		ULONG ReturnLength;

		status = ZwQueryInformationToken(hToken, TokenElevation, &Elevation, sizeof(Elevation), &ReturnLength);
		if (status == STATUS_SUCCESS) {
			fRet = Elevation.TokenIsElevated;
		}
	}

	if (hToken != NULL) {
		ZwClose(hToken);
	}

	return fRet;
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

LPWSTR GetProcessUser(_In_ HANDLE hProcess, _In_ BOOL bCloseHandle, _In_ BOOL bReturnDomainname, _In_ BOOL bReturnUsername) {
	HANDLE hToken = NULL;
	ULONG ReturnLength;
	PTOKEN_USER Ptoken_User = NULL;
	WCHAR lpName[MAX_NAME];
	WCHAR lpDomain[MAX_NAME];
	DWORD dwSize = MAX_NAME;
	LPWSTR lpwUser = NULL;
	SID_NAME_USE SidType;

	_NtOpenProcessToken NtOpenProcessToken = (_NtOpenProcessToken)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcessToken");
	if (NtOpenProcessToken == NULL) {
		return NULL;
	}

	NTSTATUS status = NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	if (status == STATUS_SUCCESS) {
		status = ZwQueryInformationToken(hToken, TokenUser, NULL, 0, &ReturnLength);
		if (status != STATUS_BUFFER_TOO_SMALL) {
			goto CleanUp;
		}

		Ptoken_User = (PTOKEN_USER)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ReturnLength);
		status = ZwQueryInformationToken(hToken, TokenUser, Ptoken_User, ReturnLength, &ReturnLength);
		if (status != STATUS_SUCCESS) {
			goto CleanUp;
		}

		if (!ADVAPI32$LookupAccountSidW(NULL, Ptoken_User->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType)) {
			goto CleanUp;
		}

		lpwUser = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_NAME * sizeof(WCHAR));
		if (lpwUser != NULL) {
			if (bReturnDomainname) {
				MSVCRT$wcscat_s(lpwUser, MAX_NAME, lpDomain);
				if (bReturnUsername) {
					MSVCRT$wcscat_s(lpwUser, MAX_NAME, L"\\");
				}
			}
			if (bReturnUsername) {
				MSVCRT$wcscat_s(lpwUser, MAX_NAME, lpName);
			}
		}
	}
	
CleanUp:
	
	MSVCRT$memset(lpName, 0, MAX_NAME * sizeof(WCHAR));
	MSVCRT$memset(lpDomain, 0, MAX_NAME * sizeof(WCHAR));

	if (hProcess != NULL && bCloseHandle) {
		ZwClose(hProcess);
	}
	
	if (hToken != NULL) {
		if (Ptoken_User != NULL){
			KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, Ptoken_User);
		}
		ZwClose(hToken);
	}

	return lpwUser;
}

DWORD IntegrityLevel(_In_ HANDLE hProcess) {
	HANDLE hToken = NULL;
	ULONG ReturnLength;
	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	DWORD dwIntegrityLevel;
	DWORD dwRet = 0;

	_NtOpenProcessToken NtOpenProcessToken = (_NtOpenProcessToken)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcessToken");
	if (NtOpenProcessToken == NULL) {
		return 0;
	}
	
	_RtlSubAuthoritySid RtlSubAuthoritySid = (_RtlSubAuthoritySid)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlSubAuthoritySid");
	if (RtlSubAuthoritySid == NULL) {
		return 0;
	}

	_RtlSubAuthorityCountSid RtlSubAuthorityCountSid = (_RtlSubAuthorityCountSid)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlSubAuthorityCountSid");
	if (RtlSubAuthorityCountSid == NULL) {
		return 0;
	}

	NTSTATUS status = NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	if (status == STATUS_SUCCESS) {
		status = ZwQueryInformationToken(hToken, TokenIntegrityLevel, NULL, 0, &ReturnLength);
		if (status != STATUS_BUFFER_TOO_SMALL) {
			goto CleanUp;
		}

		pTIL = (PTOKEN_MANDATORY_LABEL)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ReturnLength);
		status = ZwQueryInformationToken(hToken, TokenIntegrityLevel, pTIL, ReturnLength, &ReturnLength);
		if (status != STATUS_SUCCESS) {
			goto CleanUp;
		}

		dwIntegrityLevel = *RtlSubAuthoritySid(pTIL->Label.Sid, (DWORD)(UCHAR)(*RtlSubAuthorityCountSid(pTIL->Label.Sid) - 1));

		if (dwIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID) {
			dwRet = Untrusted;
		}
		else if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
			dwRet = LowIntegrity;
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
			dwRet = MediumIntegrity;
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
			dwRet = HighIntegrity;
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID && dwIntegrityLevel < SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
			dwRet = SystemIntegrity;
		}
		else if (dwIntegrityLevel == SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
			dwRet = ProtectedProcess;
		}
		else {
			goto CleanUp;
		}
	}

CleanUp:

	if (hToken != NULL) {
		ZwClose(hToken);
	}

	if (pTIL != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTIL);
	}

	return dwRet;
}

BOOL EnumSecurityProc(_In_ LPWSTR lpCompany, _In_ LPWSTR lpDescription, _In_ DWORD dwPID) {
	LPCWSTR pwszCompany[29];
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
	pwszCompany[26] = L"Dominik Reichl"; //KeePass
	pwszCompany[27] = L"Darktrace";
	pwszCompany[28] = L"Trellix";

	const DWORD dwSize = _countof(pwszCompany);
	for (DWORD i = 0; i < dwSize && g_dwSecProcCount < MAX_SEC_PRD; i++) {
		if (SHLWAPI$StrStrIW(lpCompany, pwszCompany[i])) {
			g_pSecProducts[g_dwSecProcCount]->dwPID = dwPID;
			MSVCRT$memcpy(g_pSecProducts[g_dwSecProcCount]->wcCompany, lpCompany, MSVCRT$wcslen(lpCompany) * sizeof(WCHAR));
			MSVCRT$memcpy(g_pSecProducts[g_dwSecProcCount]->wcDescription, lpDescription, MSVCRT$wcslen(lpDescription) * sizeof(WCHAR));
			g_dwSecProcCount++;
		}
	}

	if (g_dwSecProcCount < MAX_SEC_PRD) {
		//Windows Defender (ATP)
		if (SHLWAPI$StrStrIW(lpDescription, L"Antimalware Service Executable") || SHLWAPI$StrStrIW(lpDescription, L"Windows Defender")) {
			g_pSecProducts[g_dwSecProcCount]->dwPID = dwPID;
			MSVCRT$memcpy(g_pSecProducts[g_dwSecProcCount]->wcCompany, lpCompany, MSVCRT$wcslen(lpCompany) * sizeof(WCHAR));
			MSVCRT$memcpy(g_pSecProducts[g_dwSecProcCount]->wcDescription, lpDescription, MSVCRT$wcslen(lpDescription) * sizeof(WCHAR));
			g_dwSecProcCount++;
		}
	}

	if (g_dwSecProcCount < MAX_SEC_PRD) {
		//Carbon Black
		if (SHLWAPI$StrStrIW(lpDescription, L"Carbon Black")) {
			g_pSecProducts[g_dwSecProcCount]->dwPID = dwPID;
			MSVCRT$memcpy(g_pSecProducts[g_dwSecProcCount]->wcCompany, lpCompany, MSVCRT$wcslen(lpCompany) * sizeof(WCHAR));
			MSVCRT$memcpy(g_pSecProducts[g_dwSecProcCount]->wcDescription, lpDescription, MSVCRT$wcslen(lpDescription) * sizeof(WCHAR));
			g_dwSecProcCount++;
		}
	}

	//MS
	if (SHLWAPI$StrStrIW(lpCompany, L"Microsoft")) {
		g_dwMSProc++;
	}
	else {
		g_dwNonMSProc++;
	}

	MSVCRT$memset(pwszCompany, 0, sizeof(pwszCompany));

	return TRUE;
}

BOOL PrintSummary(_In_ DWORD dwTotalProc, _In_ DWORD dwLowProc, _In_ DWORD dwMediumProc, _In_ DWORD dwHighProc, _In_ DWORD dwSystemProc) {
	if (g_dwSecProcCount > 0) {
		BeaconPrintToStreamW(L"\n--------------------------------------------------------------------\n");
		BeaconPrintToStreamW(L"[!] Security products found: %d\n", g_dwSecProcCount);

		for (DWORD i = 0; i < g_dwSecProcCount; i++) {
			BeaconPrintToStreamW(L"%-18ls %d\n", L"    ProcessID:", g_pSecProducts[i]->dwPID);
			BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Vendor:", g_pSecProducts[i]->wcCompany);
			BeaconPrintToStreamW(L"%-18ls %ls\n\n", L"    Product:", g_pSecProducts[i]->wcDescription);
		}
	}
	BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");

	if (dwHighProc == 0 && dwSystemProc == 0) {
		BeaconPrintToStreamW(L"[S] Process summary (running in non-elevated security context):\n");
		if (dwMediumProc > 0) {
			BeaconPrintToStreamW(L"    Low integrity processes:    %d\n", dwLowProc);
			BeaconPrintToStreamW(L"    Medium integrity processes: %d\n", dwMediumProc);
		}
	}
	else {
		BeaconPrintToStreamW(L"[S] Process summary (running in elevated security context):\n");
		BeaconPrintToStreamW(L"    Low integrity processes:    %d\n", dwLowProc);
		BeaconPrintToStreamW(L"    Medium integrity processes: %d\n", dwMediumProc);
		BeaconPrintToStreamW(L"    High integrity processes:   %d\n", dwHighProc);
		BeaconPrintToStreamW(L"    System integrity processes: %d\n", dwSystemProc);
	}

	BeaconPrintToStreamW(L"    Microsoft processes:        %d\n", g_dwMSProc);
	BeaconPrintToStreamW(L"    Non Microsoft processes:    %d\n\n", g_dwNonMSProc);
	BeaconPrintToStreamW(L"    Total active processes:     %d\n\n", dwTotalProc);

	return TRUE;
}

BOOL EnumPeb(_In_ HANDLE hProcess) {
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	PEB peb = { 0 };
	RTL_USER_PROCESS_PARAMETERS upp = { 0 };

	NTSTATUS status = ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = ZwReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = ZwReadVirtualMemory(hProcess, peb.ProcessParameters, &upp, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	if (g_lpwReadBuf <= (LPWSTR)1) { // For BOF we need to avoid large stack buffers, so put unicode string data on heap.
		g_lpwReadBuf = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_STRING * sizeof(WCHAR));
		if (g_lpwReadBuf == NULL) {
			return FALSE;
		}
	}

	status = ZwReadVirtualMemory(hProcess, upp.ImagePathName.Buffer, g_lpwReadBuf, upp.ImagePathName.Length, NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}
	g_lpwReadBuf[upp.ImagePathName.Length / sizeof(WCHAR)] = L'\0';
	BeaconPrintToStreamW(L"%-18ls %ls\n", L"    ImagePath:", g_lpwReadBuf);

	status = ZwReadVirtualMemory(hProcess, upp.CommandLine.Buffer, g_lpwReadBuf, upp.CommandLine.Length, NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}
	g_lpwReadBuf[upp.CommandLine.Length / sizeof(WCHAR)] = L'\0';
	BeaconPrintToStreamW(L"%-18ls %ls\n", L"    CommandLine:", g_lpwReadBuf);	
	
	MSVCRT$memset(g_lpwReadBuf, 0, MAX_STRING * sizeof(WCHAR));

	return TRUE;
}

BOOL EnumPebFromWoW64(_In_ HANDLE hProcess) {
	PROCESS_BASIC_INFORMATION_WOW64 pbi64 = { 0 };
	PEB64 peb64 = { 0 };
	RTL_USER_PROCESS_PARAMETERS64 upp64 = { 0 };

	_NtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (_NtWow64QueryInformationProcess64)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64QueryInformationProcess64");
	if (NtWow64QueryInformationProcess64 == NULL) {
		return FALSE;
	}

	_NtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = (_NtWow64ReadVirtualMemory64)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64ReadVirtualMemory64");
	if (NtWow64ReadVirtualMemory64 == NULL) {
		return FALSE;
	}

	NTSTATUS status = NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &pbi64, sizeof(pbi64), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = NtWow64ReadVirtualMemory64(hProcess, pbi64.PebBaseAddress, &peb64, sizeof(peb64), NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_ERROR, "NtWow64ReadVirtualMemory64 Failed, status: 0x%08x", status);
		return FALSE;
	}

	status = NtWow64ReadVirtualMemory64(hProcess, peb64.ProcessParameters, &upp64, sizeof(RTL_USER_PROCESS_PARAMETERS64), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	if (g_lpwReadBuf <= (LPWSTR)1) { // For BOF we need to avoid large stack buffers, so put unicode string data on heap.
		g_lpwReadBuf = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_STRING * sizeof(WCHAR));
		if (g_lpwReadBuf == NULL) {
			return FALSE;
		}
	}

	status = NtWow64ReadVirtualMemory64(hProcess, upp64.ImagePathName.Buffer, g_lpwReadBuf, upp64.ImagePathName.Length, NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}
	g_lpwReadBuf[upp64.ImagePathName.Length / sizeof(WCHAR)] = L'\0';
	BeaconPrintToStreamW(L"%-18ls %ls\n", L"    ImagePath:", g_lpwReadBuf);

	status = NtWow64ReadVirtualMemory64(hProcess, upp64.CommandLine.Buffer, g_lpwReadBuf, upp64.CommandLine.Length, NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}
	g_lpwReadBuf[upp64.CommandLine.Length / sizeof(WCHAR)] = L'\0';
	BeaconPrintToStreamW(L"%-18ls %ls\n", L"    CommandLine:", g_lpwReadBuf);
	
	MSVCRT$memset(g_lpwReadBuf, 0, MAX_STRING * sizeof(WCHAR));

	return TRUE;
}

BOOL EnumFileProperties(_In_ HANDLE ProcessId, _In_ PUNICODE_STRING uProcImage, BOOL bEnumSecurityProc) {
	NTSTATUS status;
	SYSTEM_PROCESS_ID_INFORMATION pInfo;
	UNICODE_STRING uImageName;
	IO_STATUS_BLOCK IoStatusBlock;
	OBJECT_ATTRIBUTES FileObjectAttributes;
	HANDLE hFile = NULL;
	DWORD dwBinaryType = SCS_32BIT_BINARY;
	PBYTE lpVerInfo = NULL;
	LPWSTR lpCompany = NULL;
	LPWSTR lpDescription = NULL;
	LPWSTR lpProductVersion = NULL;

	MSVCRT$memset(&pInfo, 0, sizeof(SYSTEM_PROCESS_ID_INFORMATION));
	if (ProcessId != NULL){
		pInfo.ProcessId = ProcessId;
		pInfo.ImageName.Length = 0;
		pInfo.ImageName.MaximumLength = MAX_PATH;
		pInfo.ImageName.Buffer = NULL;

		pInfo.ImageName.Buffer = (PWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, pInfo.ImageName.MaximumLength + 1);

		status = ZwQuerySystemInformation(SystemProcessIdInformation, &pInfo, sizeof(pInfo), NULL);
		if (status != STATUS_SUCCESS) {
			goto CleanUp;
		}

		InitializeObjectAttributes(&FileObjectAttributes, &pInfo.ImageName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	}
	else if (uProcImage != NULL){
		InitializeObjectAttributes(&FileObjectAttributes, uProcImage, OBJ_CASE_INSENSITIVE, NULL, NULL);
	}
	else{
		goto CleanUp;
	}

	MSVCRT$memset(&IoStatusBlock, 0, sizeof(IoStatusBlock));
	NTSTATUS Status = ZwCreateFile(&hFile, GENERIC_READ | SYNCHRONIZE, &FileObjectAttributes, &IoStatusBlock, 0,
		0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

	if (hFile == INVALID_HANDLE_VALUE && Status != STATUS_SUCCESS) {
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

	BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Path:", pwszPath);

	if (KERNEL32$GetBinaryTypeW(pwszPath, &dwBinaryType)) {
		if (dwBinaryType == SCS_64BIT_BINARY) {
			BeaconPrintToStreamW(L"%-18ls %ls\n", L"    ImageType:", L"64-bit");
		}
		else {
			BeaconPrintToStreamW(L"%-18ls %ls\n", L"    ImageType:", L"32-bit");
		}
	}

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
			BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Version:", lpProductVersion);
		}

		if (bEnumSecurityProc){
			EnumSecurityProc(lpCompany, lpDescription, HandleToULong(ProcessId));
		}
	}

CleanUp:

	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		ZwClose(hFile);
	}

	if (pInfo.ImageName.Buffer != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pInfo.ImageName.Buffer);
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
	ANSI_STRING aKernelImage;
	UNICODE_STRING uKernelImage;

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
	RtlInitAnsiString(&aKernelImage, (PSTR)pModuleInfo->Module[0].FullPathName);
	
	RtlAnsiStringToUnicodeString(&uKernelImage, &aKernelImage, TRUE);
	if (uKernelImage.Buffer != NULL) {
		EnumFileProperties(NULL, &uKernelImage, FALSE);
	}

CleanUp:

	if (pModInfoBuffer == NULL) {
		ZwFreeVirtualMemory(NtCurrentProcess(), &pModInfoBuffer, &modInfoSize, MEM_RELEASE);
	}

	if (uKernelImage.Buffer != NULL) {
		RtlFreeUnicodeString(&uKernelImage);
	}

	return TRUE;
}

VOID Psx(_In_ BOOL bExtended) {
	NTSTATUS status;
	BOOL bIsWoW64 = FALSE;
	PSYSTEM_PROCESSES pProcInfo = NULL;
	LPVOID pProcInfoBuffer = NULL;
	SIZE_T procInfoSize = 0x10000;
	ULONG uReturnLength = 0;
	FILETIME ftCreate;
	SYSTEMTIME stUTC, stLocal;
	ULONG ulPid = GetPid();
	DWORD SessionID;
	DWORD dwTotalProc = 0, dwLowProc = 0, dwMediumProc = 0, dwHighProc = 0, dwSystemProc = 0;
	
	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.");
		return;
	}

	_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEqualUnicodeString");
	if (RtlEqualUnicodeString == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.");
		return;
	}

#if defined(WOW64)
	_RtlWow64EnableFsRedirectionEx RtlWow64EnableFsRedirectionEx = (_RtlWow64EnableFsRedirectionEx)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlWow64EnableFsRedirectionEx");
	if (RtlWow64EnableFsRedirectionEx == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.");
		return;
	}

	bIsWoW64 = IsProcessWoW64(NtCurrentProcess());
	if (bIsWoW64) {
		PVOID OldValue = NULL;
		status = RtlWow64EnableFsRedirectionEx((PVOID)TRUE, &OldValue);
	}
#endif

	if (IsElevated()) {
		SetDebugPrivilege();
	}

	g_dwMSProc = 0, g_dwNonMSProc = 0, g_dwSecProcCount = 0;
	for (DWORD i = 0; i < MAX_SEC_PRD; i++) {
		g_pSecProducts[i] = (PSECPROD)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECPROD));
	}

	do {
		pProcInfoBuffer = NULL;
		//__asm__("int 0x3"); // Break into debugger
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

	UNICODE_STRING uLsass;
	UNICODE_STRING uWinlogon;
	UNICODE_STRING uSecSystem;
	RtlInitUnicodeString(&uLsass, (PCWSTR)L"lsass.exe");
	RtlInitUnicodeString(&uWinlogon, (PCWSTR)L"winlogon.exe");
	RtlInitUnicodeString(&uSecSystem, (PCWSTR)L"Secure System");

	pProcInfo = (PSYSTEM_PROCESSES)pProcInfoBuffer;
	do {
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

		if (HandleToULong(pProcInfo->ProcessId) == ulPid){
			BeaconPrintToStreamW(L"%-19ls %wZ (implant process)\n", L"\n[I] ProcessName:", &pProcInfo->ProcessName);
		}
		else{
			BeaconPrintToStreamW(L"%-19ls %wZ\n", L"\n[I] ProcessName:", &pProcInfo->ProcessName);
		}

		BeaconPrintToStreamW(L"%-18ls %lu\n", L"    ProcessID:", HandleToULong(pProcInfo->ProcessId));
		BeaconPrintToStreamW(L"%-18ls %lu ", L"    PPID:", HandleToULong(pProcInfo->InheritedFromProcessId));

		dwTotalProc++;

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

		// Exclude ProcessHandle on Lsass and WinLogon (Sysmon will log this). 
		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uLsass, TRUE)) {
			continue;
		}
		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uWinlogon, TRUE)) {
			continue;
		}
		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uSecSystem, TRUE)) {
			continue;
		}

		if (HandleToULong(pProcInfo->ProcessId) == 4) {
			EnumKernel();
		}
		else{
			EnumFileProperties(pProcInfo->ProcessId, NULL, TRUE);
		}

		if (bExtended) {
			HANDLE hProcess = NULL;
			OBJECT_ATTRIBUTES ObjectAttributes;
			InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
			CLIENT_ID uPid = { 0 };

			uPid.UniqueProcess = pProcInfo->ProcessId;
			uPid.UniqueThread = (HANDLE)0;

			status = ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &ObjectAttributes, &uPid);
			if (hProcess != NULL) {
				LPWSTR lpwProcUser = GetProcessUser(hProcess, FALSE, TRUE, TRUE);
				if (lpwProcUser != NULL) {
					BeaconPrintToStreamW(L"%-18ls %ls\n", L"    UserName:", lpwProcUser);
					KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpwProcUser);
				}

				DWORD dwIntegrityLevel = IntegrityLevel(hProcess); // Should be switch but this fails on older Mingw compilers...
				if (dwIntegrityLevel == Untrusted) {
					BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Integrity:", L"Untrusted");
				}
				else if (dwIntegrityLevel == LowIntegrity) {
					BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Integrity:", L"Low");
					dwLowProc++;
				}
				else if (dwIntegrityLevel == MediumIntegrity) {
					BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Integrity:", L"Medium");
					dwMediumProc++;
				}
				else if (dwIntegrityLevel == HighIntegrity) {
					BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Integrity:", L"High");
					dwHighProc++;
				}
				else if (dwIntegrityLevel == SystemIntegrity) {
					BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Integrity:", L"System");
					dwSystemProc++;
				}
				else if (dwIntegrityLevel == ProtectedProcess) {
					BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Integrity:", L"Protected Process");
				}

				if (bIsWoW64) {
					EnumPebFromWoW64(hProcess);
				}
				else{
					EnumPeb(hProcess);
				}
		
				// Close the Process Handle
				ZwClose(hProcess);
			}
		}

		if (pProcInfo->NextEntryDelta == 0) {
			break;
		}

	} while (pProcInfo);

	PrintSummary(dwTotalProc, dwLowProc, dwMediumProc, dwHighProc, dwSystemProc);

CleanUp:

	if (pProcInfoBuffer != NULL) {
		ZwFreeVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, &procInfoSize, MEM_RELEASE);
	}

	if (g_lpwReadBuf != (LPWSTR)1) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, g_lpwReadBuf);
	}

	if (g_pSecProducts[0] != NULL) {
		for (DWORD i = 0; i < MAX_SEC_PRD; i++) {
			KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, g_pSecProducts[i]);
		}
	}

	BeaconOutputStreamW();
	return;
}


VOID go(_In_ PCHAR Args, _In_ ULONG Length) {
	BOOL bExtended = FALSE;
	SHORT sArgs = 0;
	
	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);

	sArgs = BeaconDataShort(&parser);
	if (sArgs > 0){
		bExtended = TRUE;
	}

	Psx(bExtended);
	return;
}
