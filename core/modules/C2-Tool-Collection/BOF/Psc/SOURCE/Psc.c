#ifdef __MINGW32__
#if(_WIN32_WINNT >= 0x0601)
#else
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#endif

#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wtsapi32.h>

#if defined(WOW64)
#include "Syscalls-WoW64.h"
#else
#include "Syscalls.h"
#endif

#include "beacon.h"
#include "Psc.h"

#define MAX_NAME 256
#define MAX_STRING 8192

INT g_iGarbage = 1;
LPSTREAM g_lpStream = (LPSTREAM)1;
LPWSTR g_lpwPrintBuffer = (LPWSTR)1;
LPWSTR g_lpwReadBuf = (LPWSTR)1;

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

BOOL EnumFileProperties(_In_ HANDLE ProcessId, _In_ PUNICODE_STRING uProcImage) {
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
		EnumFileProperties(NULL, &uKernelImage);
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

BOOL EnumRDPSessions() {
	BOOL bResult = FALSE;
	PWTS_SESSION_INFOW pSessions = NULL;
	DWORD pCount = 0;

	if (!WTSAPI32$WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &pCount)) {
		goto CleanUp;
	}

	for (DWORD i = 0; i < pCount; i++) {
		LPWSTR lpUserName = NULL;
		LPWSTR lpDomainName = NULL;
		LPWSTR lpClientAddress = NULL;
		LPWSTR lpClientName = NULL;
		DWORD pBytesReturned = 0;

		if (!WTSAPI32$WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, pSessions[i].SessionId, WTSUserName, &lpUserName, &pBytesReturned)) {
			goto CleanUp;
		}

		if (!WTSAPI32$WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, pSessions[i].SessionId, WTSDomainName, &lpDomainName, &pBytesReturned)) {
			goto CleanUp;
		}

		if (!WTSAPI32$WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, pSessions[i].SessionId, WTSClientName, &lpClientName, &pBytesReturned)) {
			goto CleanUp;
		}

		if (!WTSAPI32$WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, pSessions[i].SessionId, WTSClientAddress, &lpClientAddress, &pBytesReturned)) {
			goto CleanUp;
		}

		if (pSessions[i].SessionId != 0) {
			BeaconPrintToStreamW(L"%-19ls %d\n", L"\n<R> RDP Session:", pSessions[i].SessionId);

			if (MSVCRT$_wcsicmp(lpClientName, L"") != 0) {
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    ClientName:", lpClientName);
				WTSAPI32$WTSFreeMemory(lpClientName);
			}

			if (MSVCRT$_wcsicmp(lpUserName, L"") != 0) {
				BeaconPrintToStreamW(L"%-18ls %ls\\%ls\n", L"    UserName:", lpDomainName, lpUserName);
				WTSAPI32$WTSFreeMemory(lpUserName);
				WTSAPI32$WTSFreeMemory(lpDomainName);
			}

			if (pSessions[i].State == WTSActive){
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    State:", L"Active");
			}
			else if (pSessions[i].State == WTSConnected){
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    State:", L"Connected");
			}
			else if (pSessions[i].State == WTSConnectQuery){
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    State:", L"Connecting");
			}
			else if (pSessions[i].State == WTSShadow){
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    State:", L"Shadowing");
			}
			else if (pSessions[i].State == WTSDisconnected){
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    State:", L"Disconnected");
			}
			else if (pSessions[i].State == WTSIdle){
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    State:", L"Idle");
			}
			else if (pSessions[i].State == WTSListen){
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    State:", L"Listening");
			}
			else if (pSessions[i].State == WTSReset){
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    State:", L"Reset");
			}
			else if (pSessions[i].State == WTSDown){
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    State:", L" Down");
			}
			else if (pSessions[i].State == WTSInit){
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    State:", L"Initialization");
			}
			else {
				BeaconPrintToStreamW(L"%-18ls %d\n", pSessions[i].State);
			}

			if (MSVCRT$_wcsicmp(pSessions[i].pWinStationName, L"") != 0) {
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    WinStation:", pSessions[i].pWinStationName);
			}

			PWTS_CLIENT_ADDRESS pAddress = (PWTS_CLIENT_ADDRESS)lpClientAddress;
			if (AF_INET == pAddress->AddressFamily) {
				BeaconPrintToStreamW(L"%-18ls %d.%d.%d.%d\n", L"    ClientAddr:", pAddress->Address[2], pAddress->Address[3], pAddress->Address[4], pAddress->Address[5]);
			}
			else if (AF_INET6 == pAddress->AddressFamily) {
				BeaconPrintToStreamW(L"%-18ls %x:%x:%x:%x:%x:%x:%x:%x\n", L"    ClientAddr:",
					pAddress->Address[2] << 8 | pAddress->Address[3],
					pAddress->Address[4] << 8 | pAddress->Address[5],
					pAddress->Address[6] << 8 | pAddress->Address[7],
					pAddress->Address[8] << 8 | pAddress->Address[9],
					pAddress->Address[10] << 8 | pAddress->Address[11],
					pAddress->Address[12] << 8 | pAddress->Address[13],
					pAddress->Address[14] << 8 | pAddress->Address[15],
					pAddress->Address[16] << 8 | pAddress->Address[17]);
			}
			
			WTSAPI32$WTSFreeMemory(lpClientAddress);
		}
	}

CleanUp:

	if (pSessions != NULL) {
		WTSAPI32$WTSFreeMemory(pSessions);
	}
	
	return bResult;
}

BOOL CheckConnectedProc(_In_ DWORD ProcessId) {
	BOOL bResult = FALSE;
	PMIB_TCPTABLE2 pTcpTable = NULL;
	PMIB_TCP6TABLE2 pTcp6Table = NULL;
	ULONG ulSize = 0;
	DWORD dwRetVal = 0;
	int i;
	
	pTcpTable = (MIB_TCPTABLE2 *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(MIB_TCPTABLE2)));
	if (pTcpTable == NULL) {
		return bResult;
	}

	ulSize = sizeof(MIB_TCPTABLE);
	if ((dwRetVal = IPHLPAPI$GetTcpTable2(pTcpTable, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTcpTable);
		pTcpTable = (MIB_TCPTABLE2 *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (ulSize));
		if (pTcpTable == NULL) {
			return bResult;
		}
	}

	if ((dwRetVal = IPHLPAPI$GetTcpTable2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) {
		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
			if (pTcpTable->table[i].dwOwningPid == ProcessId) {
				if (pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
					bResult = TRUE;
					goto CleanUp;
				}
			}
		}
	}

	pTcp6Table = (MIB_TCP6TABLE2 *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(MIB_TCP6TABLE2)));
	if (pTcp6Table == NULL) {
		return bResult;
	}

	ulSize = sizeof(MIB_TCP6TABLE);
	if ((dwRetVal = IPHLPAPI$GetTcp6Table2(pTcp6Table, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTcp6Table);
		pTcp6Table = (MIB_TCP6TABLE2 *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (ulSize));
		if (pTcp6Table == NULL) {
			return bResult;
		}
	}

	if ((dwRetVal = IPHLPAPI$GetTcp6Table2(pTcp6Table, &ulSize, TRUE)) == NO_ERROR) {
		for (i = 0; i < (int)pTcp6Table->dwNumEntries; i++) {
			if (pTcp6Table->table[i].dwOwningPid == ProcessId) {
				if (pTcp6Table->table[i].State == MIB_TCP_STATE_ESTAB) {
					bResult = TRUE;
					goto CleanUp;
				}
			}
		}
	}

CleanUp:

	if (pTcpTable != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTcpTable);
	}

	if (pTcp6Table != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTcp6Table);
	}

	return bResult;
}

BOOL GetTcpSessions(_In_ DWORD ProcessId, _Out_ BOOL *bRDPEnabled) {
	BOOL bResult = FALSE;
	PMIB_TCPTABLE2 pTcpTable;
	ULONG ulSize = 0;
	DWORD dwRetVal = 0;
	WCHAR szLocalAddr[128];
	WCHAR szRemoteAddr[128];
	struct in_addr IpAddr;
	int i;
	
	pTcpTable = (MIB_TCPTABLE2 *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(MIB_TCPTABLE2)));
	if (pTcpTable == NULL) {
		return bResult;
	}

	ulSize = sizeof(MIB_TCPTABLE);
	if ((dwRetVal = IPHLPAPI$GetTcpTable2(pTcpTable, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTcpTable);
		pTcpTable = (MIB_TCPTABLE2 *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (ulSize));
		if (pTcpTable == NULL) {
			return bResult;
		}
	}

	if ((dwRetVal = IPHLPAPI$GetTcpTable2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) {
		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
			if (pTcpTable->table[i].dwOwningPid == ProcessId) {
				if (pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
					BeaconPrintToStreamW(L"%-19ls %ls\n", L"\n<-> Session:", L"TCP");
					BeaconPrintToStreamW(L"%-18ls %ls\n", L"    State:", L"ESTABLISHED");

					_RtlIpv4AddressToStringW RtlIpv4AddressToStringW = (_RtlIpv4AddressToStringW)
						GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlIpv4AddressToStringW");
					if (RtlIpv4AddressToStringW == NULL) {
						goto CleanUp;
					}

					IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
					RtlIpv4AddressToStringW(&IpAddr, szLocalAddr);
					BeaconPrintToStreamW(L"%-18ls %ls:%d\n", L"    Local Addr:", szLocalAddr, WS2_32$ntohs((u_short)pTcpTable->table[i].dwLocalPort));

					IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
					RtlIpv4AddressToStringW(&IpAddr, szRemoteAddr);
					BeaconPrintToStreamW(L"%-18ls %ls:%d\n", L"    Remote Addr:", szRemoteAddr, WS2_32$ntohs((u_short)pTcpTable->table[i].dwRemotePort));
					bResult = TRUE;
				}

				if (WS2_32$ntohs((u_short)pTcpTable->table[i].dwLocalPort) == 3389) {
					*bRDPEnabled = TRUE;
				}
			}
		}
	}

CleanUp:

	if (pTcpTable != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTcpTable);
	}

	return bResult;
}

BOOL GetTcp6Sessions(_In_ DWORD ProcessId, _Out_ BOOL *bRDPEnabled) {
	BOOL bResult = FALSE;
	PMIB_TCP6TABLE2 pTcpTable;
	ULONG ulSize = 0;
	DWORD dwRetVal = 0;
	WCHAR szLocalAddr[128];
	WCHAR szRemoteAddr[128];
	int i;

	pTcpTable = (MIB_TCP6TABLE2 *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(MIB_TCP6TABLE2)));
	if (pTcpTable == NULL) {
		return bResult;
	}

	ulSize = sizeof(MIB_TCP6TABLE);
	if ((dwRetVal = IPHLPAPI$GetTcp6Table2(pTcpTable, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTcpTable);
		pTcpTable = (MIB_TCP6TABLE2 *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (ulSize));
		if (pTcpTable == NULL) {
			return bResult;
		}
	}

	if ((dwRetVal = IPHLPAPI$GetTcp6Table2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) {
		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
			if (pTcpTable->table[i].dwOwningPid == ProcessId) {
				if (pTcpTable->table[i].State == MIB_TCP_STATE_ESTAB) {
					BeaconPrintToStreamW(L"%-19ls %ls\n", L"\n<-> Session:", L"TCP6");
					BeaconPrintToStreamW(L"%-18ls %ls\n", L"    State:", L"ESTABLISHED");

					_RtlIpv6AddressToStringW RtlIpv6AddressToStringW = (_RtlIpv6AddressToStringW)
						GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlIpv6AddressToStringW");
					if (RtlIpv6AddressToStringW == NULL) {
						goto CleanUp;
					}

					RtlIpv6AddressToStringW(&pTcpTable->table[i].LocalAddr, szLocalAddr);
					if (MSVCRT$_wcsicmp(szLocalAddr, L"::") == 0) {
						BeaconPrintToStreamW(L"%-18ls [0:0:0:0:0:0:0:0]:%d\n", L"    Local Addr:", WS2_32$ntohs((u_short)pTcpTable->table[i].dwLocalPort));
					}
					else {
						BeaconPrintToStreamW(L"%-18ls [%ls]:%d\n", L"    Local Addr:", szLocalAddr, WS2_32$ntohs((u_short)pTcpTable->table[i].dwLocalPort));
					}

					RtlIpv6AddressToStringW(&pTcpTable->table[i].RemoteAddr, szRemoteAddr);
					if (MSVCRT$_wcsicmp(szRemoteAddr, L"::") == 0) {

						BeaconPrintToStreamW(L"%-18ls [0:0:0:0:0:0:0:0]:%d\n", L"    Remote Addr:", WS2_32$ntohs((u_short)pTcpTable->table[i].dwRemotePort));
					}
					else {
						BeaconPrintToStreamW(L"%-18ls [%ls]:%d\n", L"    Remote Addr:", szRemoteAddr, WS2_32$ntohs((u_short)pTcpTable->table[i].dwRemotePort));
					}

					bResult = TRUE;
				}

				if (WS2_32$ntohs((u_short)pTcpTable->table[i].dwLocalPort) == 3389) {
					*bRDPEnabled = TRUE;
				}
			}
		}
	}

CleanUp:

	if (pTcpTable != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTcpTable);
	}
	
	return bResult;
}

VOID go(_In_ PCHAR Args, _In_ ULONG Length) {
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
LOOP:	do {
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

		if (!CheckConnectedProc(HandleToULong(pProcInfo->ProcessId))) {
			if (pProcInfo->NextEntryDelta == 0) {
				break;
			}
			goto LOOP;
		}

		BeaconPrintToStreamW(L"\n--------------------------------------------------------------------\n");
		if (HandleToULong(pProcInfo->ProcessId) == ulPid){
			BeaconPrintToStreamW(L"%-18ls %wZ (implant process)\n", L"[I] ProcessName:", &pProcInfo->ProcessName);
		}
		else{
			BeaconPrintToStreamW(L"%-18ls %wZ\n", L"[I] ProcessName:", &pProcInfo->ProcessName);
		}

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
		}
		else{
			EnumFileProperties(pProcInfo->ProcessId, NULL);
		}

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
			}
			else if (dwIntegrityLevel == MediumIntegrity) {
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Integrity:", L"Medium");
			}
			else if (dwIntegrityLevel == HighIntegrity) {
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Integrity:", L"High");
			}
			else if (dwIntegrityLevel == SystemIntegrity) {
				BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Integrity:", L"System");
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

		BOOL bRDPEnabled = FALSE;
		GetTcpSessions(HandleToULong(pProcInfo->ProcessId), &bRDPEnabled);
		GetTcp6Sessions(HandleToULong(pProcInfo->ProcessId), &bRDPEnabled);

		if (bRDPEnabled) {
			EnumRDPSessions();
		}

		if (pProcInfo->NextEntryDelta == 0) {
			break;
		}

	} while (pProcInfo);

CleanUp:

	if (pProcInfoBuffer != NULL) {
		ZwFreeVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, &procInfoSize, MEM_RELEASE);
	}

	if (g_lpwReadBuf != (LPWSTR)1) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, g_lpwReadBuf);
	}

	BeaconOutputStreamW();
	return;
}
