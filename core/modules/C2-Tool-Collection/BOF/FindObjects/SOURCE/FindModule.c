#include <windows.h>
#include <stdio.h>

#if defined(WOW64)
#include "Syscalls-WoW64.h"
#else
#include "Syscalls.h"
#endif

#include "FindObjects.h"
#include "beacon.h"

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

ULONG GetCurrentPid() {
	PROCESS_BASIC_INFORMATION pbi = { 0 };

	NTSTATUS status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	if (status != STATUS_SUCCESS) {
		return 0;
	}

	return (ULONG)pbi.UniqueProcessId;
}

LPWSTR WINAPI PathFindFileNameW(LPCWSTR lpszPath) {
	LPCWSTR lastSlash = lpszPath;

	while (lpszPath && *lpszPath)
	{
		if ((*lpszPath == '\\' || *lpszPath == '/' || *lpszPath == ':') &&
			lpszPath[1] && lpszPath[1] != '\\' && lpszPath[1] != '/')
			lastSlash = lpszPath + 1;
		lpszPath++;
	}
	return (LPWSTR)lastSlash;
}

BOOL EnumerateProcessModules(HANDLE hProcess, LPCWSTR lpwModuleName, PUNICODE_STRING uProcName, ULONG ulPid) {
	NTSTATUS status;
	BOOL bResult = FALSE;
	PROCESS_BASIC_INFORMATION BasicInformation;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PPEB_LDR_DATA pLoaderData;
	LDR_DATA_TABLE_ENTRY LoaderModule;
	PLIST_ENTRY ListHead, Current;
	UNICODE_STRING uImagePathName;
	WCHAR wcImagePathName[MAX_PATH * 2];
	WCHAR wcFullDllName[MAX_PATH * 2];
	LPWSTR lpwDllName = NULL;

	status = ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &BasicInformation, sizeof(BasicInformation), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	// Get the address of the Process Parameters struct and read ImagePathName data.
	status = ZwReadVirtualMemory(hProcess, &(BasicInformation.PebBaseAddress->ProcessParameters), &ProcessParameters, sizeof(ProcessParameters), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = ZwReadVirtualMemory(hProcess, &(ProcessParameters->ImagePathName), &uImagePathName, sizeof(uImagePathName), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	MSVCRT$memset(wcImagePathName, 0, sizeof(wcImagePathName));
	status = ZwReadVirtualMemory(hProcess, uImagePathName.Buffer, &wcImagePathName, uImagePathName.MaximumLength, NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	// Get the address of the PE Loader data.
	status = ZwReadVirtualMemory(hProcess, &(BasicInformation.PebBaseAddress->Ldr), &pLoaderData, sizeof(pLoaderData), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	// Head of the module list: the last element in the list will point to this.
	ListHead = &pLoaderData->InLoadOrderModuleList;

	// Get the address of the first element in the list.
	status = ZwReadVirtualMemory(hProcess, &(pLoaderData->InLoadOrderModuleList.Flink), &Current, sizeof(Current), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	while (Current != ListHead) 
	{
		// Read the current module.
		status = ZwReadVirtualMemory(hProcess, CONTAINING_RECORD(Current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks), &LoaderModule, sizeof(LoaderModule), NULL);
		if (status != STATUS_SUCCESS) {
			return FALSE;
		}

		MSVCRT$memset(wcFullDllName, 0, sizeof(wcFullDllName));
		status = ZwReadVirtualMemory(hProcess, (LPVOID)LoaderModule.FullDllName.Buffer, &wcFullDllName, LoaderModule.FullDllName.MaximumLength, NULL);
		if (status != STATUS_SUCCESS) {
			return FALSE;
		}

		lpwDllName = PathFindFileNameW(wcFullDllName);
		if (MSVCRT$_wcsicmp(lpwDllName, lpwModuleName) == 0) {
			BeaconPrintToStreamW(
				L"[+] ProcessName: %wZ\n"
				"    ProcessID:   %lu\n"
				"    ImagePath:   %ls\n"
				"    ModuleName:  %ls\n\n", uProcName, ulPid, wcImagePathName, wcFullDllName);
			
			bResult = TRUE;
		}

		// Address of the next module in the list.
		Current = LoaderModule.InLoadOrderLinks.Flink;
	}

	return bResult;
}

BOOL EnumerateProcessModulesFromWoW64(_In_ HANDLE hProcess, LPCWSTR lpwModuleName, PUNICODE_STRING uProcName, ULONG ulPid) {
	NTSTATUS status;
	BOOL bResult = FALSE;
	PROCESS_BASIC_INFORMATION_WOW64 BasicInformation64 = { 0 };
	PEB64 Peb64 = { 0 };
	RTL_USER_PROCESS_PARAMETERS64 ProcessParameters64 = { 0 };
	PEB_LDR_DATA64 LoaderData64 = { 0 };
	LDR_DATA_TABLE_ENTRY64 LoaderModule64 = { 0 };
	WCHAR wcImagePathName[MAX_PATH * 2];
	WCHAR wcFullDllName[MAX_PATH * 2];
	LPWSTR lpwDllName = NULL;

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

	status = NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &BasicInformation64, sizeof(BasicInformation64), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = NtWow64ReadVirtualMemory64(hProcess, BasicInformation64.PebBaseAddress, &Peb64, sizeof(Peb64), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	// Get the address of the Process Parameters struct and read ImagePathName data.
	status = NtWow64ReadVirtualMemory64(hProcess, Peb64.ProcessParameters, &ProcessParameters64, sizeof(ProcessParameters64), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	MSVCRT$memset(wcImagePathName, 0, sizeof(wcImagePathName));
	status = NtWow64ReadVirtualMemory64(hProcess, ProcessParameters64.ImagePathName.Buffer, &wcImagePathName, ProcessParameters64.ImagePathName.MaximumLength, NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	// Get the address of the PE Loader data.
	status = NtWow64ReadVirtualMemory64(hProcess, Peb64.Ldr, &LoaderData64, sizeof(LoaderData64), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	ULONG64 pStartModuleInfo = LoaderData64.InLoadOrderModuleList.Flink;
	ULONG64 pNextModuleInfo = LoaderData64.InLoadOrderModuleList.Flink;

	do
	{
		// Read the current module.
		status = NtWow64ReadVirtualMemory64(hProcess, pNextModuleInfo, &LoaderModule64, sizeof(LoaderModule64), NULL);
		if (status != STATUS_SUCCESS) {
			return FALSE;
		}

		MSVCRT$memset(wcFullDllName, 0, sizeof(wcFullDllName));
		status = NtWow64ReadVirtualMemory64(hProcess, LoaderModule64.FullDllName.Buffer, &wcFullDllName, LoaderModule64.FullDllName.MaximumLength, NULL);
		if (status != STATUS_SUCCESS) {
			return FALSE;
		}

		lpwDllName = PathFindFileNameW(wcFullDllName);
		if (MSVCRT$_wcsicmp(lpwDllName, lpwModuleName) == 0) {
			BeaconPrintToStreamW(
				L"[+] ProcessName: %wZ\n"
				"    ProcessID:   %lu\n"
				"    ImagePath:   %ls\n"
				"    ModuleName:  %ls\n\n", uProcName, ulPid, wcImagePathName, wcFullDllName);
			
			bResult = TRUE;
		}

		pNextModuleInfo = LoaderModule64.InLoadOrderLinks.Flink;

	} while (pNextModuleInfo != pStartModuleInfo);

	return bResult;
}


VOID go(IN PCHAR Args, IN ULONG Length) {
	NTSTATUS status;
	BOOL bResult = FALSE;
	BOOL bIsWoW64 = FALSE;
	PSYSTEM_PROCESSES pProcInfo = NULL;
	ULONG ulCurPid = 0;
	UNICODE_STRING uLsass;
	UNICODE_STRING uWinlogon;
	LPVOID pProcInfoBuffer = NULL;
	SIZE_T procInfoSize = 0x10000;
	ULONG uReturnLength = 0;
	LPCWSTR lpwModuleName = NULL;

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);
	lpwModuleName = (LPWSTR)BeaconDataExtract(&parser, NULL);

	if (lpwModuleName == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Invalid argument...\n");
		return;
	}

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return;
	}

	_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEqualUnicodeString");
	if (RtlEqualUnicodeString == NULL) {
		return;
	}

#if defined(WOW64)
	bIsWoW64 = IsProcessWoW64(NtCurrentProcess());
#endif

	if (IsElevated()) {
		SetDebugPrivilege();
	}

	do {
		pProcInfoBuffer = NULL;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, 0, &procInfoSize, MEM_COMMIT, PAGE_READWRITE);
		if (status != STATUS_SUCCESS) {
			return;
		}

		status = ZwQuerySystemInformation(SystemProcessInformation, pProcInfoBuffer, (ULONG)procInfoSize, &uReturnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ZwFreeVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, &procInfoSize, MEM_RELEASE);
			procInfoSize += uReturnLength;
		}

	} while (status != STATUS_SUCCESS);

	ulCurPid = GetCurrentPid();
	RtlInitUnicodeString(&uLsass, L"lsass.exe");
	RtlInitUnicodeString(&uWinlogon, L"winlogon.exe");

	pProcInfo = (PSYSTEM_PROCESSES)pProcInfoBuffer;

	do {
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

		if ((ULONG)(ULONG_PTR)pProcInfo->ProcessId == 4) {
			continue;
		}

		if ((ULONG)(ULONG_PTR)pProcInfo->ProcessId == ulCurPid) {
			continue;
		}
		
		// Don't trigger sysmon by touching lsass or winlogon
		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uLsass, TRUE)) {
			continue;
		}
		
		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uWinlogon, TRUE)) {
			continue;
		}

		HANDLE hProcess = NULL;
		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
		CLIENT_ID uPid = { 0 };

		uPid.UniqueProcess = pProcInfo->ProcessId;
		uPid.UniqueThread = (HANDLE)0;

		NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &ObjectAttributes, &uPid);
		if (hProcess != NULL) {
			if (bIsWoW64 && (!IsProcessWoW64(hProcess))) {
				if (EnumerateProcessModulesFromWoW64(hProcess, lpwModuleName, &pProcInfo->ProcessName, (ULONG)(ULONG_PTR)pProcInfo->ProcessId)) {
					bResult = TRUE;
				}
			}
			else{
				if (EnumerateProcessModules(hProcess, lpwModuleName, &pProcInfo->ProcessName, (ULONG)(ULONG_PTR)pProcInfo->ProcessId)) {
					bResult = TRUE;
				}
			}

			ZwClose(hProcess);
		}
		
		if (pProcInfo->NextEntryDelta == 0) {
			break;
		}

	} while (pProcInfo && pProcInfo->NextEntryDelta);

	if (bResult) {
		//Print final Output
		BeaconOutputStreamW();
	}
	else{
		BeaconPrintf(CALLBACK_OUTPUT,"[!] No matching modules found.");
	}

	if (pProcInfoBuffer) {
		status = ZwFreeVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, &procInfoSize, MEM_RELEASE);
	}

	return;
}
