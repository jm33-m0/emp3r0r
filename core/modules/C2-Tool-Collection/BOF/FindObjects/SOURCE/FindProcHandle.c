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

ULONG GetPid(LPCWSTR lpwProcName) {
	NTSTATUS status;
	PSYSTEM_PROCESSES pProcInfo = NULL;
	LPVOID pProcInfoBuffer = NULL;
	SIZE_T procInfoSize = 0x10000;
	UNICODE_STRING uProcName;
	ULONG ulPid = 0;
	ULONG uReturnLength = 0;

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

	do {
		pProcInfoBuffer = NULL;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, 0, &procInfoSize, MEM_COMMIT, PAGE_READWRITE);
		if (status != STATUS_SUCCESS) {
			return 0;
		}

		status = ZwQuerySystemInformation(SystemProcessInformation, pProcInfoBuffer, (ULONG)procInfoSize, &uReturnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ZwFreeVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, &procInfoSize, MEM_RELEASE);
			procInfoSize += uReturnLength;
		}

	} while (status != STATUS_SUCCESS);

	RtlInitUnicodeString(&uProcName, lpwProcName);

	pProcInfo = (PSYSTEM_PROCESSES)pProcInfoBuffer;
	do {
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uProcName, TRUE)) {
			ulPid = (DWORD)(DWORD_PTR)pProcInfo->ProcessId;
			break;
		}

		if (pProcInfo->NextEntryDelta == 0) {
			break;
		}

	} while (pProcInfo && pProcInfo->NextEntryDelta);

	if (pProcInfoBuffer != NULL) {
		ZwFreeVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, &procInfoSize, MEM_RELEASE);
	}

	return ulPid;
}

BOOL EnumObjectHandles(HANDLE hProcess, PSYSTEM_HANDLE pObjHandle, LPCWSTR lpwHandleName, LPWSTR lpwProcName, ULONG ulPid) {
	NTSTATUS status;
	BOOL bResult = FALSE;
	HANDLE dupObjHandle = NULL;
	POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;
	SIZE_T objectInfoSize = 0x10000;
	UNICODE_STRING uProcess;
	BYTE OutputBuffer[2048] = { 0 };
	LPWSTR lpwFileName = NULL;
	ULONG uReturnLength = 0;

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEqualUnicodeString");
	if (RtlEqualUnicodeString == NULL) {
		return FALSE;
	}

	status = ZwDuplicateObject(hProcess, (HANDLE)(DWORD_PTR)pObjHandle->Handle, NtCurrentProcess(), &dupObjHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, 0);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	if (pObjHandle->GrantedAccess == 0x0012019f) {
		ZwClose(dupObjHandle);
		return FALSE;
	}

	do {
		objectTypeInfo = NULL;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&objectTypeInfo, 0, &objectInfoSize, MEM_COMMIT, PAGE_READWRITE);
		if (status != STATUS_SUCCESS) {
			ZwClose(dupObjHandle);
			return FALSE;
		}

		status = ZwQueryObject(dupObjHandle, ObjectTypeInformation, objectTypeInfo, uReturnLength, &uReturnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&objectTypeInfo, &objectInfoSize, MEM_RELEASE);
			objectInfoSize += uReturnLength;
		}
	} while (status != STATUS_SUCCESS);

	RtlInitUnicodeString(&uProcess, L"Process");

	if (RtlEqualUnicodeString(&objectTypeInfo->Name, &uProcess, TRUE)) {
		status = ZwQueryInformationProcess(dupObjHandle, ProcessImageFileName, OutputBuffer, sizeof(OutputBuffer), &uReturnLength);
		if (status == STATUS_SUCCESS) {
			PUNICODE_STRING uFileName = (PUNICODE_STRING)OutputBuffer;
			lpwFileName = PathFindFileNameW((LPWSTR)uFileName->Buffer);

			if (MSVCRT$_wcsicmp(lpwFileName, lpwHandleName) == 0) {
				BeaconPrintToStreamW(
				    L"[+] ProcessName: %ls\n"
				    "    ProcessID:   %lu\n" 
				    "    Handle:      0x%x\n"
				    "    HandleType:  %wZ\n"
				    "    HandleName:  %ls\n\n", lpwProcName ,ulPid, pObjHandle->Handle, &objectTypeInfo->Name, lpwFileName);

				bResult = TRUE;
			}
		}
	}

	if (objectTypeInfo != NULL) {
		status = ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&objectTypeInfo, &objectInfoSize, MEM_RELEASE);
	}

	if (dupObjHandle != NULL) {
		ZwClose(dupObjHandle);
	}

	return bResult;
}


VOID go(IN PCHAR Args, IN ULONG Length) {
	NTSTATUS status;
	BOOL bResult = FALSE;
	ULONG ulProcId = 0;
	PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
	ULONG ulLsassPid = 0;
	ULONG ulWinlogonPid = 0;
	LPVOID pHandleInfoBuffer = NULL;
	SIZE_T handleInfoSize = 0x10000;
	BYTE OutputBuffer[2048] = { 0 };
	LPWSTR lpwHandleName = NULL;
	LPWSTR lpwProcName = NULL;
	ULONG uReturnLength = 0;
	ULONG i = 0;

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);
	lpwHandleName = (LPWSTR)BeaconDataExtract(&parser, NULL);

	if (lpwHandleName == NULL) {
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

	if (IsElevated()) {
		SetDebugPrivilege();
	}

	ulProcId = GetPid(lpwHandleName);
	if (ulProcId == 0) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to obtain ProcessId...\n");
		return;
	}

	ulLsassPid = GetPid(L"lsass.exe");
	ulWinlogonPid = GetPid(L"winlogon.exe");

	do {
		pHandleInfoBuffer = NULL;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pHandleInfoBuffer, 0, &handleInfoSize, MEM_COMMIT, PAGE_READWRITE);
		if (status != STATUS_SUCCESS) {
			return;
		}

		status = ZwQuerySystemInformation(SystemHandleInformation, pHandleInfoBuffer, (ULONG)handleInfoSize, &uReturnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ZwFreeVirtualMemory(NtCurrentProcess(), &pHandleInfoBuffer, &handleInfoSize, MEM_RELEASE);
			handleInfoSize += uReturnLength;
		}

	} while (status != STATUS_SUCCESS);

	pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)pHandleInfoBuffer;
	for (i = 0; i < pHandleInfo->HandleCount; i++) {
		SYSTEM_HANDLE objHandle = pHandleInfo->Handles[i];

		// Ignore System handles
		if (objHandle.ProcessId == 4) {
			continue;
		}

		if (objHandle.ProcessId == ulProcId) {
			continue;
		}

		// Don't trigger sysmon by touching lsass or winlogon
		if ((objHandle.ProcessId == ulLsassPid) || (objHandle.ProcessId == ulWinlogonPid)) {
			continue;
		}

		HANDLE hProcess = NULL;
		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
		CLIENT_ID uPid = { 0 };

		uPid.UniqueProcess = (HANDLE)(DWORD_PTR)objHandle.ProcessId;
		uPid.UniqueThread = (HANDLE)0;

		NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, &ObjectAttributes, &uPid);
		if (hProcess != NULL) {
			status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, OutputBuffer, sizeof(OutputBuffer), &uReturnLength);
			if (status == STATUS_SUCCESS) {
				PUNICODE_STRING uProcName = (PUNICODE_STRING)OutputBuffer;
				lpwProcName = PathFindFileNameW((LPWSTR)uProcName->Buffer);
				if (EnumObjectHandles(hProcess, &objHandle, lpwHandleName, lpwProcName, objHandle.ProcessId)) {
					bResult = TRUE;
				}
			}
			ZwClose(hProcess);
		}
	}

	if (bResult) {
		//Print final Output
		BeaconOutputStreamW();
	}
	else{
		BeaconPrintf(CALLBACK_OUTPUT,"[!] No matching process handles found.");
	}

	if (pHandleInfoBuffer) {
		status = ZwFreeVirtualMemory(NtCurrentProcess(), &pHandleInfoBuffer, &handleInfoSize, MEM_RELEASE);
	}

	return;
}
