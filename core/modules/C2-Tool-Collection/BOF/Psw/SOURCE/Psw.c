#include <windows.h>

#if defined(WOW64)
#include "Syscalls-WoW64.h"
#else
#include "Syscalls.h"
#endif
#include "beacon.h"
#include "Psw.h"

#define MAX_NAME 8192


BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	NTSTATUS status;
	DWORD dwProcessId = 0;
	PCHAR pWindowTitle = NULL;
	LPVOID pBuffer = NULL;

	if (!hWnd) {
		return TRUE;
	}

	if (!USER32$IsWindowVisible(hWnd)) {
		return TRUE;
	}

	pWindowTitle = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_NAME);
	if (pWindowTitle == NULL) {
		goto CleanUp;
	}

	if (!USER32$SendMessageA(hWnd, WM_GETTEXT, MAX_NAME, (LPARAM)pWindowTitle)) {
		goto CleanUp;
	}

	USER32$GetWindowThreadProcessId(hWnd, &dwProcessId);

	if (dwProcessId != 0) {
		ULONG uReturnLength = 0;
		status = ZwQuerySystemInformation(SystemProcessInformation, 0, 0, &uReturnLength);
		if (!status == STATUS_INFO_LENGTH_MISMATCH) {
			goto CleanUp;
		}
		
		pBuffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, uReturnLength);
		if (pBuffer == NULL) {
			goto CleanUp;
		}

		status = ZwQuerySystemInformation(SystemProcessInformation, pBuffer, uReturnLength, &uReturnLength);
		if (status != STATUS_SUCCESS) {
			goto CleanUp;
		}

		PSYSTEM_PROCESSES pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
		do {
			pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

			if (HandleToUlong(pProcInfo->ProcessId) == dwProcessId) {
				BeaconPrintf(CALLBACK_OUTPUT,
					"[+] ProcessName:\t %wZ\n"
					"    ProcessID:\t %d\n"
					"    WindowTitle:\t %s\n", &pProcInfo->ProcessName, dwProcessId, pWindowTitle);
				break;
			}
			else if (pProcInfo->NextEntryDelta == 0) {
				BeaconPrintf(CALLBACK_OUTPUT,"\n[!] ProcessID not found.\n");
				break;
			}

		} while (pProcInfo);
	}

CleanUp:

	if (pWindowTitle != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pWindowTitle);
	}

	if (pBuffer != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pBuffer);
	}

	return TRUE;
}


VOID go(IN PCHAR Args, IN ULONG Length) {
	USER32$EnumWindows(EnumWindowsProc, (LPARAM)NULL);

	return;
}
