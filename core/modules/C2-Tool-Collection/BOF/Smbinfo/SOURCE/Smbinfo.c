#include <windows.h>
#include <lm.h>

#include "Smbinfo.h"
#include "beacon.h"


VOID go(IN PCHAR Args, IN ULONG Length) {
	DWORD dwLevel = 100;
	LPWKSTA_INFO_100 pBuf = NULL;
	NET_API_STATUS nStatus;
	HINSTANCE hModule = NULL;
	LPWSTR lpwComputername = NULL;

	hModule = LoadLibraryA("Netapi32.dll");
	_NetWkstaGetInfo NetWkstaGetInfo = (_NetWkstaGetInfo)
		GetProcAddress(GetModuleHandleA("Netapi32.dll"), "NetWkstaGetInfo");
	if (NetWkstaGetInfo == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "GetProcAddress Failed");
		return;
	}

	_NetApiBufferFree NetApiBufferFree = (_NetApiBufferFree)
		GetProcAddress(GetModuleHandleA("Netapi32.dll"), "NetApiBufferFree");
	if (NetApiBufferFree == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "GetProcAddress Failed");
		return;
	}

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);
	
	lpwComputername = (WCHAR*)BeaconDataExtract(&parser, NULL);
	if (lpwComputername != NULL){
		nStatus = NetWkstaGetInfo(lpwComputername, dwLevel, (LPBYTE*)&pBuf);
		if (nStatus == NERR_Success) {
			BeaconPrintf(CALLBACK_OUTPUT, 
				"Platform: %d, " 
				"Version: %d.%d, " 
				"Name: %ls, " 
				"Domain: %ls\n", pBuf->wki100_platform_id, pBuf->wki100_ver_major, pBuf->wki100_ver_minor, pBuf->wki100_computername, pBuf->wki100_langroup);
		}
		else {
			BeaconPrintf(CALLBACK_ERROR, "A system error has occurred: %d\n", nStatus);
		}
	}

	if (pBuf != NULL) {
		NetApiBufferFree(pBuf);
	}

	return;
}
