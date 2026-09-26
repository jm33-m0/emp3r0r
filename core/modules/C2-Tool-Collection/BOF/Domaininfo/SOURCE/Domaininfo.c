#include <winsock2.h>
#include <windows.h>
#include <dsgetdc.h>
#include <lm.h>

#include "Domaininfo.h"
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


VOID go(IN PCHAR Args, IN ULONG Length) { 
	DWORD dwRet = 0;
	PDOMAIN_CONTROLLER_INFOW pdcInfo;

	// Get a Domain Controller for the Domain this computer is on.
	dwRet = NETAPI32$DsGetDcNameW(NULL, NULL, NULL, NULL, 0, &pdcInfo);
	if (ERROR_SUCCESS == dwRet) {
		// Open the enumeration.
		HANDLE hGetDc;
		dwRet = NETAPI32$DsGetDcOpenW(pdcInfo->DomainName,
			DS_NOTIFY_AFTER_SITE_RECORDS,
			NULL,
			NULL,
			NULL,
			0,
			&hGetDc);

		if (ERROR_SUCCESS == dwRet) {
			LPWSTR pszDnsHostName;
			GUID guid;
			OLE32$CoCreateGuid(&guid);

			OLECHAR* guidString;
			OLE32$StringFromCLSID(&pdcInfo->DomainGuid, &guidString);

			BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");
			BeaconPrintToStreamW(L"[+] DomainName:\n");
			BeaconPrintToStreamW(L"    %ls\n", pdcInfo->DomainName);

			BeaconPrintToStreamW(L"[+] DomainGuid:\n");
			BeaconPrintToStreamW(L"    %ls\n", guidString);

			BeaconPrintToStreamW(L"[+] DnsForestName:\n");
			BeaconPrintToStreamW(L"    %ls\n", pdcInfo->DnsForestName);

			BeaconPrintToStreamW(L"[+] DcSiteName:\n");
			BeaconPrintToStreamW(L"    %ls\n", pdcInfo->DcSiteName);

			BeaconPrintToStreamW(L"[+] ClientSiteName:\n");
			BeaconPrintToStreamW(L"    %ls\n", pdcInfo->ClientSiteName);

			BeaconPrintToStreamW(L"[+] DomainControllerName (PDC):\n");
			BeaconPrintToStreamW(L"    %ls\n", pdcInfo->DomainControllerName);

			BeaconPrintToStreamW(L"[+] DomainControllerAddress (PDC):\n");
			BeaconPrintToStreamW(L"    %ls\n", pdcInfo->DomainControllerAddress);

			OLE32$CoTaskMemFree(guidString);

			// Enumerate Domain password policy.
			DWORD dwLevel = 0;
			USER_MODALS_INFO_0 *pBuf0 = NULL;
			USER_MODALS_INFO_3 *pBuf3 = NULL;
			NET_API_STATUS nStatus;

			// Call the NetUserModalsGet function; specify level 0.
			nStatus = NETAPI32$NetUserModalsGet(pdcInfo->DomainControllerName, dwLevel, (LPBYTE *)&pBuf0);

			// If the call succeeds, print the global information.
			if (nStatus == NERR_Success) {
				if (pBuf0 != NULL) {
					BeaconPrintToStreamW(L"[+] Default Domain Password Policy:\n");
					BeaconPrintToStreamW(L"    Password history length: %d\n", pBuf0->usrmod0_password_hist_len);
					BeaconPrintToStreamW(L"    Maximum password age (d): %d\n", pBuf0->usrmod0_max_passwd_age / 86400);
					BeaconPrintToStreamW(L"    Minimum password age (d): %d\n", pBuf0->usrmod0_min_passwd_age / 86400);
					BeaconPrintToStreamW(L"    Minimum password length: %d\n", pBuf0->usrmod0_min_passwd_len);
				}
			}

			// Free the allocated memory.
			if (pBuf0 != NULL) {
				NETAPI32$NetApiBufferFree(pBuf0);
			}

			// Call the NetUserModalsGet function; specify level 3.
			dwLevel = 3;
			nStatus = NETAPI32$NetUserModalsGet(pdcInfo->DomainControllerName, dwLevel, (LPBYTE *)&pBuf3);

			// If the call succeeds, print the global information.
			if (nStatus == NERR_Success) {
				if (pBuf3 != NULL) {
					BeaconPrintToStreamW(L"[+] Account Lockout Policy:\n");
					BeaconPrintToStreamW(L"    Account lockout threshold: %d\n", pBuf3->usrmod3_lockout_threshold);
					BeaconPrintToStreamW(L"    Account lockout duration (m): %d\n", pBuf3->usrmod3_lockout_duration / 60);
					BeaconPrintToStreamW(L"    Account lockout observation window (m): %d\n", pBuf3->usrmod3_lockout_duration / 60);
				}
			}

			// Free the allocated memory.
			if (pBuf3 != NULL) {
				NETAPI32$NetApiBufferFree(pBuf3);
			}

			// Enumerate each Domain Controller and print its name.
			BeaconPrintToStreamW(L"[+] NextDc DnsHostName:\n");

			while (TRUE) {
				ULONG ulSocketCount;
				LPSOCKET_ADDRESS rgSocketAddresses;

				dwRet = NETAPI32$DsGetDcNextW(
					hGetDc, 
					&ulSocketCount, 
					&rgSocketAddresses, 
					&pszDnsHostName);

				if (ERROR_SUCCESS == dwRet) {
					BeaconPrintToStreamW(L"    %ls\n", pszDnsHostName);

					// Free the allocated string.
					NETAPI32$NetApiBufferFree(pszDnsHostName);

					// Free the socket address array.
					KERNEL32$LocalFree(rgSocketAddresses);
				}
				else if (ERROR_NO_MORE_ITEMS == dwRet) {
					// The end of the list has been reached.
					break;
				}
				else if (ERROR_FILEMARK_DETECTED == dwRet) {
					// DS_NOTIFY_AFTER_SITE_RECORDS was specified inmDsGetDcOpen and the end of the site-specific records was reached.
					BeaconPrintToStreamW(L"[+] End of site-specific Domain Controllers.\n");
					continue;
				}
				else {
					// Some other error occurred.
					break;
				}
			}

			BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");

			// Close the enumeration.
			NETAPI32$DsGetDcCloseW(hGetDc);

			//Print final Output
			BeaconOutputStreamW();
		}

		// Free the DOMAIN_CONTROLLER_INFO structure.
		NETAPI32$NetApiBufferFree(pdcInfo);
	}
	else {
		// Check if Device is joined to Azure AD.
		PDSREG_JOIN_INFO ppJoinInfo = NULL;

		// Use GetProcAddress to avoid API resolve error on Windows < 10/2016
		_NetGetAadJoinInformation NetGetAadJoinInformation = (_NetGetAadJoinInformation)
			GetProcAddress(GetModuleHandleA("Netapi32.dll"), "NetGetAadJoinInformation");
		if (NetGetAadJoinInformation == NULL) {
			BeaconPrintf(CALLBACK_ERROR, "GetProcAddress Failed");
			return;
		}

		_NetFreeAadJoinInformation NetFreeAadJoinInformation = (_NetFreeAadJoinInformation)
			GetProcAddress(GetModuleHandleA("Netapi32.dll"), "NetFreeAadJoinInformation");
		if (NetFreeAadJoinInformation == NULL) {
			BeaconPrintf(CALLBACK_ERROR, "GetProcAddress Failed");
			return;
		}

		HRESULT hr = NetGetAadJoinInformation(NULL, &ppJoinInfo);
		if (hr == S_OK){
			BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");
			if (ppJoinInfo->joinType == 1){
				BeaconPrintToStreamW(L"[+] This device is joined to Azure Active Directory (Azure AD)\n\n");
			}
			if (ppJoinInfo->joinType == 2){
				BeaconPrintToStreamW(L"[+] An Azure AD work account is added on the device.\n");
			}

			BeaconPrintToStreamW(L"[+] Azure TenantDisplayName:\n");
			BeaconPrintToStreamW(L"    %ls\n", ppJoinInfo->pszTenantDisplayName);

			BeaconPrintToStreamW(L"[+] Azure Active Directory (Azure AD):\n");
			BeaconPrintToStreamW(L"    %ls\n", ppJoinInfo->pszIdpDomain);

			BeaconPrintToStreamW(L"[+] Azure TenantId:\n");
			BeaconPrintToStreamW(L"    %ls\n", ppJoinInfo->pszTenantId);

			BeaconPrintToStreamW(L"[+] Azure DeviceId:\n");
			BeaconPrintToStreamW(L"    %ls\n", ppJoinInfo->pszDeviceId);

			BeaconPrintToStreamW(L"[+] Azure JoinUserEmail:\n");
			BeaconPrintToStreamW(L"    %ls\n", ppJoinInfo->pszJoinUserEmail);

			BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");

			//Print final Output
			BeaconOutputStreamW();
			
			NetFreeAadJoinInformation(ppJoinInfo);
		}
	}
}
