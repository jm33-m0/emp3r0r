#include <windows.h>
#include <activeds.h>
#include <sddl.h>

#include "ReconAD.h"
#include "beacon.h"

#define BUF_SIZE 512
#define MAX_STRING 8192 * 2
#define MAX_ATTRIBUTES 32

INT iGarbage = 1;
LPSTREAM g_lpStream = (LPSTREAM)1;
LPWSTR g_lpwPrintBuffer = (LPWSTR)1;

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

LPWSTR RemoveQuotesFromArgs(LPWSTR lpwArgs) {
	if (lpwArgs != NULL && lpwArgs[0] == L'"') {
		DWORD dwArgsLen = (DWORD)MSVCRT$wcslen(lpwArgs);
		if (dwArgsLen <= 3) {
			return lpwArgs;
		}

		lpwArgs++;
		dwArgsLen--;
		LPWSTR lpwArgsEnd = &lpwArgs[dwArgsLen - 1];
		for (DWORD i = 0; i < 3; i++) {
			if (*lpwArgsEnd == L'"') {
				*lpwArgsEnd = 0;
				break;
			}
			else if (*lpwArgsEnd == L' ') {
				*lpwArgsEnd = 0;
			}
			lpwArgsEnd--;
		}
	}
	
	return lpwArgs;
}

HRESULT ShowAttributes(_In_ IDirectorySearch *pContainerToSearch, _In_ ADS_SEARCH_HANDLE hSearch, _In_ INT iMaxResults) {
	INT iCount = 0;
	LPWSTR pszColumn = NULL;
	ADS_SEARCH_COLUMN col;
	LPOLESTR pszBool = NULL;
	DWORD dwBool;
	PSID pObjectSID = NULL;
	LPOLESTR szSID = NULL;
	LPGUID pObjectGUID = NULL;
	WCHAR szGUID[39] = { 0 };
	FILETIME filetime;
	SYSTEMTIME systemtime;
	DATE date;
	VARIANT varDate;
	LARGE_INTEGER liValue;
	PSECURITY_DESCRIPTOR pSD = NULL;
	LPWSTR lpwSecDescriptor = NULL;
	BOOL bResult = FALSE;

	_ADsGetObject ADsGetObject = (_ADsGetObject)
		GetProcAddress(GetModuleHandleA("Activeds.dll"), "ADsGetObject");
	if (ADsGetObject == NULL) {
		return S_FALSE;
	}	

	_FreeADsMem FreeADsMem = (_FreeADsMem)
		GetProcAddress(GetModuleHandleA("Activeds.dll"), "FreeADsMem");
	if (FreeADsMem == NULL) {
		return S_FALSE;
	}

	// Call IDirectorySearch::GetNextRow() to retrieve the next row of data.
	HRESULT hr = pContainerToSearch->lpVtbl->GetFirstRow(pContainerToSearch, hSearch);
	if (SUCCEEDED(hr)) {
		while (hr != S_ADS_NOMORE_ROWS) {
			// Keep track of count.
			iCount++;
			BeaconPrintToStreamW(L"\n--------------------------------------------------------------------\n");

			// Loop through the array of passed column names, print the data for each column
			while (pContainerToSearch->lpVtbl->GetNextColumnName(pContainerToSearch, hSearch, &pszColumn) != S_ADS_NOMORE_COLUMNS) {
				hr = pContainerToSearch->lpVtbl->GetColumn(pContainerToSearch, hSearch, pszColumn, &col);
				if (SUCCEEDED(hr)) {
					bResult = TRUE;

					// Print the data for the column and free the column. Get the data for this column.
					BeaconPrintToStreamW(L"[+] %ls:\n", col.pszAttrName);
					// Nasty fix for BOF large switch statement crash...
					if (col.dwADsType == ADSTYPE_DN_STRING) {
						for (DWORD x = 0; x < col.dwNumValues; x++) {
							BeaconPrintToStreamW(L"    %ls\n", col.pADsValues[x].DNString);
						}
					}
					else if ((col.dwADsType == ADSTYPE_CASE_EXACT_STRING) ||
						(col.dwADsType == ADSTYPE_CASE_IGNORE_STRING) ||
						(col.dwADsType == ADSTYPE_PRINTABLE_STRING) ||
						(col.dwADsType == ADSTYPE_NUMERIC_STRING) ||
						(col.dwADsType == ADSTYPE_TYPEDNAME) ||
						(col.dwADsType == ADSTYPE_FAXNUMBER) ||
						(col.dwADsType == ADSTYPE_PATH) ||
						(col.dwADsType == ADSTYPE_OBJECT_CLASS)
						)
					{
						for (DWORD x = 0; x < col.dwNumValues; x++) {
							BeaconPrintToStreamW(L"    %ls\n", col.pADsValues[x].CaseIgnoreString);

							if (MSVCRT$_wcsicmp(L"ADsPath", col.pszAttrName) == 0) {
								IADsUser* pUser;
								IID IADsUserIID;
								SYSTEMTIME ExpirationDate;
								VARIANT_BOOL pfAccountDisabled;

								// Resolve IID from GUID string.
								LPCOLESTR pIADsUserIID = L"{3e37e320-17e2-11cf-abc4-02608c9e7553}";
								hr = OLE32$IIDFromString(pIADsUserIID, &IADsUserIID);

								hr = ADsGetObject(col.pADsValues[x].CaseIgnoreString, &IADsUserIID, (void**)&pUser);
								if (SUCCEEDED(hr)) {
									DATE expirationDate;

									hr = pUser->lpVtbl->get_PasswordExpirationDate(pUser, &expirationDate);
									if (SUCCEEDED(hr)) {
										OLEAUT32$VariantTimeToSystemTime(expirationDate, &ExpirationDate);
									}
									else {
										pUser->lpVtbl->Release(pUser);
										break;
									}

									BeaconPrintToStreamW(L"[+] Password expire settings:\n");

									hr = pUser->lpVtbl->get_AccountDisabled(pUser, &pfAccountDisabled);
									if (SUCCEEDED(hr)) {
										if (pfAccountDisabled != 0) {
											BeaconPrintToStreamW(L"    account disabled\n");
										}
										else if (pfAccountDisabled == 0) {
											BeaconPrintToStreamW(L"    account enabled\n");
										}
										else if (ExpirationDate.wYear == 1970) {
											BeaconPrintToStreamW(L"    password never expires\n");
										}
										else {
											BeaconPrintToStreamW(L"    password expires at: %02d-%02d-%02d %02d:%02d:%02d\n", ExpirationDate.wDay, ExpirationDate.wMonth, ExpirationDate.wYear, ExpirationDate.wHour, ExpirationDate.wMinute, ExpirationDate.wSecond);
										}
									}
									pUser->lpVtbl->Release(pUser);
								}
							}
						}
					}
					else if (col.dwADsType == ADSTYPE_BOOLEAN) {
						for (DWORD x = 0; x < col.dwNumValues; x++) {
							dwBool = col.pADsValues[x].Boolean;
							pszBool = dwBool ? L"TRUE" : L"FALSE";
							BeaconPrintToStreamW(L"    %ls\n", pszBool);
						}
					}
					else if (col.dwADsType == ADSTYPE_INTEGER) {
						for (DWORD x = 0; x < col.dwNumValues; x++) {
							BeaconPrintToStreamW(L"    %d\n", col.pADsValues[x].Integer);
						}
					}
					else if (col.dwADsType == ADSTYPE_OCTET_STRING) {
						if (MSVCRT$_wcsicmp(col.pszAttrName, L"objectSID") == 0) {
							for (DWORD x = 0; x < col.dwNumValues; x++) {
								pObjectSID = (PSID)(col.pADsValues[x].OctetString.lpValue);
								// Convert SID to string.
								ADVAPI32$ConvertSidToStringSidW(pObjectSID, &szSID);
								BeaconPrintToStreamW(L"    %ls\n", szSID);
								KERNEL32$LocalFree(szSID);
							}
						}
						else if (MSVCRT$_wcsicmp(col.pszAttrName, L"objectGUID") == 0) { 
							for (DWORD x = 0; x < col.dwNumValues; x++) {
								// Cast to LPGUID
								pObjectGUID = (LPGUID)(col.pADsValues[x].OctetString.lpValue);
								// Convert GUID to string.
								OLE32$StringFromGUID2(pObjectGUID, szGUID, _countof(szGUID));
								// Print the GUID
								BeaconPrintToStreamW(L"    %ls\n", szGUID);
							}
						}
						else {
							BeaconPrintToStreamW(L"    Value of type Octet String. No Conversion.\n");
						}
					}
					else if (col.dwADsType == ADSTYPE_UTC_TIME) {
						for (DWORD x = 0; x < col.dwNumValues; x++) {
							systemtime = col.pADsValues[x].UTCTime;
							if (OLEAUT32$SystemTimeToVariantTime(&systemtime, &date) != 0) {
								// Pack in variant.vt
								varDate.vt = VT_DATE;
								varDate.date = date;
								OLEAUT32$VariantChangeType(&varDate, &varDate, VARIANT_NOVALUEPROP, VT_BSTR);
								BeaconPrintToStreamW(L"    %ls\n", varDate.bstrVal);
								OLEAUT32$VariantClear(&varDate);
							}
							else {
								BeaconPrintToStreamW(L"    Could not convert UTC-Time.\n");
							}
						}
					}
					else if (col.dwADsType == ADSTYPE_LARGE_INTEGER) {
						for (DWORD x = 0; x < col.dwNumValues; x++) {
							liValue = col.pADsValues[x].LargeInteger;
							filetime.dwLowDateTime = liValue.LowPart;
							filetime.dwHighDateTime = liValue.HighPart;
							if ((filetime.dwHighDateTime == 0) && (filetime.dwLowDateTime == 0)) {
								BeaconPrintToStreamW(L"    No value set.\n");
							}
							else {
								// Check for properties of type LargeInteger that represent time
								// if TRUE, then convert to variant time.
								if ((0 == MSVCRT$_wcsicmp(L"accountExpires", col.pszAttrName)) |
									(0 == MSVCRT$_wcsicmp(L"badPasswordTime", col.pszAttrName)) ||
									(0 == MSVCRT$_wcsicmp(L"lastLogon", col.pszAttrName)) ||
									(0 == MSVCRT$_wcsicmp(L"lastLogoff", col.pszAttrName)) ||
									(0 == MSVCRT$_wcsicmp(L"lockoutTime", col.pszAttrName)) ||
									(0 == MSVCRT$_wcsicmp(L"lastLogonTimestamp", col.pszAttrName)) ||
									(0 == MSVCRT$_wcsicmp(L"ms-Mcs-AdmPwdExpirationTime", col.pszAttrName)) ||
									(0 == MSVCRT$_wcsicmp(L"pwdLastSet", col.pszAttrName))
									)
								{
									// Handle special case for Never Expires where low part is -1
									if (filetime.dwLowDateTime == -1) {
										BeaconPrintToStreamW(L"    Never Expires.\n");
									}
									else {
										if (KERNEL32$FileTimeToLocalFileTime(&filetime, &filetime) != 0) {
											if (KERNEL32$FileTimeToSystemTime(&filetime, &systemtime) != 0) {
												if (OLEAUT32$SystemTimeToVariantTime(&systemtime, &date) != 0) {
													// Pack in variant.vt
													varDate.vt = VT_DATE;
													varDate.date = date;
													OLEAUT32$VariantChangeType(&varDate, &varDate, VARIANT_NOVALUEPROP, VT_BSTR);
													BeaconPrintToStreamW(L"    %ls\n", varDate.bstrVal);
													OLEAUT32$VariantClear(&varDate);
												}
												else {
													BeaconPrintToStreamW(L"    SystemTimeToVariantTime failed\n");
												}
											}
											else {
												BeaconPrintToStreamW(L"    FileTimeToSystemTime failed\n");
											}
										}
										else {
											BeaconPrintToStreamW(L"    FileTimeToLocalFileTime failed\n");
										}
									}
								}
								else {
									// Print the LargeInteger.
									BeaconPrintToStreamW(L"    high: %d low: %d\r\n", filetime.dwHighDateTime, filetime.dwLowDateTime);
								}
							}
						}
					}
					else if (col.dwADsType ==  ADSTYPE_NT_SECURITY_DESCRIPTOR) {
						for (DWORD x = 0; x < col.dwNumValues; x++) {
							pSD = (PSECURITY_DESCRIPTOR)(col.pADsValues[x].SecurityDescriptor.lpValue);
							if (ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorW(pSD, SDDL_REVISION_1,
									DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION, &lpwSecDescriptor, NULL) != 0) {
									
								BeaconPrintToStreamW(L"    %ls\n", lpwSecDescriptor);
								KERNEL32$LocalFree(lpwSecDescriptor);
							}
							else {
								BeaconPrintToStreamW(L"    Security descriptor.\n");
							}
						}
					}
					else {
						BeaconPrintToStreamW(L"    Unknown type %d.\n", col.dwADsType);
					}

					pContainerToSearch->lpVtbl->FreeColumn(pContainerToSearch, &col);
				}
				
				if (pszColumn != NULL) {
					FreeADsMem(pszColumn);
				}
			}

			if ((iMaxResults > 0) && (iMaxResults == iCount)) {
				hr = S_OK;
				break;
			}

			if (iCount > 0 && iCount % 50 == 0) {
				BeaconOutputStreamW();
			}

			// Get the next row
			hr = pContainerToSearch->lpVtbl->GetNextRow(pContainerToSearch, hSearch);
		}
	}

	if (SUCCEEDED(hr) && 0 == iCount) {
		BeaconPrintToStreamW(L"\n[!] No results found.\n");
		hr = S_FALSE;
	}

	return hr;
}

HRESULT SearchContainer(_In_ IDirectorySearch *pContainerToSearch, _In_ LPWSTR lpwSearchFilter, _In_ LPWSTR *lpwAttributeNames, _In_ DWORD dwNumberAttributes, _In_ INT iMaxResults) {
	// Specify subtree search
	ADS_SEARCHPREF_INFO SearchPrefs;
	SearchPrefs.dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	SearchPrefs.vValue.dwType = ADSTYPE_INTEGER;
	SearchPrefs.vValue.Integer = 1000;
	DWORD dwNumPrefs = 1;

	// Handle used for searching
	ADS_SEARCH_HANDLE hSearch = NULL;

	// Set the search preference
	HRESULT hr = pContainerToSearch->lpVtbl->SetSearchPreference(pContainerToSearch, &SearchPrefs, dwNumPrefs);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to set search preference.\n");
		return hr;
	}

	if (dwNumberAttributes > 0) {
		hr = pContainerToSearch->lpVtbl->ExecuteSearch(pContainerToSearch, lpwSearchFilter, lpwAttributeNames, dwNumberAttributes, &hSearch);
	}
	else {
		// Return all properties
		hr = pContainerToSearch->lpVtbl->ExecuteSearch(pContainerToSearch, lpwSearchFilter, NULL, -1L, &hSearch);
	}

	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to execute search.\n");
		return hr;
	}

	// Diplay LDAP Attributes
	hr = ShowAttributes(pContainerToSearch, hSearch, iMaxResults);

	// Close the search handle to clean up
	if (hSearch != NULL) {
		pContainerToSearch->lpVtbl->CloseSearchHandle(pContainerToSearch, hSearch);
	}

	return hr;
}

HRESULT SearchDirectory(_In_ LPWSTR lpwLdapFilter, _In_ LPWSTR *lpwAttributeNames, _In_ DWORD dwNumberAttributes, _In_ INT iMaxResults, _In_ BOOL bUseGC, _In_ LPWSTR lpwServer) {
	HRESULT hr = S_OK;
	HINSTANCE hModule = NULL;
	IADs* pObject = NULL;
	IDirectorySearch* pContainerToSearch = NULL;
	IID IADsIID, IDirectorySearchIID;

	WCHAR wcConnection[BUF_SIZE] = { 0 };
	WCHAR wcPathName[BUF_SIZE] = { 0 };
	VARIANT varHostNameCtx;
	VARIANT varNameCtx;

	hModule = LoadLibraryA("Activeds.dll");
	_ADsOpenObject ADsOpenObject = (_ADsOpenObject)
		GetProcAddress(hModule, "ADsOpenObject");
	if (ADsOpenObject == NULL) {
		return S_FALSE;
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

	if (bUseGC) {
		MSVCRT$wcscpy_s(wcConnection, _countof(wcConnection), L"GC://");
	}
	else {
		MSVCRT$wcscpy_s(wcConnection, _countof(wcConnection), L"LDAP://");
	}

	if (MSVCRT$_wcsicmp(lpwServer, L"-noserver") == 0) { // Serverless Binding
		MSVCRT$wcscat_s(wcConnection, _countof(wcConnection), L"rootDSE");
	}
	else {
		MSVCRT$wcscat_s(wcConnection, _countof(wcConnection), lpwServer);
		MSVCRT$wcscat_s(wcConnection, _countof(wcConnection), L"/rootDSE");
	}

	// Get rootDSE and the current user's domain container DN.
	hr = ADsOpenObject((LPCWSTR)wcConnection,
		NULL,
		NULL,
		ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION, // Use Kerberos encryption
		&IADsIID,
		(void**)&pObject);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to connect.\n");
		goto CleanUp;
	}

	OLEAUT32$VariantInit(&varHostNameCtx);
	hr = pObject->lpVtbl->Get(pObject, (BSTR)L"dnsHostName", &varHostNameCtx);
	if (SUCCEEDED(hr)) {
		BeaconPrintToStreamW(L"[*] Default Naming Context [%ls]\n", varHostNameCtx.bstrVal);
	}

	OLEAUT32$VariantInit(&varNameCtx);
	hr = pObject->lpVtbl->Get(pObject, (BSTR)L"defaultNamingContext", &varNameCtx);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get defaultNamingContext.\n");
		goto CleanUp;
	}

	LPWSTR lpwProtocol = L"LDAP://"; 
	if (bUseGC) { 
		lpwProtocol = L"GC://"; 
	} 
 
	MSVCRT$wcscpy_s(wcPathName, _countof(wcPathName), lpwProtocol);
	if (MSVCRT$_wcsicmp(lpwServer, L"-noserver") != 0) {
		MSVCRT$wcscat_s(wcPathName, _countof(wcPathName), lpwServer);
		MSVCRT$wcscat_s(wcPathName, _countof(wcPathName), L"/");
	}

	MSVCRT$wcscat_s(wcPathName, _countof(wcPathName), varNameCtx.bstrVal);

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

	BeaconPrintToStreamW(L"[*] Using ADsPath: %ls\n", wcPathName);

	// Search container
	if (pContainerToSearch != NULL){
		hr = SearchContainer(pContainerToSearch, lpwLdapFilter, lpwAttributeNames, dwNumberAttributes, iMaxResults);
	}

CleanUp:

	OLEAUT32$VariantClear(&varHostNameCtx);
	OLEAUT32$VariantClear(&varNameCtx);

	if (pObject != NULL) {
		pObject->lpVtbl->Release(pObject);
		pObject = NULL;
	}

	if (pContainerToSearch != NULL) {
		pContainerToSearch->lpVtbl->Release(pContainerToSearch);
		pContainerToSearch = NULL;
	}

	OLE32$CoUninitialize();

	return hr;
}

VOID go(IN PCHAR Args, IN ULONG Length) {
	HRESULT hr = S_OK;
	LPWSTR lpwObjects = NULL;
	LPWSTR lpwFilter = NULL;
	WCHAR wcSearchFilter[BUF_SIZE] = { 0 };
	LPWSTR lpwAttributes = NULL;
	LPWSTR lpwAttributesArr[MAX_ATTRIBUTES] = { 0 };
	LPWSTR lpwServer = NULL;
	DWORD dwAttrCount = 0;
	INT iMaxResults = 0;
	INT iUseGC = 0;

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);

	lpwObjects = (WCHAR*)BeaconDataExtract(&parser, NULL);
	lpwFilter = RemoveQuotesFromArgs((WCHAR*)BeaconDataExtract(&parser, NULL));
	lpwAttributes = (WCHAR*)BeaconDataExtract(&parser, NULL);
	iMaxResults = BeaconDataInt(&parser);
	iUseGC = BeaconDataInt(&parser);
	lpwServer = (WCHAR*)BeaconDataExtract(&parser, NULL);

	if (lpwObjects != NULL && MSVCRT$_wcsicmp(lpwObjects, L"users") == 0) {
		LPCWSTR lpwFormat = L"(&(objectClass=user)(objectCategory=person)(sAMAccountName=%ls))";
		MSVCRT$swprintf_s(wcSearchFilter, BUF_SIZE, lpwFormat, lpwFilter);
		BeaconPrintToStreamW(L"[*] Searching for useraccount(s) with LDAP filter: %ls\n", wcSearchFilter);
	}
	else if (lpwObjects != NULL && MSVCRT$_wcsicmp(lpwObjects, L"groups") == 0) {
		LPCWSTR lpwFormat = L"(&(objectCategory=group)sAMAccountName=%ls)";
		MSVCRT$swprintf_s(wcSearchFilter, BUF_SIZE, lpwFormat, lpwFilter);
		BeaconPrintToStreamW(L"[*] Searching for groupname(s) with LDAP filter: %ls\n", wcSearchFilter);
	}
	else if (lpwObjects != NULL && MSVCRT$_wcsicmp(lpwObjects, L"computers") == 0) {
		LPCWSTR lpwFormat = L"(&(objectCategory=computer)(objectClass=computer)(cn=%ls))";
		MSVCRT$swprintf_s(wcSearchFilter, BUF_SIZE, lpwFormat, lpwFilter);
		BeaconPrintToStreamW(L"[*] Searching for computername(s) with LDAP filter: %ls\n", wcSearchFilter);
	}
	else if (lpwObjects != NULL && MSVCRT$_wcsicmp(lpwObjects, L"custom") == 0) {
		LPCWSTR lpwFormat = L"%ls";
		MSVCRT$swprintf_s(wcSearchFilter, BUF_SIZE, lpwFormat, lpwFilter);
		BeaconPrintToStreamW(L"[*] Searching AD with custom LDAP filter: %ls\n", wcSearchFilter);
	}
	else {
		BeaconPrintToStreamW(L"[!] Wrong object.\n");
	}

	// Split attributes into array
	if (lpwAttributes != NULL && MSVCRT$_wcsicmp(lpwAttributes, L"-all") != 0) {
		LPWSTR lpwToken = NULL, lpwNext = NULL;

		BeaconPrintToStreamW(L"[*] Search Attributes:\n");

		lpwToken = MSVCRT$wcstok_s(lpwAttributes, L",", &lpwNext);
		while (lpwToken != NULL) {
			lpwAttributesArr[dwAttrCount] = lpwToken;
			BeaconPrintToStreamW(L"    -> %ls\n", lpwAttributesArr[dwAttrCount]);
			lpwToken = MSVCRT$wcstok_s(NULL, L",", &lpwNext);
			dwAttrCount++;
		}
	}

	if (iMaxResults > 0) {
		BeaconPrintToStreamW(L"[*] Max results: %d\n", iMaxResults);
	}

	BeaconPrintToStreamW(L"[*] Use Global Catalogue: %ls\n", iUseGC == 0 ? L"FALSE" : L"TRUE");

	hr = SearchDirectory(wcSearchFilter, lpwAttributesArr, dwAttrCount, iMaxResults, iUseGC, lpwServer);
	if (FAILED(hr)) {
		GetFormattedErrMsg(hr);
	}

	BeaconOutputStreamW();
}
