#include <windows.h>
#include <activeds.h>
#include <dsgetdc.h>

#include "AddMachineAccount.h"
#include "beacon.h"

#define BUF_SMALL 128
#define BUF_LARGE 256


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

HRESULT DeleteMachineAccount(_In_ LPCWSTR lpwComputername) {
	HRESULT hr = S_FALSE;
    HINSTANCE hModule = NULL;
	IADs* pRoot = NULL;
	IDirectoryObject* pDirectoryObj = NULL;
	IID IADsIID, IDirectoryObjectIID;
	VARIANT var;

	WCHAR wcPathName[BUF_LARGE];
	WCHAR wcCommonName[BUF_SMALL];

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
	LPCOLESTR pIDirectoryObjectIID = L"{E798DE2C-22E4-11D0-84FE-00C04FD8D503}";

	hr = OLE32$IIDFromString(pIADsIID, &IADsIID);
	hr = OLE32$IIDFromString(pIDirectoryObjectIID, &IDirectoryObjectIID);

	// Get rootDSE and the current user's domain container DN.
	hr = ADsOpenObject(L"LDAP://rootDSE",
		NULL,
		NULL,
		ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION, // Use Kerberos encryption
		&IADsIID,
		(void**)&pRoot);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get rootDSE.");
		goto CleanUp;
	}

	OLEAUT32$VariantInit(&var);
	hr = pRoot->lpVtbl->Get(pRoot, (BSTR)L"defaultNamingContext", &var);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get defaultNamingContext.");
		goto CleanUp;
	}

	MSVCRT$memset(wcPathName, 0, sizeof(wcPathName));
	MSVCRT$wcscpy_s(wcPathName, _countof(wcPathName), L"LDAP://CN=Computers,");
	MSVCRT$wcscat_s(wcPathName, _countof(wcPathName), var.bstrVal);

	// Get Computer container object.
	hr = ADsOpenObject((LPCWSTR)wcPathName,
		NULL,
		NULL,
		ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION, // Use Kerberos encryption
		&IDirectoryObjectIID,
		(void**)&pDirectoryObj);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "ADsOpenObject failed.");
		goto CleanUp;
	}

    // Delete the object in the Computer container with the specified property values.
	MSVCRT$memset(wcCommonName, 0, sizeof(wcCommonName));
	MSVCRT$wcscpy_s(wcCommonName, _countof(wcCommonName), L"CN=");
	MSVCRT$wcscat_s(wcCommonName, _countof(wcCommonName), lpwComputername);

	hr = pDirectoryObj->lpVtbl->DeleteDSObject(pDirectoryObj, wcCommonName);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to delete Computer object.");
		goto CleanUp;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[+] Machine account %ls deleted \n", lpwComputername);


CleanUp:

	if (pDirectoryObj != NULL) {
		pDirectoryObj->lpVtbl->Release(pDirectoryObj);
		pDirectoryObj = NULL;
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
	LPCWSTR lpwComputername = NULL;

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);
	
	lpwComputername = (WCHAR*)BeaconDataExtract(&parser, NULL);

	hr = DeleteMachineAccount(USER32$CharUpperW((LPWSTR)lpwComputername));
	if (FAILED(hr)) {
		GetFormattedErrMsg(hr);
	}

	return;
}
