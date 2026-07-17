#pragma once
#define WIN32_WINNT 0x0601
#include <windows.h>
#include "CertCli.h"     // from /mnt/hgfs/git/external/winsdk-10/Include/10.0.16299.0/um
#include "CertPol.h"     // from /mnt/hgfs/git/external/winsdk-10/Include/10.0.16299.0/um
#include "certenroll.h"  // from /mnt/hgfs/git/external/winsdk-10/Include/10.0.16299.0/um

HRESULT _adcs_request_CreatePrivateKey(BOOL bMachine, IX509PrivateKey ** lppPrivateKey);
HRESULT _adcs_request_CreateCertRequest(BOOL bMachine, IX509PrivateKey * pPrivateKey, BSTR bstrTemplate, BSTR bstrSubject, BSTR bstrAltName, BSTR bstrAltUrl, IX509CertificateRequestPkcs10V3 ** lppCertificateRequestPkcs10V3, BOOL addAppPolicy, BOOL dns);
HRESULT _adcs_request_CreateEnrollment(IX509CertificateRequestPkcs10V3 * pCertificateRequestPkcs10V3, IX509Enrollment ** lppEnrollment);
HRESULT _adcs_request_SubmitEnrollment(IX509Enrollment * pEnrollment, BSTR bstrCA, BSTR * lpbstrCertificate);

HRESULT adcs_request( LPCWSTR lpswzCA, LPCWSTR lpswzTemplate, LPCWSTR lpswzSubject, LPCWSTR lpswzAltName, LPCWSTR lpswzAltUrl, BOOL bInstall, BOOL bMachine, BOOL addAppPolicy, BOOL dns );
