#pragma once
#define SECURITY_WIN32

#include "kerb_struct.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <security.h>

#include <dsgetdc.h>
#include <ntsecapi.h>
#include "beacon.h"
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _LOGON_SESSION_DATA {
	PSECURITY_LOGON_SESSION_DATA* sessionData;
	ULONG sessionCount;
} LOGON_SESSION_DATA, *PLOGON_SESSION_DATA;

typedef CONST UNICODE_STRING* PCUNICODE_STRING;

typedef NTSTATUS(WINAPI* PKERB_ECRYPT_INITIALIZE) (LPCVOID pbKey, ULONG KeySize, ULONG MessageType, PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_ENCRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_DECRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_FINISH) (PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_HASHPASSWORD_NT5) (PCUNICODE_STRING Password, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_HASHPASSWORD_NT6) (PCUNICODE_STRING Password, PCUNICODE_STRING Salt, ULONG Count, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_RANDOMKEY) (LPCVOID Seed, ULONG SeedLength, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_CONTROL) (ULONG Function, PVOID pContext, PUCHAR InputBuffer, ULONG InputBufferSize);

typedef struct _KERB_ECRYPT {
	ULONG EncryptionType;
	ULONG BlockSize;
	ULONG ExportableEncryptionType;
	ULONG KeySize;
	ULONG HeaderSize;
	ULONG PreferredCheckSum;
	ULONG Attributes;
	PCWSTR Name;
	PKERB_ECRYPT_INITIALIZE Initialize;
	PKERB_ECRYPT_ENCRYPT Encrypt;
	PKERB_ECRYPT_DECRYPT Decrypt;
	PKERB_ECRYPT_FINISH Finish;
	union {
		PKERB_ECRYPT_HASHPASSWORD_NT5 HashPassword_NT5;
		PKERB_ECRYPT_HASHPASSWORD_NT6 HashPassword_NT6;
	};
	PKERB_ECRYPT_RANDOMKEY RandomKey;
	PKERB_ECRYPT_CONTROL Control;
	PVOID unk0_null;
	PVOID unk1_null;
	PVOID unk2_null;
} KERB_ECRYPT, * PKERB_ECRYPT;

typedef NTSTATUS(WINAPI* PKERB_CHECKSUM_INITIALIZE) (ULONG dwSeed, PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_CHECKSUM_SUM) (PVOID pContext, ULONG cbData, LPCVOID pbData);
typedef NTSTATUS(WINAPI* PKERB_CHECKSUM_FINALIZE) (PVOID pContext, PVOID pbSum);
typedef NTSTATUS(WINAPI* PKERB_CHECKSUM_FINISH) (PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_CHECKSUM_INITIALIZEEX) (LPCVOID Key, ULONG KeySize, ULONG MessageType, PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_CHECKSUM_INITIALIZEEX2)(LPCVOID Key, ULONG KeySize, LPCVOID ChecksumToVerify, ULONG MessageType, PVOID* pContext);

typedef struct _KERB_CHECKSUM {
	ULONG CheckSumType;
	ULONG CheckSumSize;
	ULONG Attributes;
	PKERB_CHECKSUM_INITIALIZE Initialize;
	PKERB_CHECKSUM_SUM Sum;
	PKERB_CHECKSUM_FINALIZE Finalize;
	PKERB_CHECKSUM_FINISH Finish;
	PKERB_CHECKSUM_INITIALIZEEX InitializeEx;
	PKERB_CHECKSUM_INITIALIZEEX2 InitializeEx2;
} KERB_CHECKSUM, * PKERB_CHECKSUM;

typedef NTSTATUS(WINAPI* pCDLocateCheckSum)(ULONG Type, PKERB_CHECKSUM* ppCheckSum);
typedef NTSTATUS(WINAPI* pRtlAnsiStringToUnicodeString)(PUNICODE_STRING DestinationString, STRING* SourceString, BOOLEAN AllocateDestinationString);
typedef NTSTATUS(WINAPI* pRtlInitAnsiString)(STRING* DestinationString, char* SourceString);
typedef NTSTATUS(WINAPI* pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(WINAPI* pCDLocateCSystem)(ULONG Type, PKERB_ECRYPT* ppCSystem);

#define KERNEL32$GetCurrentProcess() (HANDLE)(-1)
#define KERNEL32$GetCurrentThread() (HANDLE)(-2)

WINBASEAPI DWORD WINAPI NETAPI32$DsGetDcNameA(LPCSTR ComputerName, LPCSTR DomainName, GUID* DomainGuid, LPCSTR SiteName, ULONG Flags, PDOMAIN_CONTROLLER_INFOA* DomainControllerInfo);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);

DECLSPEC_IMPORT int __stdcall WS2_32$WSAGetLastError();
DECLSPEC_IMPORT int __stdcall WS2_32$getaddrinfo(char* host, char* port, const struct addrinfo* hints, struct addrinfo** result);
DECLSPEC_IMPORT unsigned int __stdcall WS2_32$socket(int af, int type, int protocol);
DECLSPEC_IMPORT int __stdcall WS2_32$closesocket(SOCKET sock);
DECLSPEC_IMPORT int WSAAPI WS2_32$send(SOCKET s, const char* buf, int len, int flags);
DECLSPEC_IMPORT int WSAAPI WS2_32$recv(SOCKET s, char* buf, int len, int flags);
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET, const SOCKADDR*, INT);
DECLSPEC_IMPORT void __stdcall WS2_32$freeaddrinfo(struct addrinfo* ai);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSACleanup();
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);

WINBASEAPI int __cdecl MSVCRT$sprintf(char* __stream, const char* __format, ...);
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char* d, size_t n, const char* format, va_list arg);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict _Dst, const void* __restrict _Src, size_t _MaxCount);

WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI int WINAPI KERNEL32$FileTimeToSystemTime(CONST FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
WINBASEAPI BOOL WINAPI KERNEL32$GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();
WINBASEAPI BOOL WINAPI KERNEL32$SystemTimeToFileTime(CONST SYSTEMTIME* lpSystemTime, LPFILETIME lpFileTime);
WINBASEAPI VOID WINAPI KERNEL32$GetLocalTime(LPSYSTEMTIME lpSystemTime);
WINBASEAPI VOID WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME lpSystemTime);


typedef WINADVAPI BOOL (WINAPI* _ConvertSidToStringSidA)(PSID Sid,LPSTR *StringSid);
typedef WINADVAPI BOOL (__stdcall* _SystemFunction036)(_Out_writes_bytes_(RandomBufferLength) PVOID RandomBuffer, _In_ ULONG RandomBufferLength);
typedef WINADVAPI BOOL (WINAPI* _GetTokenInformation)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
typedef WINADVAPI BOOL (WINAPI* _OpenThreadToken)(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
typedef WINADVAPI BOOL (WINAPI* _OpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
typedef WINADVAPI BOOL (WINAPI* _AllocateAndInitializeSid)(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD nSubAuthority0, DWORD nSubAuthority1, DWORD nSubAuthority2, DWORD nSubAuthority3, DWORD nSubAuthority4, DWORD nSubAuthority5, DWORD nSubAuthority6, DWORD nSubAuthority7, PSID* pSid);
typedef WINADVAPI BOOL (WINAPI* _EqualSid)(PSID pSid1, PSID pSid2);
typedef WINADVAPI PVOID (WINAPI* _FreeSid)(PSID pSid);

typedef WINBASEAPI NTSTATUS (WINAPI* _LsaConnectUntrusted)(PHANDLE LsaHandle);
typedef WINBASEAPI NTSTATUS (WINAPI* _LsaRegisterLogonProcess)(PLSA_STRING LogonProcessName, PHANDLE LsaHandle, PLSA_OPERATIONAL_MODE SecurityMode);
typedef WINBASEAPI NTSTATUS (WINAPI* _LsaGetLogonSessionData)(PLUID LogonId, PSECURITY_LOGON_SESSION_DATA* ppLogonSessionData);
typedef WINBASEAPI NTSTATUS (WINAPI* _LsaEnumerateLogonSessions)(PULONG LogonSessionCount, PLUID* LogonSessionList);
typedef WINBASEAPI NTSTATUS (NTAPI* _LsaFreeReturnBuffer)(PVOID Buffer);
typedef WINBASEAPI NTSTATUS (WINAPI* _LsaCallAuthenticationPackage)(HANDLE LsaHandle, ULONG AuthenticationPackage, PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus);
typedef WINBASEAPI NTSTATUS (NTAPI* _LsaDeregisterLogonProcess)(HANDLE LsaHandle);
typedef WINBASEAPI NTSTATUS (WINAPI* _LsaLookupAuthenticationPackage)(HANDLE LsaHandle, PLSA_STRING PackageName, PULONG AuthenticationPackage);
typedef WINBASEAPI DWORD (WINAPI * _InitializeSecurityContextA)(PCredHandle, PCtxtHandle, SEC_CHAR*, unsigned long, unsigned long, unsigned long, PSecBufferDesc, unsigned long, PCtxtHandle, PSecBufferDesc, unsigned long*, PTimeStamp);
typedef WINBASEAPI SECURITY_STATUS (WINAPI* _DeleteSecurityContext)(PCtxtHandle phContext);
typedef WINBASEAPI SECURITY_STATUS (WINAPI* _FreeCredentialsHandle)(PCredHandle phCredential);
typedef WINBASEAPI SECURITY_STATUS (WINAPI* _AcquireCredentialsHandleA)(SEC_CHAR* pszPrincipal, SEC_CHAR* pszPackage, unsigned int fCredentialUse, void* pvLogonId, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry);


#define OutBlockSize 8192

LPVOID* MEMORY_BANK    __attribute__((section(".data"))) = 0;
DWORD   BANK_COUNT     __attribute__((section(".data"))) = 0;
char*   globalOut      __attribute__((section(".data"))) = 0;
WORD    globalOutSize  __attribute__((section(".data"))) = 0;
WORD    currentOutSize __attribute__((section(".data"))) = 0;

_ConvertSidToStringSidA   ADVAPI32$ConvertSidToStringSidA   __attribute__((section(".data"))) = 0;
_SystemFunction036        ADVAPI32$SystemFunction036        __attribute__((section(".data"))) = 0;
_GetTokenInformation      ADVAPI32$GetTokenInformation      __attribute__((section(".data"))) = 0;
_OpenThreadToken          ADVAPI32$OpenThreadToken          __attribute__((section(".data"))) = 0;
_OpenProcessToken         ADVAPI32$OpenProcessToken         __attribute__((section(".data"))) = 0;
_AllocateAndInitializeSid ADVAPI32$AllocateAndInitializeSid __attribute__((section(".data"))) = 0;
_EqualSid                 ADVAPI32$EqualSid                 __attribute__((section(".data"))) = 0;
_FreeSid                  ADVAPI32$FreeSid                  __attribute__((section(".data"))) = 0;

pRtlAnsiStringToUnicodeString RtlAnsiStringToUnicodeString __attribute__((section(".data"))) = 0;
pRtlInitUnicodeString         RtlInitUnicodeString         __attribute__((section(".data"))) = 0;
pRtlInitAnsiString            RtlInitAnsiString            __attribute__((section(".data"))) = 0;
pCDLocateCheckSum             CDLocateCheckSum             __attribute__((section(".data"))) = 0;
pCDLocateCSystem              CDLocateCSystem              __attribute__((section(".data"))) = 0;

_LsaConnectUntrusted            SECUR32$LsaConnectUntrusted            __attribute__((section(".data"))) = 0;
_LsaRegisterLogonProcess        SECUR32$LsaRegisterLogonProcess        __attribute__((section(".data"))) = 0;
_LsaGetLogonSessionData         SECUR32$LsaGetLogonSessionData         __attribute__((section(".data"))) = 0;
_LsaEnumerateLogonSessions      SECUR32$LsaEnumerateLogonSessions      __attribute__((section(".data"))) = 0;
_LsaFreeReturnBuffer            SECUR32$LsaFreeReturnBuffer            __attribute__((section(".data"))) = 0;
_LsaCallAuthenticationPackage   SECUR32$LsaCallAuthenticationPackage   __attribute__((section(".data"))) = 0;
_LsaDeregisterLogonProcess      SECUR32$LsaDeregisterLogonProcess      __attribute__((section(".data"))) = 0;
_LsaLookupAuthenticationPackage SECUR32$LsaLookupAuthenticationPackage __attribute__((section(".data"))) = 0;
_InitializeSecurityContextA     SECUR32$InitializeSecurityContextA     __attribute__((section(".data"))) = 0;
_DeleteSecurityContext          SECUR32$DeleteSecurityContext          __attribute__((section(".data"))) = 0;
_FreeCredentialsHandle          SECUR32$FreeCredentialsHandle          __attribute__((section(".data"))) = 0;
_AcquireCredentialsHandleA      SECUR32$AcquireCredentialsHandleA      __attribute__((section(".data"))) = 0;

LPVOID MemAlloc(SIZE_T dwBytes) {
    LPVOID mem = KERNEL32$VirtualAlloc(NULL, dwBytes, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    MEMORY_BANK[BANK_COUNT++] = mem;
    return mem;
}

void MemCpy(PBYTE d, PBYTE s, DWORD n) {
    if (d && s)
        MSVCRT$memcpy(d, s, n);
}

void FreeBank() {
    for (int i = 0; i < BANK_COUNT; i++) {
        KERNEL32$VirtualFree(MEMORY_BANK[i], 0, MEM_RELEASE);
    }
    KERNEL32$VirtualFree(MEMORY_BANK, 0, MEM_RELEASE);
}

void SEND_OUT(BOOL done) {
    if (currentOutSize > 0) {
        BeaconOutput(CALLBACK_OUTPUT, globalOut, currentOutSize);

        for (int i = 0; i < currentOutSize; i++)
            globalOut[i] = 0;

        currentOutSize = 0;
    }
    if (done) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, globalOut );

    }
}

int INIT_BOF() {
    globalOut = KERNEL32$HeapAlloc( KERNEL32$GetProcessHeap(), 0, OutBlockSize );
    globalOutSize = OutBlockSize;
    return 1;
}

void PRINT_OUT(char* format, ...) {
    va_list args;
    va_start( args, format );
    int bufSize = MSVCRT$vsnprintf( NULL, 0, format, args );
    va_end(args);

    if (bufSize == -1)
        return;

    if (bufSize + currentOutSize < globalOutSize) {
        MSVCRT$vsnprintf(globalOut + currentOutSize, bufSize, format, args);
        currentOutSize += bufSize;
    }
    else {
        SEND_OUT(FALSE);
        if (bufSize <= globalOutSize) {
            MSVCRT$vsnprintf(globalOut + currentOutSize, bufSize, format, args);
            currentOutSize += bufSize;
        } else {
            char* tmpOut = MemAlloc( bufSize );
            MSVCRT$vsnprintf(tmpOut, bufSize, format, args);
            BeaconOutput(CALLBACK_OUTPUT, tmpOut, bufSize);
//            MemFree(tmpOut);
        }
    }
}

void END_BOF() {
    SEND_OUT(TRUE);
}

BOOL LoadFunc() {
    HMODULE crypt = GetModuleHandleA("CRYPTDLL");
    if (!crypt) crypt = LoadLibraryA("CRYPTDLL");
    if (!crypt) {
        PRINT_OUT("[x] Failed to load CRYPTDLL module\n");
        goto failed;
    }

    CDLocateCheckSum = GetProcAddress(crypt, "CDLocateCheckSum");
    if (!CDLocateCheckSum) goto failed;

    CDLocateCSystem = GetProcAddress(crypt, "CDLocateCSystem");
    if (!CDLocateCSystem) goto failed;
    
    

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) goto failed;

    RtlAnsiStringToUnicodeString = GetProcAddress(ntdll, "RtlAnsiStringToUnicodeString");
    if (!RtlAnsiStringToUnicodeString) goto failed;

    RtlInitUnicodeString = GetProcAddress(ntdll, "RtlInitUnicodeString");
    if (!RtlInitUnicodeString) goto failed;

    RtlInitAnsiString = GetProcAddress(ntdll, "RtlInitAnsiString");
    if (!RtlInitAnsiString) goto failed;




    HMODULE advapi = GetModuleHandleA("ADVAPI32");
    if (!advapi)
        advapi = LoadLibraryA("ADVAPI32");
    if (!advapi) {
        PRINT_OUT("[x] Failed to load ADVAPI32 module\n");
        goto failed;
    }

    ADVAPI32$ConvertSidToStringSidA = GetProcAddress(advapi, "ConvertSidToStringSidA");
    if (!ADVAPI32$ConvertSidToStringSidA) goto failed;

    ADVAPI32$SystemFunction036 = GetProcAddress(advapi, "SystemFunction036");
    if (!ADVAPI32$SystemFunction036) goto failed;

    ADVAPI32$GetTokenInformation = GetProcAddress(advapi, "GetTokenInformation");
    if (!ADVAPI32$GetTokenInformation) goto failed;

    ADVAPI32$OpenThreadToken = GetProcAddress(advapi, "OpenThreadToken");
    if (!ADVAPI32$OpenThreadToken) goto failed;

    ADVAPI32$OpenProcessToken = GetProcAddress(advapi, "OpenProcessToken");
    if (!ADVAPI32$OpenProcessToken) goto failed;

    ADVAPI32$AllocateAndInitializeSid = GetProcAddress(advapi, "AllocateAndInitializeSid");
    if (!ADVAPI32$AllocateAndInitializeSid) goto failed;

    ADVAPI32$EqualSid = GetProcAddress(advapi, "EqualSid");
    if (!ADVAPI32$EqualSid) goto failed;

    ADVAPI32$FreeSid = GetProcAddress(advapi, "FreeSid");
    if (!ADVAPI32$FreeSid) goto failed;

    HMODULE secur32 = GetModuleHandleA("SECUR32");
    if (!secur32)
        secur32 = LoadLibraryA("SECUR32");
    if (!secur32) {
        PRINT_OUT("[x] Failed to load WS2_32 module\n");
        goto failed;
    }

    SECUR32$LsaConnectUntrusted = GetProcAddress(secur32, "LsaConnectUntrusted");
    if (!SECUR32$LsaConnectUntrusted) goto failed;

    SECUR32$LsaRegisterLogonProcess = GetProcAddress(secur32, "LsaRegisterLogonProcess");
    if (!SECUR32$LsaRegisterLogonProcess) goto failed;

    SECUR32$LsaGetLogonSessionData = GetProcAddress(secur32, "LsaGetLogonSessionData");
    if (!SECUR32$LsaGetLogonSessionData) goto failed;

    SECUR32$LsaEnumerateLogonSessions = GetProcAddress(secur32, "LsaEnumerateLogonSessions");
    if (!SECUR32$LsaEnumerateLogonSessions) goto failed;

    SECUR32$LsaFreeReturnBuffer = GetProcAddress(secur32, "LsaFreeReturnBuffer");
    if (!SECUR32$LsaFreeReturnBuffer) goto failed;

    SECUR32$LsaCallAuthenticationPackage = GetProcAddress(secur32, "LsaCallAuthenticationPackage");
    if (!SECUR32$LsaCallAuthenticationPackage) goto failed;

    SECUR32$LsaDeregisterLogonProcess = GetProcAddress(secur32, "LsaDeregisterLogonProcess");
    if (!SECUR32$LsaDeregisterLogonProcess) goto failed;

    SECUR32$LsaLookupAuthenticationPackage = GetProcAddress(secur32, "LsaLookupAuthenticationPackage");
    if (!SECUR32$LsaLookupAuthenticationPackage) goto failed;

    SECUR32$InitializeSecurityContextA = GetProcAddress(secur32, "InitializeSecurityContextA");
    if (!SECUR32$InitializeSecurityContextA) goto failed;

    SECUR32$DeleteSecurityContext = GetProcAddress(secur32, "DeleteSecurityContext");
    if (!SECUR32$DeleteSecurityContext) goto failed;

    SECUR32$FreeCredentialsHandle = GetProcAddress(secur32, "FreeCredentialsHandle");
    if (!SECUR32$FreeCredentialsHandle) goto failed;

    SECUR32$AcquireCredentialsHandleA = GetProcAddress(secur32, "AcquireCredentialsHandleA");
    if ( !SECUR32$AcquireCredentialsHandleA) goto failed;

    MEMORY_BANK = KERNEL32$VirtualAlloc(NULL, sizeof(void*) * 0x1000, MEM_COMMIT, PAGE_READWRITE);
    BANK_COUNT = 0;

    return FALSE;

failed:
    return TRUE;

}



int my_strncmp(const char* s1, const char* s2, int len) {
    int i = 0;
    while ((s1[i] != 0) && (s1[i] == s2[i]) && (i < len))
        i++;
    if (i == len)
        return 0;
    else
        return (int)((unsigned char)s1[i] - (unsigned char)s2[i]);
}

int my_strcmp(const char* s1, const char* s2) {
    while (*s1 != 0 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return (int)((unsigned char)*s1 - (unsigned char)*s2);
}

int my_strfind(const char* s, char c) {
    int index = 0;
    while (*s != '\0') {
        if (*s == c)
            return index;

        s++;
        index++;
    }
    return -1;
}

int my_strlen(char* str) {
    const char *s = str;
    while (*s) {
        ++s;
        if (*(s - 1) == '\0' && *s == '\0') break;
    }
    return s - str;
}

BOOL my_copybuf(byte** dst, byte* src, size_t size) {
    *dst = MemAlloc(size);
    if (!*dst)
        return TRUE;

    MemCpy(*dst, src, size);
    return FALSE;
}



char my_toupper(char c) {
    if (c >= 'a' && c <= 'z')
        return c - ('a' - 'A');

    return c;
}

char my_tolower(char c) {
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');

    return c;
}

int my_tohex(byte* bytes, int length, char** hexString, int retLength) {
    if (retLength < length * 2 + 1)
        return 0;

    for (int i = 0; i < length; i++) {
        (*hexString)[i * 2] = (bytes[i] >> 4) & 0xF;
        (*hexString)[i * 2 + 1] = bytes[i] & 0xF;
        (*hexString)[i * 2] += ((*hexString)[i * 2] < 10) ? '0' : 'A' - 10;
        (*hexString)[i * 2 + 1] += ((*hexString)[i * 2 + 1] < 10) ? '0' : 'A' - 10;
    }
    (*hexString)[length * 2] = 0;
    return retLength;
}

int my_strgetcount( char* str, char c ) {
    int count = 0;
    int index = 0;
    while ( str[index]) {
        if ( str[index] == c )
            count++;
        index++;
    }
    return count;
}

char** my_strsplit( char* str, char c, int* count ) {
    int partCount = my_strgetcount(str, c) + 1;
    char** parts = MemAlloc(partCount * sizeof(void*));
    parts[0] = str;

    int partIndex = 1;
    int index = 0;

    while (str[index] && partIndex < partCount) {
        if (str[index] == c) {
            str[index] = 0;
            parts[partIndex] = str + index + 1;
            partIndex++;
        }
        index++;
    }
    *count = partCount;
    return parts;
}

void StrToUpper(char* str) {
    while (*str != '\0') {
        *str = my_toupper(*str);
        str++;
    }
}

void StrToLower(char* str) {
    while (*str != '\0') {
        *str = my_tolower(*str);
        str++;
    }
}

void GetDomainInfo(char** domain, char** dc) {
    if ((domain && *domain == NULL) || (dc && *dc == NULL)) {
        PDOMAIN_CONTROLLER_INFOA pDomainControllerInfo = NULL;
        DWORD dwError = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &pDomainControllerInfo);
        if (dwError == ERROR_SUCCESS) {
            if (domain && *domain == NULL)
                my_copybuf(domain, pDomainControllerInfo->DomainName, my_strlen(pDomainControllerInfo->DomainName) + 1);

            if (dc && *dc == NULL)
                my_copybuf(dc, ((char*)pDomainControllerInfo->DomainControllerName) + 2, my_strlen(((char*)pDomainControllerInfo->DomainControllerName) + 2) + 1);

            if (pDomainControllerInfo != NULL)
                NETAPI32$NetApiBufferFree(pDomainControllerInfo);
        }
    }
}

int GetStrParam(PCHAR buffer, DWORD bufferLength, PCHAR param, DWORD paramLength, PCHAR* Value){
    if ( my_strncmp(buffer, param, paramLength) == 0 ) {
        int ind = my_strfind(buffer + paramLength, ' ');
        if (ind == -1)
            ind = bufferLength - paramLength - 1;
        my_copybuf(Value, buffer + paramLength, ind + 1);
        (*Value)[ind] = 0;
        return paramLength + ind;
    }
    return 0;
}

int IsSetParam( PCHAR buffer, DWORD bufferLength, PCHAR param, DWORD paramLength, BOOL* Value ){
    if ( my_strncmp(buffer, param, paramLength) == 0 && (buffer[paramLength] == ' ' || buffer[paramLength] == 0) ) {
        *Value = TRUE;
        return paramLength;
    }
    return 0;
}
