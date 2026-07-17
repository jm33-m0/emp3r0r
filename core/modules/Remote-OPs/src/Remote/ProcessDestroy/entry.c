#include <windows.h>
#include <ntstatus.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"

 
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS (NTAPI *_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
typedef NTSTATUS (NTAPI *_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
 
typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;
 
 
typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

 
PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName) {
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

DWORD cutit(DWORD pid, USHORT handleID)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HANDLE processHandle = NULL;
    _NtDuplicateObject NtDuplicateObject = NULL;

    NtDuplicateObject = GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");

    if (NULL == NtDuplicateObject) {
        dwErrorCode = ERROR_INVALID_FUNCTION;
        internal_printf("Failed to resolve NT functions.\n");
        goto cutit_end;
    }

    processHandle = KERNEL32$OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (NULL == processHandle) {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("Could not open PID %lu! (Don't try to open a system process.)\n", pid);
        goto cutit_end;
    }
    
    #pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
    dwErrorCode = (DWORD)NtDuplicateObject(
        processHandle, // sph
        (HANDLE) handleID,//sh
        NULL, //tph
        NULL, //th
        0, //dh
        0, //ha
        DUPLICATE_CLOSE_SOURCE //options
    );
    #pragma GCC diagnostic pop
    if (!NT_SUCCESS(dwErrorCode)) {
        internal_printf("Failed to close handle %u in pid:%lu (%lX)\n", handleID, pid, dwErrorCode);
    } else {
        internal_printf("Closed handle %u in pid:%lu\n", handleID, pid);
    }

cutit_end:
    if (processHandle) {
        KERNEL32$CloseHandle(processHandle);
        processHandle = NULL;
    }

    return dwErrorCode;
}
 
DWORD killit(DWORD pid) {
 
    DWORD dwErrorCode = ERROR_SUCCESS;
    PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
    ULONG handleInfoSize = 0x10000;
    HANDLE processHandle = NULL;
    ULONG i = 0;
    _NtQuerySystemInformation NtQuerySystemInformation = NULL;
    _NtDuplicateObject NtDuplicateObject = NULL;

    NtQuerySystemInformation = GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
    NtDuplicateObject = GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");

    if ((NULL == NtQuerySystemInformation)||(NULL == NtDuplicateObject)) {
        dwErrorCode = ERROR_INVALID_FUNCTION;
        internal_printf("Failed to resolve NT functions.\n");
        goto killit_end;
    }

    processHandle = KERNEL32$OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (NULL == processHandle) {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("Could not open PID %lu! (Don't try to open a system process.)\n", pid);
        goto killit_end;
    }

    handleInfo = (PSYSTEM_HANDLE_INFORMATION)intAlloc(handleInfoSize);
    if ( NULL == handleInfo ) {
        dwErrorCode = ERROR_OUTOFMEMORY;
        internal_printf("Failed to allocate handle info\n");
        goto killit_end;
    }
 
    // NtQuerySystemInformation won't give us the correct buffer size,
    //  so we guess by doubling the buffer size.
    while ((dwErrorCode = (DWORD)NtQuerySystemInformation(
            SystemHandleInformation,
            handleInfo,
            handleInfoSize,
            NULL
        )) == STATUS_INFO_LENGTH_MISMATCH) {
        
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)intRealloc(handleInfo, handleInfoSize *= 2);
        if ( NULL == handleInfo ) {
            dwErrorCode = ERROR_OUTOFMEMORY;
            internal_printf("Failed to reallocate handle info\n");
            goto killit_end;
        }
    }
 
    // NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
    if (!NT_SUCCESS(dwErrorCode)) {
        internal_printf("NtQuerySystemInformation failed! (%lX)\n", dwErrorCode);
        goto killit_end;
    }

    for (i = 0; i < handleInfo->Count; i++) {
        SYSTEM_HANDLE_ENTRY handle = handleInfo->Handle[i];
 
        // Check if this handle belongs to the PID the user specified.
        if (handle.OwnerPid != pid)
            continue;
        // Check if we're cutting a specific handle or all

        // Duplicate the handle so we can query it.
        #pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
        dwErrorCode = (DWORD)NtDuplicateObject(
            processHandle, // sph
            (HANDLE) handle.HandleValue,//sh
            NULL, //tph
            NULL, //th
            0, //dh
            0, //ha
            DUPLICATE_CLOSE_SOURCE //options
        );
        #pragma GCC diagnostic pop
        if (!NT_SUCCESS(dwErrorCode)) {
            internal_printf("Failed to close handle %u in pid:%lu (%lX)\n", handle.HandleValue, pid, dwErrorCode);
            continue;
        } else {
            //internal_printf("Closed handle %u in pid:%lu\n", handle.HandleValue, pid);
		}
    }

    internal_printf("Closed all handles in pid:%lu\n", pid);
 
 killit_end:
    if (handleInfo) {
        intFree(handleInfo);
        handleInfo = NULL;
    }
    
    if (processHandle) {
        KERNEL32$CloseHandle(processHandle);
        processHandle = NULL;
    }
  
    return dwErrorCode;
}


#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
    DWORD dwErrorCode = ERROR_SUCCESS;
	DWORD dwPid = 0;
	USHORT wHandleID = 0;
	datap parser = {0};
	BeaconDataParse(&parser, Buffer, Length);
	
    dwPid = BeaconDataInt(&parser);
    wHandleID = (USHORT)BeaconDataInt(&parser);

	if(!bofstart())
	{
		return;
	}

    if(wHandleID)
    {
        internal_printf("Killing handle:%u in PID:%lu\n", wHandleID, dwPid);

        dwErrorCode = cutit(dwPid, wHandleID);
        if ( ERROR_SUCCESS != dwErrorCode )
        {
            BeaconPrintf(CALLBACK_ERROR, "cutit failed! (%lX)\n", dwErrorCode);	
            goto go_end;
        }
    }
    else
    {
        internal_printf("Killing all handles in PID:%lu\n", dwPid);

        dwErrorCode = killit(dwPid);
        if ( ERROR_SUCCESS != dwErrorCode )
        {
            BeaconPrintf(CALLBACK_ERROR, "killit failed! (%lX)\n", dwErrorCode);	
            goto go_end;
        }
    }

    internal_printf("SUCCESS.\n");

go_end:
	printoutput(TRUE);

	bofstop();
};
#else
#define TEST_TARGET_HANDLE_ID 0
#define TEST_TARGET_PROCESS L"C:\\Windows\\System32\\notepad.exe"
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	DWORD dwPid = 0;
	USHORT wHandleID = TEST_TARGET_HANDLE_ID;
	STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    MSVCRT$memset( &si, 0, sizeof(si) );
    si.cb = sizeof(si);
    MSVCRT$memset( &pi, 0, sizeof(pi) );
	
	if ( !KERNEL32$CreateProcessW( TEST_TARGET_PROCESS, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi ) ) 		
	{
		dwErrorCode = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "CreateProcessW failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	dwPid = pi.dwProcessId;

	KERNEL32$CloseHandle( pi.hProcess );
    KERNEL32$CloseHandle( pi.hThread );
	
    if(wHandleID)
    {
        internal_printf("Killing handle:%u in PID:%lu\n", wHandleID, dwPid);

        dwErrorCode = cutit(dwPid, wHandleID);
        if ( ERROR_SUCCESS != dwErrorCode )
        {
            BeaconPrintf(CALLBACK_ERROR, "cutit failed! (%lX)\n", dwErrorCode);
            goto main_end;
        }
    }
    else
    {
        internal_printf("Killing all handles in PID:%lu\n", dwPid);

        dwErrorCode = killit(dwPid);
        if ( ERROR_SUCCESS != dwErrorCode )
        {
            BeaconPrintf(CALLBACK_ERROR, "killit failed! (%lX)\n", dwErrorCode);
            goto main_end;
        }
    }

    internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif
