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
typedef NTSTATUS (NTAPI *_NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
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
 
DWORD killit(DWORD pid) {
 
    DWORD dwErrorCode = ERROR_SUCCESS;
    PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
    ULONG handleInfoSize = 0x10000;
    HANDLE processHandle = NULL;
    ULONG i = 0;
    HANDLE dupHandle = NULL;
    POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;
    PVOID objectNameInfo = NULL;
    _NtQuerySystemInformation NtQuerySystemInformation = NULL;
    _NtDuplicateObject NtDuplicateObject = NULL;
    _NtQueryObject NtQueryObject = NULL;

    NtQuerySystemInformation = GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
    NtDuplicateObject = GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
    NtQueryObject = GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

    if ((NULL == NtQuerySystemInformation)||(NULL == NtDuplicateObject)||(NULL == NtQueryObject)) {
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
        UNICODE_STRING objectName;
        ULONG returnLength = 0;

        MSVCRT$memset(&objectName, 0, sizeof(UNICODE_STRING));

        if (objectTypeInfo) {
            intFree(objectTypeInfo);
            objectTypeInfo = NULL;
        }

        if (objectNameInfo) {
            intFree(objectNameInfo);
            objectNameInfo = NULL;
        }

        if (dupHandle) {
            KERNEL32$CloseHandle(dupHandle);
            dupHandle = NULL;
        }

        
 
        // Check if this handle belongs to the PID the user specified.
        if (handle.OwnerPid != pid)
            continue;
 
        // Duplicate the handle so we can query it.
        #pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
        dwErrorCode = (DWORD)NtDuplicateObject(
            processHandle, // sph
            (HANDLE) handle.HandleValue,//sh
            KERNEL32$GetCurrentProcess(),
            &dupHandle,
            0, //dh
            0, //ha
            0 //options
        );
        #pragma GCC diagnostic pop
        if (!NT_SUCCESS(dwErrorCode)) {
            internal_printf("Failed to duplicate handle %u in pid:%lu (%lX)\n", handle.HandleValue, pid, dwErrorCode);
            continue;
        } 
 
        // Allocate the object type
        objectTypeInfo = (POBJECT_TYPE_INFORMATION)intAlloc(0x1000);
        if ( NULL == objectTypeInfo ) {
            internal_printf("Failed to allocate objectTypeInfo\n");
            continue;
        }

        // Query the object type
        dwErrorCode = (DWORD)NtQueryObject(
            dupHandle,
            ObjectTypeInformation,
            objectTypeInfo,
            0x1000,
            NULL
        );
        if (!NT_SUCCESS(dwErrorCode)) {
            internal_printf("Failed to query the object type for handle %#X in pid:%lu (%lX)\n", (UINT)handle.HandleValue, pid, dwErrorCode);
            continue;
        }
 
        // Query the object name 
        // (unless it has an access of 0x0012019f, on which NtQueryObject could hang)
        if (handle.AccessMask == 0x0012019f) {
 
            // We have the type, so display that.
            internal_printf(
                "[%#d] %.*S: (did not get name)\n",
                handle.HandleValue,
                objectTypeInfo->TypeName.Length / 2,
                objectTypeInfo->TypeName.Buffer
                );
            continue;
        }
 
        objectNameInfo = intAlloc(0x1000);
        if ( NULL == objectNameInfo ) {
            internal_printf("Failed to allocate objectNameInfo\n");
            continue;
        }

        dwErrorCode = (DWORD)NtQueryObject(
            dupHandle,
            ObjectNameInformation,
            objectNameInfo,
            0x1000,
            &returnLength
        );
        if (!NT_SUCCESS(dwErrorCode)) {
 
            // Reallocate the buffer and try again.
            objectNameInfo = intRealloc(objectNameInfo, returnLength);
            if ( NULL == objectNameInfo ) {
                internal_printf("Failed to allocate objectNameInfo\n");
                continue;
            }

            dwErrorCode = (DWORD)NtQueryObject(
                dupHandle,
                ObjectNameInformation,
                objectNameInfo,
                returnLength,
                NULL
            );
            if (!NT_SUCCESS(dwErrorCode)) {
 
                // We have the type name, so just display that.
                internal_printf(
                    "[%#d] %.*S: (could not get name)\n",
                    handle.HandleValue,
                    objectTypeInfo->TypeName.Length / 2,
                    objectTypeInfo->TypeName.Buffer
                    );
                continue;
            }
        }
 
        // Cast our buffer into an UNICODE_STRING.
        objectName = *(PUNICODE_STRING)objectNameInfo;
 
        // Print the information!
        if (objectName.Length)
        {
            // The object has a name.
            internal_printf(
                "[%#d] %.*S: %.*S\n",
                handle.HandleValue,
                objectTypeInfo->TypeName.Length / 2,
                objectTypeInfo->TypeName.Buffer,
                objectName.Length / 2,
                objectName.Buffer
                );
        }
        else {
            // Print something else.
            internal_printf(
                "[%#d] %.*S: (unnamed)\n",
                handle.HandleValue,
                objectTypeInfo->TypeName.Length / 2,
                objectTypeInfo->TypeName.Buffer
                );
        }
    }

    dwErrorCode = ERROR_SUCCESS;
 
 killit_end:
    if (handleInfo) {
        intFree(handleInfo);
        handleInfo = NULL;
    }

    if (processHandle) {
        KERNEL32$CloseHandle(processHandle);
        processHandle = NULL;
    }

    if (objectTypeInfo) {
        intFree(objectTypeInfo);
        objectTypeInfo = NULL;
    }

    if (objectNameInfo) {
        intFree(objectNameInfo);
        objectNameInfo = NULL;
    }

    if (dupHandle) {
        KERNEL32$CloseHandle(dupHandle);
        dupHandle = NULL;
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
	datap parser = {0};

	BeaconDataParse(&parser, Buffer, Length);

    dwPid = BeaconDataInt(&parser);

	if(!bofstart())
	{
		return;
	}

    internal_printf("Listing handles for PID:%lu\n", dwPid);

	dwErrorCode = killit(dwPid);
    if ( ERROR_SUCCESS != dwErrorCode )
    {
        BeaconPrintf(CALLBACK_ERROR, "killit failed: %lX\n", dwErrorCode);
        goto go_end;
    }

    internal_printf("SUCCESS.\n");

go_end:
	printoutput(TRUE);

	bofstop();
};
#else
#define TEST_TARGET_PROCESS L"C:\\Windows\\System32\\notepad.exe"
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	DWORD dwPid = 0;
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
	
	internal_printf("Listing handles for PID:%lu\n", dwPid);

    dwErrorCode = killit(dwPid);
    if ( ERROR_SUCCESS != dwErrorCode )
    {
        BeaconPrintf(CALLBACK_ERROR, "killit failed: %lX\n", dwErrorCode);
        goto main_end;
    }

    internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif
