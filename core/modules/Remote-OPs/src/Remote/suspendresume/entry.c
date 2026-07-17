#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DECLSPEC_IMPORT WINAPI HRESULT NTDLL$NtSuspendProcess(HANDLE hprocess);
DECLSPEC_IMPORT WINAPI HRESULT NTDLL$NtResumeProcess(HANDLE hprocess);

DWORD SetPrivilege(
    HANDLE hTokenArg,          // access token handle
    LPCSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    ) 
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    DWORD dwErrorCode = ERROR_SUCCESS;

    if ( hTokenArg )
    {
        hToken = hTokenArg;
    }
    else
    {
        // Open a handle to the access token for the calling process. That is this running program
        if( FALSE == ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))    
        {
            dwErrorCode = KERNEL32$GetLastError();
            goto SetPrivilege_end;
        }
    }
    

    if ( FALSE == ADVAPI32$LookupPrivilegeValueA( 
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
        dwErrorCode = KERNEL32$GetLastError();
        goto SetPrivilege_end; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if ( FALSE == ADVAPI32$AdjustTokenPrivileges(
           hToken, 
           FALSE, 
           &tp, 
           sizeof(TOKEN_PRIVILEGES), 
           (PTOKEN_PRIVILEGES) NULL, 
           (PDWORD) NULL) )
    {
        dwErrorCode = KERNEL32$GetLastError();
        goto SetPrivilege_end; 
    } 

    // Possibly ERROR_NOT_ALL_ASSIGNED
    dwErrorCode = KERNEL32$GetLastError();

SetPrivilege_end:

    if ( !hTokenArg )
    {
        if ( hToken )
        {
            KERNEL32$CloseHandle(hToken);
            hToken = NULL;
        }
    }

    return dwErrorCode;
}

HANDLE openProcessForSuspendResume(DWORD pid)
{
	HANDLE result = INVALID_HANDLE_VALUE;
	result = KERNEL32$OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
	if(!result)
	{
		internal_printf("[-] Failed to open process %lu : %lu\n", pid, KERNEL32$GetLastError());
	}
	return result;
}

BOOL suspend(DWORD pid)
{
	HANDLE htarget = openProcessForSuspendResume(pid);
	if(!htarget)
	{
		return FALSE;
	}
	else
	{
		HRESULT status = NTDLL$NtSuspendProcess(htarget);
		if(NT_SUCCESS(status))
		{
			internal_printf("[+] Success suspending process %lu\n", pid);
		}
		else
		{
			internal_printf("[-] Failed to suspend process 0x%x\n", status);
		}
		KERNEL32$CloseHandle(htarget);
		return TRUE;
	}
}

BOOL resume(DWORD pid)
{
	HANDLE htarget = openProcessForSuspendResume(pid);
	if(!htarget)
	{
		return FALSE;
	}
	else
	{
		HRESULT status = NTDLL$NtResumeProcess(htarget);
		if(NT_SUCCESS(status))
		{
			internal_printf("[+] Success resuming process %lu\n", pid);
		}
		else
		{
			internal_printf("[-] Failed to resuming process 0x%x\n", status);
		}
		KERNEL32$CloseHandle(htarget);
		return TRUE;
	}
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	datap parser = {0};

	BeaconDataParse(&parser, Buffer, Length);
	const short option = BeaconDataShort(&parser); // 0 to resume, 1 to suspend
	DWORD pid = (DWORD)BeaconDataInt(&parser);
	
	if(!bofstart())
	{
		return;
	}

	HANDLE currentTokenHandle = NULL;
	BOOL getCurrentToken = ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
	if(getCurrentToken)
	{
		if (!SetPrivilege(currentTokenHandle, "SeDebugPrivilege", TRUE))
		{
			internal_printf("[+] SeDebugPrivilege enabled!\n");
		}
		else
		{
			internal_printf("[-] Unable to get SeDebugPrivilege, still trying but this may fail\n");
		}
	}
	else
	{
		internal_printf("[-]Can't get a handle to ourself, that's odd\n");
	}

	if(option)
	{
		suspend(pid);
	}
	else
	{
		resume(pid);
	}
	if(getCurrentToken)
	{
		if (!SetPrivilege(currentTokenHandle, "SeDebugPrivilege", FALSE))
		{
			internal_printf("[+] SeDebugPrivilege Disabled!\n");
		}
		KERNEL32$CloseHandle(currentTokenHandle);
	}

	printoutput(TRUE);
	
	bofstop();
};
#else
#define TEST_STRING_ARG "TEST_STRING_ARG"
#define TEST_INT_ARG 12345
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	const char * string_arg = TEST_STRING_ARG;
	int int_arg = TEST_INT_ARG;

	internal_printf("Calling YOUNAMEHERE with arguments %s and %d\n", string_arg, int_arg );

	dwErrorCode = YOUNAMEHERE(string_arg, int_arg);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "YOUNAMEHERE failed: %lX\n", dwErrorCode);	
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif