#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


#ifdef BOF

DWORD SetPrivilege(
    HANDLE hTokenArg,          // access token handle
    LPCSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege,   // to enable or disable privilege
    BOOL use_thread_token  // use the process or thread token
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
      if (use_thread_token){
        // Open the token used by the thread, which in case of impersonation is
        // different from the process token
	if (FALSE == ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, FALSE, &hToken)) {
	  
	  dwErrorCode = KERNEL32$GetLastError();
	  goto SetPrivilege_end;
	}
      } else {
	// Open a handle to the access token for the calling process. That is this running program
        if( FALSE == ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))    
        {
            dwErrorCode = KERNEL32$GetLastError();
            goto SetPrivilege_end;
        }
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


VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
  char* priv_name = NULL;
	datap parser = {0};
	BeaconDataParse(&parser, Buffer, Length);
	char * priv = BeaconDataExtract(&parser, NULL);
	BOOL use_thread_token = FALSE;

	if(!bofstart())
	{
		return;
	}

        // In case privileges are preppended by ~
        // then it will apply to current thread token instead of process token.
        // For example: ~SeDebugPrivilege
        // Useful for modify an impersonated token
	if (priv[0] == '~') {
	  priv_name = priv + 1;
	  use_thread_token = TRUE;
	} else {
	  priv_name = priv;
	  use_thread_token = FALSE;
	}
	DWORD status = SetPrivilege(NULL, priv_name, TRUE, use_thread_token);
	if(status != ERROR_SUCCESS)
	{
		internal_printf("Failed to activate priv %s : %d", (*priv) ? priv : "NOT SPECIFIED", status);
	}
	else{
		internal_printf("SUCCESS: Activated priv %s.\n", priv);
	}
	


go_end:

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
