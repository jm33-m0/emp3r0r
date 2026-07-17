#include <windows.h>
#include <winreg.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DWORD SetPrivilege(
	HANDLE hTokenArg,		        // access token handle
	LPCSTR lpszPrivilege,           // name of privilege to enable/disable
	BOOL bEnablePrivilege           // to enable or disable privilege
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
			NULL,			    // lookup privilege on local system
			lpszPrivilege,      // privilege to lookup
			&luid ) )		    // receives LUID of privilege
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

#ifdef BOF
VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	datap parser = {0};

	BeaconDataParse(&parser, Buffer, Length);
	const char * hostname = BeaconDataExtract(&parser, NULL);
	const char * message = BeaconDataExtract(&parser, NULL);
	DWORD timeout = (DWORD)BeaconDataInt(&parser);
	const short closeapps = BeaconDataShort(&parser);
	const short reboot = BeaconDataShort(&parser);
	BOOL status;
    const char * privilege = (! hostname[0] ? "SeShutdownPrivilege" : "SeRemoteShutdownPrivilege");

	HANDLE currentTokenHandle = NULL;
	if(!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle))
	{
		BeaconPrintf(CALLBACK_ERROR, "Can't get a handle to ourself, that's odd, stopping\n");
		return;
	}
	
	if (!SetPrivilege(currentTokenHandle, privilege, TRUE))
	{
		BeaconPrintf(CALLBACK_OUTPUT, "%s enabled!\n", privilege);
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to set %s, stopping\n", privilege);
		return;
	}


	status = ADVAPI32$InitiateSystemShutdownExA((LPSTR) hostname, (LPSTR) message, timeout, closeapps, reboot, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_SECURITYFIX | SHTDN_REASON_FLAG_PLANNED);
	dwErrorCode = KERNEL32$GetLastError();
	if(status)
	{
        if(! hostname[0]) {
    		BeaconPrintf(CALLBACK_OUTPUT, "Successfully called InitiateSystemShutdownExW: %lu", dwErrorCode);
        } else {
    		BeaconPrintf(CALLBACK_OUTPUT, "Successfully called InitiateSystemShutdownExW on %s: %lu", hostname, dwErrorCode);
        }
	} else {
       if(! hostname[0]) {
    		BeaconPrintf(CALLBACK_ERROR, "Failed to call InitiateSystemShutdownExW: %lu", dwErrorCode);
       } else {
    		BeaconPrintf(CALLBACK_ERROR, "Failed to call InitiateSystemShutdownExW on %s: %lu", hostname, dwErrorCode);
       }
    }


	if (!SetPrivilege(currentTokenHandle, privilege, FALSE))
	{
		BeaconPrintf(CALLBACK_OUTPUT, "%s Disabled!\n", privilege);
	}
	KERNEL32$CloseHandle(currentTokenHandle);
	
}
#else
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	const char * hostname = "";
	const char * message = "This was a test of shutdown BOF. System will reboot in 10s";
	DWORD timeout = 10;
	const short closeapps = 1;
	const short reboot = 1;
	BOOL status;
    const char * privilege = "SeShutdownPrivilege";

	HANDLE currentTokenHandle = NULL;
	BOOL getCurrentToken = ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
	if(getCurrentToken)
	{
		if (!SetPrivilege(currentTokenHandle, privilege, TRUE))
		{
			BeaconPrintf(CALLBACK_OUTPUT, "[+] %s enabled!\n", privilege);
		}
		else
		{
			BeaconPrintf(CALLBACK_ERROR, "Unable to get %s, stopping\n", privilege);
			return;
		}
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "Can't get a handle to ourself, that's odd, stopping\n");
		return;
	}

	status = ADVAPI32$InitiateSystemShutdownExA((LPSTR) hostname, (LPSTR) message, timeout, closeapps, reboot, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_SECURITYFIX | SHTDN_REASON_FLAG_PLANNED);
	if(status)
	{
    DWORD dwErrorCode = KERNEL32$GetLastError();

        if(! MSVCRT$strcmp(hostname, "")) {
    		BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully called InitiateSystemShutdownExW: %lX", dwErrorCode);
        } else {
    		BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully called InitiateSystemShutdownExW on %s: %lX", hostname, dwErrorCode);
        }
	} else {
        if(! MSVCRT$strcmp(hostname, "")) {
    		BeaconPrintf(CALLBACK_ERROR, "Failed to call InitiateSystemShutdownExW: %lX", dwErrorCode);
        } else {
    		BeaconPrintf(CALLBACK_ERROR, "Failed to call InitiateSystemShutdownExW on %s: %lX", hostname, dwErrorCode);
        }
	}

	if(getCurrentToken)
	{
		if (!SetPrivilege(currentTokenHandle, privilege, FALSE))
		{
			BeaconPrintf(CALLBACK_OUTPUT, "[+] %s Disabled!\n", privilege);
		}
		KERNEL32$CloseHandle(currentTokenHandle);
	}
    return status;
}
#endif