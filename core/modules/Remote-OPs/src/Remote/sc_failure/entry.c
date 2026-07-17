#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

void ___chkstk_ms() { return; }

int myAtoi(char* str)
{
    // take ASCII character of corresponding digit and subtract the code from '0' to get numerical
    // value and multiply res by 10 to shuffle digits left to update running total
	int res = 0;
    for (int i = 0; str[i] != '\0'; ++i)
        res = res * 10 + str[i] - '0';
 
    return res;
}

DWORD config_failure(const char* Hostname, const char* cpServiceName, DWORD dwResetPeriod, LPSTR lpRebootMsg, LPSTR lpCommand, DWORD cActions, LPSTR lpsaActions)
{
	DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scManager = NULL;
	SC_HANDLE scService = NULL;
	HANDLE hToken = NULL;
	LUID luid;
	SERVICE_FAILURE_ACTIONSA serviceFailureActions;
	serviceFailureActions.dwResetPeriod = dwResetPeriod;
	serviceFailureActions.lpRebootMsg = lpRebootMsg;
	serviceFailureActions.lpCommand = lpCommand;
	serviceFailureActions.cActions = cActions;

    char buffer[100];
    int bufferIndex = 0;
	int actionsIndex = 0;
	SC_ACTION actions[cActions];
	int counter = 0;

    // Iterate through lpsaActions
    for (int i = 0; lpsaActions[i] != '\0'; i++) {
        if (lpsaActions[i] == '/') {
            // Found a delimiter, null-terminate the buffer and assign the substring
            buffer[bufferIndex] = '\0';

			if (counter < 1) { 
				actions[actionsIndex].Type = myAtoi(buffer);
				counter++;
			}
			else { 
				actions[actionsIndex].Delay = myAtoi(buffer);
				counter--;
				actionsIndex++;
			}

            // Reset the buffer for the next substring
            bufferIndex = 0;
        } else {
            // Copy the character into the buffer
            buffer[bufferIndex] = lpsaActions[i];
            bufferIndex++;

            // Check for buffer overflow
            if (bufferIndex >= sizeof(buffer)) { break; }
        }
    }

    // Assign the last substring
    if (bufferIndex > 0) {
        buffer[bufferIndex] = '\0';
        actions[actionsIndex].Delay = myAtoi(buffer);
    }

	serviceFailureActions.lpsaActions= actions;
	
	// Open the service control manager
	scManager = ADVAPI32$OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT);
	if (NULL == scManager)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("OpenSCManagerA failed (%lu)\n", dwResult);
		goto config_failure_end;
	}

	// Open the service
	scService = ADVAPI32$OpenServiceA(scManager, cpServiceName, SERVICE_ALL_ACCESS);
	if (NULL == scService)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("OpenServiceA failed (%lu)\n", dwResult);
		goto config_failure_end;
	}

	// Enabling the SE_SHUTDOWN_NAME privilege 

	ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	ADVAPI32$LookupPrivilegeValueA(NULL, SE_SHUTDOWN_NAME, &luid);
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, 0);

	// Set the service configuration
	if( FALSE == ADVAPI32$ChangeServiceConfig2A(
			scService,
			SERVICE_CONFIG_FAILURE_ACTIONS,
			&serviceFailureActions
		)
	)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("ChangeServiceConfig2A failed (%lu)\n", dwResult);
		goto config_failure_end;
	}

config_failure_end:

	if (scService)
	{
		ADVAPI32$CloseServiceHandle(scService);
		scService = NULL;
	}

	if (scManager)
	{
		ADVAPI32$CloseServiceHandle(scManager);
		scManager = NULL;
	}
	if(hToken)
	{
		KERNEL32$CloseHandle(hToken);
		hToken = NULL;
	}
	return dwResult;
}


#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	datap parser;
	const char * hostname = NULL;
	const char * servicename = NULL;
	DWORD resetPeriod = 0;
	char * rebootMsg = NULL;
	char * command = NULL;
	DWORD actions = 0;
	char * saActions = NULL;

	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	servicename = BeaconDataExtract(&parser, NULL);
	resetPeriod = BeaconDataInt(&parser);
	rebootMsg = BeaconDataExtract(&parser, NULL);
	command = BeaconDataExtract(&parser, NULL);
	actions = (DWORD)BeaconDataShort(&parser);
	saActions = BeaconDataExtract(&parser, NULL);

	if(!bofstart())
	{
		return;
	}

	internal_printf("config_failure:\n");
	internal_printf("  hostname:    %s\n", hostname);
	internal_printf("  servicename: %s\n", servicename);
	internal_printf("  resetPeriod:  %lu\n", resetPeriod);
	internal_printf("  rebootMsg:   %s\n", rebootMsg);
	internal_printf("  command:   %s\n", command);
	internal_printf("  actions:   %lX\n", actions);
	internal_printf("  saActions:   %s\n", saActions);

	dwErrorCode = config_failure(hostname, servicename, resetPeriod, rebootMsg, command, actions, saActions);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "config_failure failed: %lu\n", dwErrorCode);
		goto go_end;
	}

	internal_printf("SUCCESS.\n");

go_end:

	printoutput(TRUE);
	
	bofstop();
};
#else
#define TEST_HOSTNAME        ""
#define TEST_SVC_NAME        "BOF_SVC_NAME"
int main(int argc, char ** argv)
{
	DWORD  dwErrorCode		= ERROR_SUCCESS;
	LPCSTR lpcszHostName	= TEST_HOSTNAME;
	LPCSTR lpcszServiceName	= TEST_SVC_NAME;
	DWORD  dwResetPeriod	= 0;
	LPSTR  lpRebootMsg		= "";
	LPSTR  lpCommand		= "";
	DWORD  cActions			= 0;
	LPSTR  lpsaActions		= "";

	internal_printf("config_failure:\n");
	internal_printf("  lpcszHostName:    %s\n", lpcszHostName);
	internal_printf("  lpcszServiceName: %s\n", lpcszServiceName);
	internal_printf("  dwResetPeriod:     %lu\n", dwResetPeriod);
	internal_printf("  lpRebootMsg:      %s\n", lpRebootMsg);
	internal_printf("  lpCommand:      %s\n", lpCommand);
	internal_printf("  cActions:      %lX\n", cActions);
	internal_printf("  lpsaActions:      %s\n", lpsaActions);

	dwErrorCode = config_failure(
		lpcszHostName,
		lpcszServiceName,
		dwResetPeriod,
		lpRebootMsg,
		lpCommand,
		cActions,
		lpsaActions
	);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "config_failure failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif
