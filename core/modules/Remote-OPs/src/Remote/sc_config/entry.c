#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


DWORD config_service(const char* Hostname, const char* cpServiceName, const char * binpath, DWORD errmode, DWORD startmode)
{
	DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scManager = NULL;
	SC_HANDLE scService = NULL;

	// Open the service control manager
	scManager = ADVAPI32$OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT);
	if (NULL == scManager)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("OpenSCManagerA failed (%lu)\n", dwResult);
		goto config_service_end;
	}

	// Open the service
	scService = ADVAPI32$OpenServiceA(scManager, cpServiceName, SERVICE_CHANGE_CONFIG);
	if (NULL == scService)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("OpenServiceA failed (%lu)\n", dwResult);
		goto config_service_end;
	}

	// Set the service configuration
	if( FALSE == ADVAPI32$ChangeServiceConfigA(
			scService,
			SERVICE_NO_CHANGE,
			startmode,
			errmode,
			binpath,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		)
	)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("ChangeServiceConfigA failed (%lu)\n", dwResult);
		goto config_service_end;
	}


config_service_end:

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
	const char * binpath = NULL;
	DWORD ignoremode = 0;
	DWORD startmode = 0;

	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	servicename = BeaconDataExtract(&parser, NULL);
	binpath = BeaconDataExtract(&parser, NULL);
	ignoremode = (DWORD)BeaconDataShort(&parser);
	startmode = (DWORD)BeaconDataShort(&parser);

	if(!bofstart())
	{
		return;
	}
	if(*binpath == 0) {binpath = NULL;}

	internal_printf("config_service:\n");
	internal_printf("  hostname:    %s\n", hostname);
	internal_printf("  servicename: %s\n", servicename);
	internal_printf("  binpath:     %s\n", (binpath) ? binpath : "(Unchanged)");
	internal_printf("  ignoremode:  %lX\n", ignoremode);
	internal_printf("  startmode:   %lX\n", startmode);

	dwErrorCode = config_service(hostname, servicename, binpath, ignoremode, startmode);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "config_service failed: %lu\n", dwErrorCode);
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
#define TEST_BIN_PATH        "C:\\Windows\\System32\\alg.exe"
int main(int argc, char ** argv)
{
	DWORD  dwErrorCode       = ERROR_SUCCESS;
	LPCSTR lpcszHostName     = TEST_HOSTNAME;
	LPCSTR lpcszServiceName  = TEST_SVC_NAME;
	LPCSTR lpcszBinPath      = TEST_BIN_PATH;
	DWORD  dwErrorMode       = SERVICE_ERROR_IGNORE;
	DWORD  dwStartMode       = SERVICE_AUTO_START;
	
	internal_printf("config_service:\n");
	internal_printf("  lpcszHostName:    %s\n", lpcszHostName);
	internal_printf("  lpcszServiceName: %s\n", lpcszServiceName);
	internal_printf("  lpcszBinPath:     %s\n", lpcszBinPath);
	internal_printf("  dwErrorMode:      %lX\n", dwErrorMode);
	internal_printf("  dwStartMode:      %lX\n", dwStartMode);

	dwErrorCode = config_service(
		lpcszHostName, 
		lpcszServiceName, 
		lpcszBinPath, 
		dwErrorMode, 
		dwStartMode
	);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "config_service failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif
