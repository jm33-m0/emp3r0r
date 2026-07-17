#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


DWORD delete_service(const char* Hostname, const char* cpServiceName)
{
	DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scManager = NULL;
	SC_HANDLE scService = NULL;

	// Open the service control manager
	scManager = ADVAPI32$OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT);
	if (NULL == scManager)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("OpenSCManagerA failed (%lX)\n", dwResult);
		goto delete_service_end;
	}

	// Open the service
	scService = ADVAPI32$OpenServiceA(scManager, cpServiceName, DELETE);
	if (NULL == scService)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("OpenServiceA failed (%lX)\n", dwResult);
		goto delete_service_end;
	}

	// Delete the service
	if( FALSE == ADVAPI32$DeleteService(scService))
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("DeleteService failed (%lX)\n", dwResult);
		goto delete_service_end;
	}

delete_service_end:
	
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

	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	servicename = BeaconDataExtract(&parser, NULL);

	if(!bofstart())
	{
		return;
	}
	
	internal_printf("delete_service:\n");
	internal_printf("  hostname:    %s\n", hostname);
	internal_printf("  servicename: %s\n", servicename);

	dwErrorCode = delete_service(hostname, servicename);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "delete_service failed: %lX\n", dwErrorCode);
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
	DWORD  dwErrorCode       = ERROR_SUCCESS;
	LPCSTR lpcszHostName     = TEST_HOSTNAME;
	LPCSTR lpcszServiceName  = TEST_SVC_NAME;
	
	internal_printf("delete_service:\n");
	internal_printf("  lpcszHostName:    %s\n", lpcszHostName);
	internal_printf("  lpcszServiceName: %s\n", lpcszServiceName);

	dwErrorCode = delete_service(
		lpcszHostName, 
		lpcszServiceName
	);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "delete_service failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif
