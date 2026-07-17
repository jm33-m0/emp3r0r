#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


DWORD set_service_description(const char* Hostname, const char* cpServiceName, const char * newdesc, DWORD desclen)
{
	DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scManager = NULL;
	SC_HANDLE scService = NULL;
	SERVICE_DESCRIPTIONA desc = {0};

	// Create the service description
	desc.lpDescription = intAlloc(desclen+1);
	if(NULL == desc.lpDescription)
	{
		dwResult = ERROR_OUTOFMEMORY;
		internal_printf("intAlloc failed (%lX)\n", dwResult);
		goto set_service_description_end;
	}
	memcpy(desc.lpDescription, newdesc, desclen);

	// Open the service control manager
	scManager = ADVAPI32$OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT);
	if (NULL == scManager)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("OpenSCManagerA failed (%lX)\n", dwResult);
		goto set_service_description_end;
	}

	// Open the service
	scService = ADVAPI32$OpenServiceA(scManager, cpServiceName, SERVICE_CHANGE_CONFIG);
	if (NULL == scService)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("OpenServiceA failed (%lX)\n", dwResult);
		goto set_service_description_end;
	}


	// Set the service description
	if(FALSE == ADVAPI32$ChangeServiceConfig2A(scService, SERVICE_CONFIG_DESCRIPTION, (LPVOID)&desc))
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("ChangeServiceConfig2A failed (%lX)\n", dwResult);
		goto set_service_description_end;
	}

set_service_description_end:

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
	
	if(desc.lpDescription != NULL)
	{
		intFree(desc.lpDescription);
		desc.lpDescription = NULL;
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
	const char * newdesc = NULL;
	DWORD desclen = 0;

	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	servicename = BeaconDataExtract(&parser, NULL);
	newdesc = BeaconDataExtract(&parser, (int *)&desclen);

	if(!bofstart())
	{
		return;
	}

	internal_printf("set_service_description:\n");
	internal_printf("  hostname:    %s\n", hostname);
	internal_printf("  servicename: %s\n", servicename);
	internal_printf("  newdesc:     %s\n", newdesc);
	internal_printf("  desclen:     %lu\n", desclen);

	dwErrorCode = set_service_description(hostname, servicename, newdesc, desclen);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "set_service_description failed: %lX\n", dwErrorCode);
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
#define TEST_DESCRIPTION     "Alternate BOF Test Service Description"
int main(int argc, char ** argv)
{
	DWORD  dwErrorCode       = ERROR_SUCCESS;
	LPCSTR lpcszHostName     = TEST_HOSTNAME;
	LPCSTR lpcszServiceName  = TEST_SVC_NAME;
	LPCSTR lpcszDescription  = TEST_DESCRIPTION;
	DWORD  dwDescriptionLen  = 0;
	
	dwDescriptionLen = MSVCRT$strnlen(lpcszDescription, MAX_PATH);
	
	internal_printf("set_service_description:\n");
	internal_printf("  lpcszHostName:    %s\n", lpcszHostName);
	internal_printf("  lpcszServiceName: %s\n", lpcszServiceName);
	internal_printf("  lpcszDescription: %s\n", lpcszDescription);
	internal_printf("  dwDescriptionLen: %lu\n", dwDescriptionLen);

	dwErrorCode = set_service_description(
		lpcszHostName, 
		lpcszServiceName, 
		lpcszDescription, 
		dwDescriptionLen
	);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "set_service_description failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif
