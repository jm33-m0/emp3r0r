#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


DWORD create_service(const char* Hostname, const char* cpServiceName, const char * displayname, const char * binpath, const char * newdesc, DWORD desclen, DWORD errmode, DWORD startmode, DWORD service_type)
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
		goto create_service_end;
	}
	memcpy(desc.lpDescription, newdesc, desclen);

	// Open the service control manager
	scManager = ADVAPI32$OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
	if (NULL == scManager)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("OpenSCManagerA failed (%lX)\n", dwResult);
		goto create_service_end;
	}

	// Create the service
	scService = ADVAPI32$CreateServiceA(
		scManager,
		cpServiceName,
		displayname,
		SERVICE_ALL_ACCESS,
		service_type,
		startmode,
		errmode,
		binpath,
		"",
		NULL,
		NULL,
		NULL,
		NULL
	);
	if(NULL == scService)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("CreateServiceA failed (%lX)\n", dwResult);
		goto create_service_end;
	}

	// Set the service description
	if(FALSE == ADVAPI32$ChangeServiceConfig2A(scService, SERVICE_CONFIG_DESCRIPTION, (LPVOID)&desc))
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("ChangeServiceConfig2A failed (%lX)\n", dwResult);
		goto create_service_end;
	}

create_service_end:

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
	const char * binpath = NULL;
	const char * newdesc = NULL;
	const char * displayname = NULL;
	DWORD ignoremode = 0;
	DWORD startmode = 0;
	DWORD desclen = 0;
	DWORD service_type = 0;

	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	servicename = BeaconDataExtract(&parser, NULL);
	binpath = BeaconDataExtract(&parser, NULL);
	displayname = BeaconDataExtract(&parser, NULL);
	newdesc = BeaconDataExtract(&parser, (int*)&desclen);
	ignoremode = (DWORD)BeaconDataShort(&parser);
	startmode = (DWORD)BeaconDataShort(&parser);
	service_type = (DWORD)BeaconDataShort(&parser);

	if(!bofstart())
	{
		return;
	}

	internal_printf("create_service:\n");
	internal_printf("  hostname:     %s\n", hostname);
	internal_printf("  servicename:  %s\n", servicename);
	internal_printf("  displayname:  %s\n", displayname);
	internal_printf("  binpath:      %s\n", binpath);
	internal_printf("  newdesc:      %s\n", newdesc);
	internal_printf("  desclen:      %lu\n", desclen);
	internal_printf("  ignoremode:   %lX\n", ignoremode);
	internal_printf("  startmode:    %lX\n", startmode);
	internal_printf("  service_type: %lX\n", service_type);

	dwErrorCode = create_service(hostname, servicename, displayname, binpath, newdesc, desclen, ignoremode, startmode, service_type);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "create_service failed: %lX\n", dwErrorCode);
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
#define TEST_DISPLAY_NAME    "BOF Service Display Name"
#define TEST_BIN_PATH        "C:\\Windows\\System32\\someservice.exe"
#define TEST_DESCRIPTION     "BOF Test Service Description"
int main(int argc, char ** argv)
{
	DWORD  dwErrorCode       = ERROR_SUCCESS;
	LPCSTR lpcszHostName     = TEST_HOSTNAME;
	LPCSTR lpcszServiceName  = TEST_SVC_NAME;
	LPCSTR lpcszDisplayName  = TEST_DISPLAY_NAME;
	LPCSTR lpcszBinPath      = TEST_BIN_PATH;
	LPCSTR lpcszDescription  = TEST_DESCRIPTION;
	DWORD  dwDescriptionLen  = 0;
	DWORD  dwErrorMode       = SERVICE_ERROR_IGNORE;
	DWORD  dwStartMode       = SERVICE_DEMAND_START;
	DWORD  service_type      = SERVICE_WIN32_OWN_PROCESS;
	
	dwDescriptionLen = MSVCRT$strnlen(lpcszDescription, MAX_PATH);
	
	internal_printf("create_service:\n");
	internal_printf("  lpcszHostName:    %s\n", lpcszHostName);
	internal_printf("  lpcszServiceName: %s\n", lpcszServiceName);
	internal_printf("  lpcszDisplayName: %s\n", lpcszDisplayName);
	internal_printf("  lpcszBinPath:     %s\n", lpcszBinPath);
	internal_printf("  lpcszDescription: %s\n", lpcszDescription);
	internal_printf("  dwDescriptionLen: %lu\n", dwDescriptionLen);
	internal_printf("  dwErrorMode:      %lX\n", dwErrorMode);
	internal_printf("  dwStartMode:      %lX\n", dwStartMode);
	internal_printf("  service_type:     %lX\n", service_type);


	dwErrorCode = create_service(
		lpcszHostName, 
		lpcszServiceName, 
		lpcszDisplayName, 
		lpcszBinPath, 
		lpcszDescription, 
		dwDescriptionLen, 
		dwErrorMode, 
		dwStartMode,
		service_type
	);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "create_service failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif
