#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


DWORD StopDependentServices(SC_HANDLE schSCManager, SC_HANDLE schService)
{
    DWORD dwResult = ERROR_SUCCESS;
    DWORD i = 0;
    DWORD dwBytesNeeded = 0;
    DWORD dwCount = 0;
    LPENUM_SERVICE_STATUS   lpDependencies = NULL;
    ENUM_SERVICE_STATUS     ess;
    SC_HANDLE               hDepService = NULL;
    SERVICE_STATUS_PROCESS  ssp;

    DWORD dwStartTime = KERNEL32$GetTickCount();
    DWORD dwTimeout   = 30000; // 30-second time-out

    // Pass a zero-length buffer to get the required buffer size.
    if ( ADVAPI32$EnumDependentServicesA( 
            schService, 
            SERVICE_ACTIVE, 
            lpDependencies, 
            0, 
            &dwBytesNeeded, 
            &dwCount 
            ) 
        ) 
    {
         // No dependent services, so do nothing
         goto StopDependentServices_end;
    } 
    else 
    {
        dwResult = KERNEL32$GetLastError();
        if (ERROR_MORE_DATA != dwResult)
        {
            internal_printf("EnumDependentServicesA failed (%lX)\n", dwResult);
            goto StopDependentServices_end;
        }

        // Allocate a buffer for the dependencies
        lpDependencies = intAlloc(dwBytesNeeded );
        if(NULL == lpDependencies)
        {
            dwResult = ERROR_OUTOFMEMORY;
            internal_printf("intAlloc failed (%lX)\n", dwResult);
            goto StopDependentServices_end;
        }

        // Enumerate the dependencies
        if ( FALSE == ADVAPI32$EnumDependentServicesA( 
                schService, 
                SERVICE_ACTIVE, 
                lpDependencies, 
                dwBytesNeeded, 
                &dwBytesNeeded,
                &dwCount
                ) 
            )
        {
            dwResult = KERNEL32$GetLastError();
            internal_printf("EnumDependentServicesA failed (%lX)\n", dwResult);
            goto StopDependentServices_end;
        }

        // Loop through the dependencies and attempt to stop them
        for ( i = 0; i < dwCount; i++ ) 
        {
            ess = *(lpDependencies + i);

            // Open the current dependent service
            hDepService = ADVAPI32$OpenServiceA( schSCManager, ess.lpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS );
            if (NULL == hDepService)
            {
                dwResult = KERNEL32$GetLastError();
                internal_printf("OpenServiceA failed (%lX)\n", dwResult);
                goto StopDependentServices_end;
            }

            // Send a stop code to the current dependent service
            if (FALSE == ADVAPI32$ControlService( 
                    hDepService, 
                    SERVICE_CONTROL_STOP,
                    (LPSERVICE_STATUS) &ssp 
                    )
                )
            {
                dwResult = KERNEL32$GetLastError();
		        internal_printf("ControlService failed (%lX)\n", dwResult);
		        goto StopDependentServices_end;
            }

            // Wait for the service to stop
            while (SERVICE_STOPPED != ssp.dwCurrentState) 
            {
                KERNEL32$Sleep( ssp.dwWaitHint );
                if ( FALSE == ADVAPI32$QueryServiceStatusEx( 
                        hDepService, 
                        SC_STATUS_PROCESS_INFO,
                        (LPBYTE)&ssp, 
                        sizeof(SERVICE_STATUS_PROCESS),
                        &dwBytesNeeded
                        )
                    )
                {
                    dwResult = KERNEL32$GetLastError();
		            internal_printf("QueryServiceStatusEx failed (%lX)\n", dwResult);
		            goto StopDependentServices_end;
                }

                if ( SERVICE_STOPPED == ssp.dwCurrentState )
                {
                    break;
                }

                if ( KERNEL32$GetTickCount() - dwStartTime > dwTimeout )
                {
                    dwResult = ERROR_DEPENDENT_SERVICES_RUNNING;
		            internal_printf("Timed out waiting for dependent service to stop: %s (%lX)\n", ess.lpServiceName, dwResult);
		            goto StopDependentServices_end;
                }
            } // end while loop waiting for dependent service to stop
            
            if (hDepService)
            {
                ADVAPI32$CloseServiceHandle( hDepService );
                hDepService = NULL;
            }
        } // end for loop through dependent services
    } // end else we have dependent services

StopDependentServices_end:

    if (hDepService)
    {
        ADVAPI32$CloseServiceHandle( hDepService );
        hDepService = NULL;
    }

    if (lpDependencies)
    {
        intFree(lpDependencies );
        lpDependencies = NULL;
    }

    return dwResult;
}

DWORD stop_service(const char* Hostname, const char* cpServiceName)
{
    DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scManager = NULL;
	SC_HANDLE scService = NULL;
   	SERVICE_STATUS_PROCESS ssp;
	DWORD dwBytesNeeded = 0;


	// Open the service control manager
	scManager = ADVAPI32$OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT);
	if (NULL == scManager)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("OpenSCManagerA failed (%lX)\n", dwResult);
		goto stop_service_end;
	}

	// Open the service
	scService = ADVAPI32$OpenServiceA(scManager, cpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
	if (NULL == scService)
	{
		dwResult = KERNEL32$GetLastError();
		internal_printf("OpenServiceA failed (%lX)\n", dwResult);
		goto stop_service_end;
	}

    // Get the service status process struct
    if ( FALSE == ADVAPI32$QueryServiceStatusEx( 
            scService, 
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp, 
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded
            )
        )
    {
        dwResult = KERNEL32$GetLastError();
		internal_printf("QueryServiceStatusEx failed (%lX)\n", dwResult);
		goto stop_service_end;
    }

    // Check the current state of the service
    if ( ssp.dwCurrentState == SERVICE_STOPPED )
    {
        internal_printf("Service is already stopped.\n");
        goto stop_service_end;
    }

    // If a stop is pending, wait for it
    if ( ssp.dwCurrentState == SERVICE_STOP_PENDING ) 
    {
        internal_printf("Service stop pending...\n");
        goto stop_service_end;
    }

    // If the service is running, stop the dependencies  first
	dwResult = StopDependentServices(scManager, scService);
    if (ERROR_SUCCESS != dwResult)
    {
        internal_printf("StopDependentServices failed (%lX)\n", dwResult);
		goto stop_service_end;
    }
    
    // Now we can finally Send a stop code to the service
    if ( FALSE == ADVAPI32$ControlService( 
            scService, 
            SERVICE_CONTROL_STOP, 
            (LPSERVICE_STATUS) &ssp 
            )
        )
    {
        dwResult = KERNEL32$GetLastError();
		internal_printf("ControlService failed (%lX)\n", dwResult);
		goto stop_service_end;
    }


stop_service_end:

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
	
	internal_printf("stop_service:\n");
	internal_printf("  hostname:    %s\n", hostname);
	internal_printf("  servicename: %s\n", servicename);

	dwErrorCode = stop_service(hostname, servicename);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "stop_service failed: %lX\n", dwErrorCode);
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
	
	internal_printf("stop_service:\n");
	internal_printf("  lpcszHostName:    %s\n", lpcszHostName);
	internal_printf("  lpcszServiceName: %s\n", lpcszServiceName);

	dwErrorCode = stop_service(
		lpcszHostName, 
		lpcszServiceName
	);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "stop_service failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif
