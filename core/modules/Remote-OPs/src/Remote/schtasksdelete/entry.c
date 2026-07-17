#define _WIN32_DCOM
#include <windows.h>
#include <taskschd.h>
#include <sddl.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
//#include "queue.c"
//#include "anticrash.c"


#define TYPE_TASK_FOLDER 1
#define TYPE_TASK        0

DWORD deleteTask(const wchar_t * server, const wchar_t * taskname, BOOL isfolder)
{
	HRESULT hr = S_OK;
	VARIANT Vserver;
	VARIANT VNull;
	ITaskFolder *pRootFolder = NULL;
	IRegisteredTask* pRegisteredTask = NULL;	
	BSTR rootpath = NULL;
	BSTR taskpath = NULL;
	IID CTaskScheduler = {0x0f87369f,0xa4e5,0x4cfc,{0xbd,0x3e,0x73,0xe6,0x15,0x45,0x72,0xdd}};
	IID IIDTaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
	ITaskService *pService = NULL;
		// Initialize variants
	OLEAUT32$VariantInit(&Vserver);
	OLEAUT32$VariantInit(&VNull);

	// Initialize COM
	hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
	{
		internal_printf("Could not initialize com (%lX)\n", hr);
		goto deleteTask_end;
	}



	// Get an instance of the task scheduler
    hr = OLE32$CoCreateInstance( &CTaskScheduler,
                           NULL,
                           CLSCTX_INPROC_SERVER,
                           &IIDTaskService,
                           (void**)&pService ); 
	if(FAILED(hr))
	{
		internal_printf("Failed to create Task Scheduler interface (%lX)\n", hr);
		goto deleteTask_end;
	}

	// Set up our variant for the server name if we need to
	Vserver.vt = VT_BSTR;
	Vserver.bstrVal = OLEAUT32$SysAllocString(server);
	if (NULL == Vserver.bstrVal)
	{
		hr = ERROR_OUTOFMEMORY;
		internal_printf("SysAllocString failed (%lX)\n", hr);
		goto deleteTask_end;
	}

	// Connect to the server
	// HRESULT Connect( VARIANT serverName, VARIANT user, VARIANT domain, VARIANT password );
	//internal_printf("Connecting to \"%S\"\n", Vserver.bstrVal);
	hr = pService->lpVtbl->Connect(pService, Vserver, VNull, VNull, VNull);
	if(FAILED(hr))
	{
		internal_printf("Failed to connect to requested target (%lX)\n", hr);
		goto deleteTask_end;
	}

	// Now we need to get the root folder 
	rootpath = OLEAUT32$SysAllocString(L"\\");
	if (NULL == rootpath)
	{
		hr = ERROR_OUTOFMEMORY;
		internal_printf("SysAllocString failed (%lX)\n", hr);
		goto deleteTask_end;
	}
	hr = pService->lpVtbl->GetFolder(pService, rootpath, &pRootFolder);
    if( FAILED(hr) )
    {
        internal_printf("Failed to get the root folder (%lX)\n", hr);
		goto deleteTask_end;
    }

	// Get the task name or current folder name
	taskpath = OLEAUT32$SysAllocString(taskname);
	if (NULL == taskpath)
	{
		hr = ERROR_OUTOFMEMORY;
		internal_printf("SysAllocString failed (%lX)\n", hr);
		goto deleteTask_end;
	}

	// Check if we are deleting a folder or the task itself
	if(isfolder)
	{
		// Delete the folder
		hr = pRootFolder->lpVtbl->DeleteFolder(pRootFolder, taskpath, 0);
		if(FAILED(hr))
		{
			internal_printf("Failed to delete the requested task folder %S (%lX)\n", taskpath, hr);
			goto deleteTask_end;		
		} 

		internal_printf("Deleted the task folder: %S\n", taskpath);
	}
	else // else deleting task itself
	{
		// Get our reference to the task
		hr = pRootFolder->lpVtbl->GetTask(pRootFolder, taskpath, &pRegisteredTask);
		if(FAILED(hr))
		{
			internal_printf("Failed to find the task: %S (%lX)\n", taskpath, hr);
			internal_printf("NOTE: When using delete, you must give the full path and name of the task\n");
			goto deleteTask_end;
		}

		// Stop the task if it is running
		hr = pRegisteredTask->lpVtbl->Stop(pRegisteredTask, 0);
		if(FAILED(hr))
		{
			internal_printf("Failed to stop the task: %S (%lX)\n", taskpath, hr);
			goto deleteTask_end;
		}

		// Release our reference to the task
		pRegisteredTask->lpVtbl->Release(pRegisteredTask);
		pRegisteredTask = NULL;

		// Delete the task
		hr = pRootFolder->lpVtbl->DeleteTask(pRootFolder, taskpath, 0);
		if(FAILED(hr))
		{
			internal_printf("Failed to delete the task: %S (%lX)\n", taskpath, hr);
			goto deleteTask_end;
		}
		internal_printf("Deleted the task: %S\n", taskpath);
	}

deleteTask_end:
	if(taskpath)
	{
		OLEAUT32$SysFreeString(taskpath);
		taskpath = NULL;
	}

	if(rootpath)
	{
		OLEAUT32$SysFreeString(rootpath);
		rootpath = NULL;
	}

	if(pRootFolder)
	{
		pRootFolder->lpVtbl->Release(pRootFolder);
		pRootFolder = NULL;
	}

	if(pRegisteredTask)
	{
		pRegisteredTask->lpVtbl->Release(pRegisteredTask);
		pRegisteredTask = NULL;
	}

	if(pService)
	{
		pService->lpVtbl->Release(pService);
		pService = NULL;
	}

	OLEAUT32$VariantClear(&Vserver);
	
	OLE32$CoUninitialize();

	return (DWORD)hr;
}


#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	datap parser;
	const wchar_t * hostname = NULL;
	const wchar_t * taskname = NULL;
	int isfolder = 0;

	BeaconDataParse(&parser, Buffer, Length);
	hostname = (const wchar_t *)BeaconDataExtract(&parser, NULL);
	taskname = (const wchar_t *)BeaconDataExtract(&parser, NULL);
	isfolder = BeaconDataInt(&parser);

	if(!bofstart())
	{
		return;
	}

	internal_printf("deleteTask hostname:%S taskname:%S isfolder:%d\n", 
		hostname, taskname, isfolder);

	dwErrorCode = deleteTask(hostname, taskname, isfolder);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "deleteTask failed: %lX\n", dwErrorCode);
		goto go_end;
	}

	internal_printf("SUCCESS.\n");

go_end:
	printoutput(TRUE);
	
	bofstop();
};
#else
#define TEST_HOSTNAME    L""
#define TEST_TASK_NAME   L"\\BOF_FOLDER\\BOF_TASK"
#define TEST_TASK_FOLDER L"\\BOF_FOLDER"
int main(int argc, char ** argv)
{
	DWORD   dwErrorCode      = ERROR_SUCCESS;
	LPCWSTR lpcswzHostName   = TEST_HOSTNAME;
	LPCWSTR lpcswzTaskName   = TEST_TASK_NAME;
	LPCWSTR lpcswzTaskFolder = TEST_TASK_FOLDER;
	INT     nDeleteType      = TYPE_TASK;
	
	internal_printf("deleteTask lpcswzHostName:%S lpcswzTaskName:%S nDeleteType:%d\n", 
		lpcswzHostName, lpcswzTaskName, nDeleteType);

	dwErrorCode = deleteTask(lpcswzHostName, lpcswzTaskName, nDeleteType);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "deleteTask failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	nDeleteType  = TYPE_TASK_FOLDER;

	internal_printf("deleteTask lpcswzHostName:%S lpcswzTaskFolder:%S nDeleteType:%d\n", 
		lpcswzHostName, lpcswzTaskFolder, nDeleteType);

	dwErrorCode = deleteTask(lpcswzHostName, lpcswzTaskFolder, nDeleteType);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "deleteTask failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:
	return dwErrorCode;
}
#endif
