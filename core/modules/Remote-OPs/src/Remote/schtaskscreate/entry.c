#define _WIN32_DCOM
#include <windows.h>
#include <taskschd.h>
#include <sddl.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

#define SCHTASKS_USER 0
#define SCHTASKS_SYSTEM 1
#define SCHTASKS_XML_PRINCIPAL 2
#define SCHTASKS_PASSWORD 3

#define USER_SYSTEM_STRING L"nt authority\\SYSTEM"

// domain\username from lookupsid
// the returned string MUST be freed using LocalFree
DWORD getUserDefaultSDDL(wchar_t **lpswzUserName, wchar_t **lpswzSDString)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	HANDLE Token = NULL;
	SECURITY_DESCRIPTOR Sd = {0};
	PTOKEN_USER puser = NULL;
	DWORD RequiredSize = 0;
	DWORD UserSize = 0;
	wchar_t username[257] = {0};
	DWORD usernameSize = 257;
	wchar_t domainname[256] = {0};
	DWORD domainSize = 256;
	SID_NAME_USE junk = {0};
	TOKEN_DEFAULT_DACL* DefaultDacl = NULL;

	if (FALSE == ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &Token))
	{
		dwErrorCode = KERNEL32$GetLastError();
		internal_printf("OpenProcessToken failed (%lX)\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}
	
	// These will fail, but will give us the required size
	ADVAPI32$GetTokenInformation(Token, TokenDefaultDacl, NULL, 0, &RequiredSize);
	ADVAPI32$GetTokenInformation(Token, TokenUser, NULL, 0, &UserSize);

	// Allocate buffers of required size
	DefaultDacl = (TOKEN_DEFAULT_DACL *)intAlloc(RequiredSize);
	puser = (TOKEN_USER *)intAlloc(UserSize);
	if ((NULL == DefaultDacl)||(NULL == puser))
	{
		dwErrorCode = ERROR_OUTOFMEMORY;
		internal_printf("intAlloc failed (%lX)\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}

	// Actually try to get the TokenDefaultDacl token information
	if (FALSE == ADVAPI32$GetTokenInformation(Token, TokenDefaultDacl, DefaultDacl, RequiredSize, &RequiredSize))
	{
		dwErrorCode = KERNEL32$GetLastError();
		internal_printf("GetTokenInformation(TokenDefaultDacl) failed (%lX)\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}

	// Actually try to get the TokenUser token information
	if (FALSE == ADVAPI32$GetTokenInformation(Token, TokenUser, puser, UserSize, &UserSize))
	{
		dwErrorCode = KERNEL32$GetLastError();
		internal_printf("GetTokenInformation(TokenUser) failed (%lX)\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}

	// Initialize a security descriptor
	if (FALSE == ADVAPI32$InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION))
	{
		dwErrorCode = KERNEL32$GetLastError();
		internal_printf("InitializeSecurityDescriptor failed (%lX)\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}

	// Set the security descriptor DACL to match the DefaultDacl
	if (FALSE == ADVAPI32$SetSecurityDescriptorDacl(&Sd, TRUE, DefaultDacl->DefaultDacl, FALSE))
	{
		dwErrorCode = KERNEL32$GetLastError();
		internal_printf("SetSecurityDescriptorDacl failed (%lX)\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}

	// Get the string representation of the security descriptor
	if (FALSE == ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorW(&Sd,SDDL_REVISION_1, DACL_SECURITY_INFORMATION, lpswzSDString, NULL))
	{
		dwErrorCode = KERNEL32$GetLastError();
		internal_printf("SetSecurityDescriptorDacl failed (%lX)\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}

	// Get the username for the TokenUser
	if(FALSE == ADVAPI32$LookupAccountSidW(NULL, puser->User.Sid, username, &usernameSize, domainname, &domainSize, &junk))
	{
		dwErrorCode = KERNEL32$GetLastError();
		internal_printf("LookupAccountSidW failed (%lX)\n", dwErrorCode);
		
		goto getUserDefaultSDDL_end;
	}

	*lpswzUserName = intAlloc((usernameSize + domainSize) * 2 + 4);
	if (NULL == (*lpswzUserName))
	{
		dwErrorCode = ERROR_OUTOFMEMORY;
		internal_printf("intAlloc failed (%lX)\n", dwErrorCode);
		goto getUserDefaultSDDL_end;
	}

	MSVCRT$wcsncat(*lpswzUserName, domainname, domainSize+1);
	(*lpswzUserName)[domainSize] = L'\\';
	//MSVCRT$wcsncat(*lpswzUserName, L"\\", domainSize+2);
	MSVCRT$wcsncat(*lpswzUserName, username, usernameSize+domainSize+2);

getUserDefaultSDDL_end:

	if (ERROR_SUCCESS != dwErrorCode)
	{
		if (*lpswzSDString)
		{
			KERNEL32$LocalFree(*lpswzSDString);
			*lpswzSDString = NULL;
		}
		
		if (*lpswzUserName)
		{
			intFree(*lpswzUserName);
			*lpswzUserName = NULL;
		}
	}

	if(puser)
	{
		intFree(puser);
		puser = NULL;
	}

	if(DefaultDacl)
	{
		intFree(DefaultDacl);
		DefaultDacl = NULL;
	}

	if (Token)
	{
		KERNEL32$CloseHandle(Token);
		Token = NULL;
	}

	return dwErrorCode;
}

DWORD createTask(const wchar_t * server, wchar_t * taskpath, const wchar_t* xmldef, int mode, BOOL force, const wchar_t* UserName, const wchar_t* UserPassword)
{
	HRESULT hr = S_OK;
	VARIANT Vserver;
	VARIANT VNull;
	VARIANT Vsddl;
	VARIANT Vthisuser;
	VARIANT VUserPassword;
	wchar_t *defaultSDDL = NULL;
	ITaskFolder *pCurFolder = NULL;
	ITaskFolder *pRootFolder = NULL;
	ITaskDefinition *pTaskDef = NULL;
	IRegisteredTask* pRegisteredTask = NULL;
	BSTR rootpath = NULL;
	BSTR BSTRtaskpath = NULL;
	BSTR BSTRtaskname = NULL;
	BSTR BSTRtaskxml = NULL;
	BSTR BSTRthisuser = NULL;
	BSTR BSTRsystem = NULL;
	BSTR BSTRUserPassword = NULL;
	BSTR BSTRUserName = NULL;
	wchar_t * taskname = NULL;
	wchar_t * taskpathpart = NULL;
	BOOL mustcreate = FALSE;
	TASK_STATE tstate = 0;
	TASK_LOGON_TYPE taskType = 0;	//(mode) ? TASK_LOGON_SERVICE_ACCOUNT : TASK_LOGON_INTERACTIVE_TOKEN;
	wchar_t * thisuser = NULL;
	VARIANT_BOOL isEnabled = 0;
	DATE taskdate = 0;
	IID CTaskScheduler = {0x0f87369f,0xa4e5,0x4cfc,{0xbd,0x3e,0x73,0xe6,0x15,0x45,0x72,0xdd}};
	IID IIDTaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
	ITaskService *pService = NULL;
	// Initialize variants
	OLEAUT32$VariantInit(&Vserver);
	OLEAUT32$VariantInit(&VNull);
	OLEAUT32$VariantInit(&Vsddl);
	OLEAUT32$VariantInit(&Vthisuser);
	OLEAUT32$VariantInit(&VUserPassword); // we don't clear this because we free both possible OLE strings

	// Initialize COM
	hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
	{
		internal_printf("Failed to initialize COM (%lX)\n", hr);
		goto createTask_end;
	}

	// Create System user string
	BSTRsystem = OLEAUT32$SysAllocString(USER_SYSTEM_STRING);
	if (NULL == BSTRsystem)
	{
		hr = ERROR_OUTOFMEMORY;
		internal_printf("SysAllocString failed (%lX)\n", hr);
		goto createTask_end;
	}


		
	// Get an instance of the task scheduler
    hr = OLE32$CoCreateInstance( &CTaskScheduler,
                           NULL,
                           CLSCTX_INPROC_SERVER,
                           &IIDTaskService,
                           (void**)&pService ); 
	if(FAILED(hr))
	{
		internal_printf("Failed to create Task Scheduler instance (%lX)", hr);
		goto createTask_end;
	}

	// Set up our variant for the server name if we need to
	Vserver.vt = VT_BSTR;
	Vserver.bstrVal = OLEAUT32$SysAllocString(server);
	if (NULL == Vserver.bstrVal)
	{
		hr = ERROR_OUTOFMEMORY;
		internal_printf("SysAllocString failed (%lX)\n", hr);
		goto createTask_end;
	}

	// Connect to the server
	// HRESULT Connect( VARIANT serverName, VARIANT user, VARIANT domain, VARIANT password );
	//internal_printf("Connecting to \"%S\"\n", Vserver.bstrVal);
	hr = pService->lpVtbl->Connect(pService, Vserver, VNull, VNull, VNull);
	if(FAILED(hr))
	{
		internal_printf("Failed to connect to the requested server (%lX)\n", hr);
		goto createTask_end;
	}

	// Now we need to get the root folder 
	rootpath = OLEAUT32$SysAllocString(L"\\");
	if (NULL == rootpath)
	{
		hr = ERROR_OUTOFMEMORY;
		internal_printf("SysAllocString failed (%lX)\n", hr);
		goto createTask_end;
	}
	hr = pService->lpVtbl->GetFolder(pService, rootpath, &pRootFolder);
    if( FAILED(hr) )
    {
        internal_printf("Failed to get the root folder (%lX)\n", hr );
		goto createTask_end;
    }

	// Get the user name and security descriptor
	hr = (HRESULT)getUserDefaultSDDL(&thisuser, &defaultSDDL);
	if(ERROR_SUCCESS != hr)
	{
		internal_printf("Failed to get the current user and default security descriptor (%lX)\n", hr);
		goto createTask_end;
	}

	internal_printf("Got user name and security descriptor\n");
	//internal_printf("thisuser:     %S\n", thisuser);
	//internal_printf("defaultSDDL:  %S\n", defaultSDDL);

	Vsddl.vt = VT_BSTR;
	Vsddl.bstrVal = OLEAUT32$SysAllocString(defaultSDDL);
	if (NULL == Vsddl.bstrVal)
	{
		hr = ERROR_OUTOFMEMORY;
		internal_printf("SysAllocString failed (%lX)\n", hr);
		goto createTask_end;
	}

	
	BSTRthisuser = OLEAUT32$SysAllocString(thisuser);
	if (NULL == BSTRthisuser)
	{
		hr = ERROR_OUTOFMEMORY;
		internal_printf("SysAllocString failed (%lX)\n", hr);
		goto createTask_end;
	}
	
	// Use the task XML passed in
	BSTRtaskxml = OLEAUT32$SysAllocString(xmldef);
	if (NULL == BSTRtaskxml)
	{
		hr = ERROR_OUTOFMEMORY;
		internal_printf("SysAllocString failed (%lX)\n", hr);
		goto createTask_end;
	}
	//internal_printf("BSTRtaskxml:\n%S\n", BSTRtaskxml);

	// Define username and password for password task creation.
	BSTRUserName = OLEAUT32$SysAllocString(UserName);
	if (NULL == BSTRUserName)
	{
		hr = ERROR_OUTOFMEMORY;
		internal_printf("SysAllocString failed (%lX)\n", hr);
		goto createTask_end;
	}
	BSTRUserPassword = OLEAUT32$SysAllocString(UserPassword);
	if (NULL == BSTRUserPassword)
	{
		hr = ERROR_OUTOFMEMORY;
		internal_printf("SysAllocString failed (%lX)\n", hr);
		goto createTask_end;
	}



	// internal_printf("BSTRtaskxml:\n%S\n", BSTRtaskxml);

	// Validate the task only
	hr = pRootFolder->lpVtbl->RegisterTask(pRootFolder, NULL, BSTRtaskxml, TASK_VALIDATE_ONLY, VNull, VNull, 0, VNull, &pRegisteredTask);
	if(FAILED(hr))
	{
		internal_printf("Failed to validate the task XML (%lX)\n", hr);
		goto createTask_end;
	}

	internal_printf("Valitdated task\n");

	// Release the validation instance
	if(pRegisteredTask)
	{
		pRegisteredTask->lpVtbl->Release(pRegisteredTask);
		pRegisteredTask = NULL;
	}

	// Now we need to recursivly get or create the task path
	taskname = MSVCRT$wcsrchr(taskpath, L'\\');
	if (taskname == NULL)
	{
		hr = ERROR_BAD_PATHNAME;
		internal_printf("Failed to locate \\ in your task path (%lX)\n", hr);
		goto createTask_end;
	}

	taskname[0] = L'\0'; // null terminate our path to this point
	taskname += 1; // move past null
	BSTRtaskname = OLEAUT32$SysAllocString(taskname);
	if (NULL == BSTRtaskname)
	{
		hr = ERROR_OUTOFMEMORY;
		internal_printf("SysAllocString failed (%lX)\n", hr);
		goto createTask_end;
	}
	//internal_printf("BSTRtaskname: %S", BSTRtaskname);

	// Loop through the full path name
	for(taskpathpart = MSVCRT$wcstok(taskpath, L"\\"); taskpathpart != NULL; taskpathpart = MSVCRT$wcstok(NULL, L"\\"))
	{
		if(mustcreate == FALSE)
		{
			BSTRtaskpath = OLEAUT32$SysAllocString(taskpathpart);
			if (NULL == BSTRtaskpath)
			{
				hr = ERROR_OUTOFMEMORY;
				internal_printf("SysAllocString failed (%lX)\n", hr);
				goto createTask_end;
			}

			hr = pRootFolder->lpVtbl->GetFolder(pRootFolder, BSTRtaskpath, &pCurFolder);
			if(FAILED(hr))
			{
				mustcreate = TRUE;
			} 
		}
		// Intentionally not an else, we want to start creating as soon as we fail
		if(mustcreate == TRUE)
		{
			if(!BSTRtaskpath) // if this isn't null we just tried to get it, otherwise we need to aloc it for this token
			{
				BSTRtaskpath = OLEAUT32$SysAllocString(taskpathpart);
				if (NULL == BSTRtaskpath)
				{
					hr = ERROR_OUTOFMEMORY;
					internal_printf("SysAllocString failed (%lX)\n", hr);
					goto createTask_end;
				}
			}

			hr = pRootFolder->lpVtbl->CreateFolder(pRootFolder, BSTRtaskpath, Vsddl, &pCurFolder);
			if(FAILED(hr))
			{
				BSTR errorpath = NULL;
				pRootFolder->lpVtbl->get_Path(pRootFolder, &errorpath);
				internal_printf("Failed to create task folder %S\\%S (%lX)\n", errorpath, BSTRtaskpath, hr);
				OLEAUT32$SysFreeString(errorpath);
				goto createTask_end;
			}
			else
			{
				BSTR successpath = NULL;
				pRootFolder->lpVtbl->get_Path(pRootFolder, &successpath);
				internal_printf("Created task folder %S\\%S\n", successpath, BSTRtaskpath);
				OLEAUT32$SysFreeString(successpath);
			}
		} // end we mustcreate a folder

		pRootFolder->lpVtbl->Release(pRootFolder);
		pRootFolder = pCurFolder;
		if(BSTRtaskpath)
		{
			OLEAUT32$SysFreeString(BSTRtaskpath);
			BSTRtaskpath = NULL;
		}
	} // end for loop creating task path

	internal_printf("Created task path\n");

	// Set the task type and task user
	if(mode == SCHTASKS_USER)
	{
		Vthisuser.vt = VT_BSTR;
		Vthisuser.bstrVal = BSTRthisuser;
		taskType = TASK_LOGON_INTERACTIVE_TOKEN;
	}
	else if (mode == SCHTASKS_SYSTEM)
	{
		Vthisuser.vt = VT_BSTR;
		Vthisuser.bstrVal = BSTRsystem;
		taskType = TASK_LOGON_SERVICE_ACCOUNT;
	}
	else if (mode == SCHTASKS_XML_PRINCIPAL)
	{
		taskType = TASK_LOGON_NONE;
	}
	else if (mode == SCHTASKS_PASSWORD)
	{
		taskType = TASK_LOGON_PASSWORD;
		Vthisuser.vt = VT_BSTR;
		Vthisuser.bstrVal = BSTRUserName;
		VUserPassword.vt = VT_BSTR;
		VUserPassword.bstrVal = BSTRUserPassword;
	}
	else
	{
		hr = ERROR_BAD_ARGUMENTS;
		internal_printf("Invalid mode: %d (%lX)\n", mode, hr);
		goto createTask_end;
	}

	// Are we forcing the update/create or just trying to create?
	if (force)
	{
		hr = pRootFolder->lpVtbl->RegisterTask(pRootFolder, BSTRtaskname, BSTRtaskxml, TASK_CREATE_OR_UPDATE, Vthisuser, VUserPassword, taskType, Vsddl, &pRegisteredTask);
		if(FAILED(hr))
		{
			internal_printf("Failed to register task (%lX)\n", hr);
			goto createTask_end;
		}
}
	else // else create only
	{ 
		// First check to see if the task already exits
		hr = pRootFolder->lpVtbl->GetTask(pRootFolder, BSTRtaskname, &pRegisteredTask);
		if(SUCCEEDED(hr))
		{
			hr = ERROR_ALREADY_EXISTS;
			internal_printf("Task already exists (%lX)\n", hr);
			goto createTask_end;
		}

		// The task does not exist, so we can continue

		hr = pRootFolder->lpVtbl->RegisterTask(pRootFolder, BSTRtaskname, BSTRtaskxml, TASK_CREATE, Vthisuser, VUserPassword, taskType, Vsddl, &pRegisteredTask);
		if(FAILED(hr))
			{
				internal_printf("Failed to register task (%lX)\n", hr);
				goto createTask_end;
			}
	}
	
	internal_printf("Registered task\n");


createTask_end:
	if(BSTRthisuser)
	{
		OLEAUT32$SysFreeString(BSTRthisuser);
		BSTRthisuser = NULL;
	}

	if(BSTRsystem)
	{
		OLEAUT32$SysFreeString(BSTRsystem);
		BSTRsystem = NULL;
	}

	if(pRegisteredTask)
	{
		pRegisteredTask->lpVtbl->Release(pRegisteredTask);
		pRegisteredTask = NULL;
	}

	if(BSTRtaskxml)
	{
		OLEAUT32$SysFreeString(BSTRtaskxml);
		BSTRtaskxml = NULL;
	}

	if(BSTRtaskname)
	{
		OLEAUT32$SysFreeString(BSTRtaskname);
		BSTRtaskname = NULL;
	}

	if(BSTRUserPassword)
	{
		OLEAUT32$SysFreeString(BSTRUserPassword);
		BSTRUserPassword = NULL;
	}

	if(BSTRUserName)
	{
		OLEAUT32$SysFreeString(BSTRUserName);
		BSTRUserName = NULL;
	}

	if(thisuser)
	{
		intFree(thisuser);
		thisuser = NULL;
	}

	if(defaultSDDL)
	{
		KERNEL32$LocalFree(defaultSDDL);
		defaultSDDL = NULL;
	}

	if(pRootFolder && pRootFolder != pCurFolder) // does this == current, if so we probably don't want to free them both
	{
		pRootFolder->lpVtbl->Release(pRootFolder);
		pRootFolder = NULL;
	}

	if(pCurFolder)
	{
		pCurFolder->lpVtbl->Release(pCurFolder);
		pCurFolder = NULL;
	}

	if(BSTRtaskpath)
	{
		OLEAUT32$SysFreeString(BSTRtaskpath);
		BSTRtaskpath = NULL;
	}

	if(pService)
	{
		pService->lpVtbl->Release(pService);
		pService = NULL;
	}

	if(rootpath)
	{
		OLEAUT32$SysFreeString(rootpath);
		rootpath = NULL;
	}

	OLEAUT32$VariantClear(&Vsddl);
	OLEAUT32$VariantClear(&Vserver);
	//OLEAUT32$VariantClear(&VUserPassword); backing string is freed above if used
	//OLEAUT32$VariantInit(&Vthisuser); // we don't clear this because we free both possible OLE strings
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
	wchar_t * taskpath = NULL;
	wchar_t * username = NULL;
	wchar_t * password = NULL;
	const wchar_t * xml = NULL;
	int mode = 0;
	BOOL force = 0;

	BeaconDataParse(&parser, Buffer, Length);
	hostname = (const wchar_t *)BeaconDataExtract(&parser, NULL);
	username = (wchar_t *)BeaconDataExtract(&parser, NULL);
	password = (wchar_t *)BeaconDataExtract(&parser, NULL);
	taskpath = (wchar_t *)BeaconDataExtract(&parser, NULL);
	xml = (const wchar_t *)BeaconDataExtract(&parser, NULL);
	mode = BeaconDataInt(&parser);
	force = BeaconDataInt(&parser);

	if(!bofstart())
	{
		return;
	}
	
	internal_printf("createTask hostname:%S username: %S password:%S taskpath:%S mode:%d force:%d\n", 
		hostname, username, password, taskpath, mode, force);

	dwErrorCode = createTask(hostname, taskpath, xml, mode, force, username, password);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "createTask failed: %lX\n", dwErrorCode);
		goto go_end;
	}

	internal_printf("SUCCESS.\n");

go_end:
	printoutput(TRUE);
	
	bofstop();
};
#else
#define TEST_HOSTNAME         L""
#define TEST_USERNAME         L""
#define TEST_PASSWORD         L""
#define TEST_TASK_PATH        L"\\BOF_FOLDER\\BOF_TASK"
#define TEST_TASK_XML_NOTEPAD L"\
<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n\
  <Triggers>\n\
    <LogonTrigger>\n\
      <Enabled>true</Enabled>\n\
      <UserId>TESTING\\Administrator</UserId>\n\
    </LogonTrigger>\n\
  </Triggers>\n\
  <Principals>\n\
    <Principal>\n\
      <UserId>TESTING\\Administrator</UserId>\n\
    </Principal>\n\
  </Principals>\n\
  <Settings>\n\
    <AllowStartOnDemand>true</AllowStartOnDemand>\n\
    <Enabled>true</Enabled>\n\
  </Settings>\n\
  <Actions>\n\
    <Exec>\n\
      <Command>notepad.exe</Command>\n\
    </Exec>\n\
  </Actions>\n\
</Task>\n\
"
#define TEST_TASK_XML_CALC   L"\
<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n\
  <Triggers>\n\
    <LogonTrigger>\n\
      <Enabled>true</Enabled>\n\
      <UserId>TESTING\\Administrator</UserId>\n\
    </LogonTrigger>\n\
  </Triggers>\n\
  <Principals>\n\
    <Principal>\n\
      <UserId>TESTING\\Administrator</UserId>\n\
    </Principal>\n\
  </Principals>\n\
  <Settings>\n\
    <AllowStartOnDemand>true</AllowStartOnDemand>\n\
    <Enabled>true</Enabled>\n\
  </Settings>\n\
  <Actions>\n\
    <Exec>\n\
      <Command>calc.exe</Command>\n\
    </Exec>\n\
  </Actions>\n\
</Task>\n\
"
int main(int argc, char ** argv)
{
	DWORD   dwErrorCode             = ERROR_SUCCESS;
	LPCWSTR lpcswzHostName          = TEST_HOSTNAME;
	WCHAR   lpswzTaskPath[MAX_PATH];
	LPCWSTR lpusername				= TEST_USERNAME;
	LPCWSTR lppassword				= TEST_PASSWORD;
	LPCWSTR lpcswzTaskXMLCalc       = TEST_TASK_XML_CALC;
	LPCWSTR lpcswzTaskXMLNotepad    = TEST_TASK_XML_NOTEPAD;
	INT     nMode                   = SCHTASKS_XML_PRINCIPAL;
	BOOL    bForce                  = FALSE;
	
	MSVCRT$wcscpy(lpswzTaskPath,TEST_TASK_PATH);

	internal_printf("lpcswzTaskXMLCalc:  %S\n", lpcswzTaskXMLCalc);

	internal_printf("createTask hostname:%S taskpath:%S mode:%d force:%d\n", 
		lpcswzHostName, lpswzTaskPath, nMode, bForce);
	
	dwErrorCode = createTask(lpcswzHostName, lpswzTaskPath, lpcswzTaskXMLCalc, nMode, bForce, lpusername, lppassword);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "createTask failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	bForce = TRUE;
	MSVCRT$wcscpy(lpswzTaskPath,TEST_TASK_PATH);

	internal_printf("lpcswzTaskXMLNotepad:  %S\n", lpcswzTaskXMLNotepad);

	internal_printf("createTask hostname:%S taskpath:%S mode:%d force:%d\n", 
		lpcswzHostName, lpswzTaskPath, nMode, bForce);

	dwErrorCode = createTask(lpcswzHostName, lpswzTaskPath, lpcswzTaskXMLNotepad, nMode, bForce, lpusername, lppassword);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "createTask failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:
	return dwErrorCode;
}
#endif
