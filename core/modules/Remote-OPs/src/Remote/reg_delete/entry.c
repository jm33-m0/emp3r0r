#define _WIN32_WINNT 0x0600  // Required for RegDeleteKeyValueA
#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

#define REG_DELETE_KEY 1
#define REG_DELETE_VALUE 0

DWORD delete_regkey(const char * hostname, HKEY hive, const char * path, const char * key, int delkey)
{
	DWORD dwresult = ERROR_SUCCESS;
	HKEY rootkey = NULL;
	HKEY RemoteKey = NULL;
	HKEY targetkey = NULL;

	if(hostname == NULL)
	{
		dwresult = ADVAPI32$RegOpenKeyExA(hive, NULL, 0, KEY_READ | KEY_SET_VALUE, &rootkey);
		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("RegOpenKeyExA failed (%lX)\n", dwresult); 
			goto delete_regkey_end;
		}
	}
	else
	{
		dwresult = ADVAPI32$RegConnectRegistryA(hostname, hive, &RemoteKey);
		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("RegConnectRegistryA failed (%lX)\n", dwresult); 
			goto delete_regkey_end;
		}

		dwresult = ADVAPI32$RegOpenKeyExA(RemoteKey, NULL, 0, KEY_READ | KEY_SET_VALUE, &rootkey);
		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("RegOpenKeyExA failed (%lX)\n", dwresult); 
			goto delete_regkey_end;
		}
	}

	if(delkey)
	{
		dwresult = ADVAPI32$RegDeleteKeyExA(rootkey, path, 0, 0);
		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("RegDeleteKeyExA failed (%lX)\n", dwresult); 
			goto delete_regkey_end;
		}
	}
	else
	{
		dwresult = ADVAPI32$RegDeleteKeyValueA(rootkey, path, key);
		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("RegDeleteKeyValueA failed (%lX)\n", dwresult); 
			goto delete_regkey_end;
		}
	}
	
delete_regkey_end:
	if(RemoteKey)
	{
		ADVAPI32$RegCloseKey(RemoteKey);
		RemoteKey = NULL;
	}

	if(rootkey)
	{
		ADVAPI32$RegCloseKey(rootkey);
		rootkey = NULL;
	}
	
	if(targetkey)
	{
		ADVAPI32$RegCloseKey(targetkey);
		targetkey = NULL;
	}

	
	return dwresult;
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	//		$args = bof_pack($1, $packstr, $hostname, $hive, $path, $key, $type, $value);
	datap parser = {0};
	const char * hostname = NULL;
	HKEY hive = (HKEY)0x80000000;
	const char * path = NULL;
	const char * key = NULL;
	int t = 0;
	int delkey = 0;

	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	t = BeaconDataInt(&parser);
	#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
	#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
	hive = (HKEY)((DWORD) hive + (DWORD)t);
	#pragma GCC diagnostic pop
	path = BeaconDataExtract(&parser, NULL);
	key = BeaconDataExtract(&parser, NULL);
	delkey = BeaconDataInt(&parser);

	//correct hostname param
	if(*hostname == 0)
	{
		hostname = NULL;
	}
	if(*key == 0)
	{
		key = NULL;
	}

	if(!bofstart())
	{
		return;
	}

	internal_printf("Deleting registry key %s\\%p\\%s\\%s\n", ((hostname == NULL)?"\\\\.":hostname), hive, path, ((delkey == REG_DELETE_VALUE)?key:"*"));

	dwErrorCode = delete_regkey(hostname, hive, path, key, delkey);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "delete_regkey failed: %lX\n", dwErrorCode);
		goto go_end;
	}

	internal_printf("SUCCESS.\n");

go_end:
	printoutput(TRUE);
	
	bofstop();
};
#else
#define TEST_HOSTNAME ""
#define TEST_REG_HIVE HKEY_CURRENT_USER
#define TEST_REG_PATH "Uninstall"
#define TEST_REG_VALUE "BOF_TEST"
#define TEST_REG_TYPE REG_DWORD
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	LPCSTR lpszHostName = TEST_HOSTNAME;
	HKEY hkRootKey = TEST_REG_HIVE;
	LPCSTR lpszRegPathName = TEST_REG_PATH;
	LPCSTR lpszRegValueName = TEST_REG_VALUE;
	DWORD dwType = TEST_REG_TYPE;
	DWORD dwRegData = 1;
	DWORD dwRegDataLength = sizeof(DWORD);
	int nDeleteKey = REG_DELETE_VALUE;

	//correct hostname param
	if(*lpszHostName == 0)
	{
		lpszHostName = NULL;
	}
	if(*lpszRegValueName == 0)
	{
		lpszRegValueName = NULL;
	}

	internal_printf("Deleting registry key %s\\%p\\%s\\%s\n", ((lpszHostName == NULL)?"\\\\.":lpszHostName), hkRootKey, lpszRegPathName, ((nDeleteKey == REG_DELETE_VALUE)?lpszRegValueName:"*"));

	dwErrorCode = delete_regkey(lpszHostName, hkRootKey, lpszRegPathName, lpszRegValueName, nDeleteKey);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "delete_regkey failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:
	return dwErrorCode;
}
#endif
