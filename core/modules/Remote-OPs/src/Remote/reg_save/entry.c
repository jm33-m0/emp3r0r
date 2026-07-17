#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DWORD savereg(HKEY hive, const char * regpath, const char * outfile)
{
	DWORD dwresult = 0;
	HKEY rootkey = NULL;

	dwresult = ADVAPI32$RegOpenKeyExA(hive, regpath, 0, KEY_READ, &rootkey);
	if(ERROR_SUCCESS != dwresult)
	{
		internal_printf("RegOpenKeyExA failed (%lX)\n", dwresult); 
		goto savereg_end;
	}

	dwresult = ADVAPI32$RegSaveKeyExA(rootkey, outfile, NULL, REG_LATEST_FORMAT);
	if(ERROR_SUCCESS != dwresult)
	{
		internal_printf("RegSaveKeyExA failed (%lX)\n", dwresult); 
		goto savereg_end;
	}
	
	internal_printf("Saved reg to path %s\nDon't Forget to delete it after you download it!\n", outfile);

savereg_end:
	if(rootkey){
		ADVAPI32$RegCloseKey(rootkey);
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
	datap parser = {0};
	const char * reg_path = NULL;
	const char * output_file = NULL;
	HKEY hive = (HKEY)0x80000000;
	int t = 0;
	BeaconDataParse(&parser, Buffer, Length);
	reg_path = BeaconDataExtract(&parser, NULL);
	output_file = BeaconDataExtract(&parser, NULL);
	t = BeaconDataInt(&parser);
    #pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
	#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
	hive = (HKEY)((DWORD) hive + (DWORD)t);
    #pragma GCC diagnostic pop

	if(!bofstart())
	{
		return;
	}
	
	internal_printf("Saving registry key %p\\%s to file %s\n", hive, reg_path, output_file);

	dwErrorCode = savereg(hive, reg_path, output_file);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "savereg failed: %lX\n", dwErrorCode);
		goto go_end;
	}

	internal_printf("SUCCESS.\n");

go_end:
	printoutput(TRUE);
	
	bofstop();
};
#else
#define TEST_OUTPUT_FILENAME_FMT "savereg%08x.reg"
#define TEST_REG_HIVE HKEY_CURRENT_USER
#define TEST_REG_PATH "Uninstall"
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	CHAR lpszOutputFilename[MAX_PATH];
	HKEY hkRootKey = TEST_REG_HIVE;
	LPCSTR lpszRegPathName = TEST_REG_PATH;
	
	MSVCRT$sprintf(lpszOutputFilename, TEST_OUTPUT_FILENAME_FMT, KERNEL32$GetTickCount());

	dwErrorCode = SetPrivilege(NULL, SE_BACKUP_NAME,TRUE);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "SetPrivilege failed: %lX\n", dwErrorCode );
		goto main_end;
	}

	internal_printf("Saving registry key %p\\%s to file %s\n", hkRootKey, lpszRegPathName, lpszOutputFilename);

	dwErrorCode = savereg(hkRootKey, lpszRegPathName, lpszOutputFilename);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "savereg failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:
	return dwErrorCode;
}
#endif
