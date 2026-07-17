#include <windows.h>
#include <stdio.h>
#include <lmaccess.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


DWORD SetExpirationDateForUser(LPCWSTR lpswzServer, LPCWSTR lpswzUserName)
{
	USER_INFO_1017 NewFlags = {0};	
	NET_API_STATUS dwErrorCode = NERR_Success;
	DWORD dwParmErr = 0;

	NewFlags.usri1017_acct_expires = TIMEQ_FOREVER;
	dwErrorCode = NETAPI32$NetUserSetInfo(lpswzServer, lpswzUserName, 1017, (LPBYTE)&NewFlags, &dwParmErr);
	if(NERR_Success != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to set account never exipres %lX\n", dwErrorCode);
		goto end;
	}

	internal_printf("Account should never expire!\n");
	
	end:
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
	BeaconDataParse(&parser, Buffer, Length);
	LPCWSTR lpswzHostName = (LPCWSTR)BeaconDataExtract(&parser, NULL);;
	LPCWSTR lpswzUserName = (LPCWSTR)BeaconDataExtract(&parser, NULL);;

	if(!bofstart())
	{
		return;
	}

	internal_printf("Setting expiration date to 'never' for %S\\%S\n", lpswzHostName, lpswzUserName);

	dwErrorCode = SetExpirationDateForUser(lpswzHostName, lpswzUserName);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "Setting expiration date failed: %lX\n", dwErrorCode);
		goto go_end;
	}
	
	internal_printf("SUCCESS.\n");

go_end:
	printoutput(TRUE);
	
	bofstop();
};
#else
#define TEST_USERNAME L"Guest"
#define TEST_HOSTNAME L""
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	LPCWSTR lpswzHostName = TEST_HOSTNAME;
	LPCWSTR lpswzUserName = TEST_USERNAME;
	
	internal_printf("Enabling %S\\%S\n", lpswzHostName, lpswzUserName);

	dwErrorCode = SetExpirationDateForUser(lpswzHostName, lpswzUserName);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "EnableUser failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:
	return dwErrorCode;
}
#endif