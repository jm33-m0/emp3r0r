#include <windows.h>
#include <stdio.h>
#include <lmaccess.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


DWORD EnableUser(LPCWSTR lpswzServer, LPCWSTR lpswzUserName)
{
	LPUSER_INFO_1 lpExistingInfo = NULL;
	USER_INFO_1008 NewFlags = {0};
	DWORD dwUnlockMask = 0xFFFFFFFF ^ (UF_ACCOUNTDISABLE | UF_LOCKOUT);
	NET_API_STATUS dwErrorCode = NERR_Success;
	DWORD dwParmErr = 0;

	dwErrorCode = NETAPI32$NetUserGetInfo(lpswzServer, lpswzUserName, 1, (LPBYTE *)&lpExistingInfo);
	if(NERR_Success != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to get existing account info: %lX\n", dwErrorCode);
		goto end;
	}
	if(lpExistingInfo->usri1_flags & UF_ACCOUNTDISABLE )
	{
		internal_printf("Account was disabled, attempting to enable\n");
	}
	if(lpExistingInfo->usri1_flags & UF_LOCKOUT)
	{
		internal_printf("Account is locked out, unlocking\n");
	}

	NewFlags.usri1008_flags = lpExistingInfo->usri1_flags & dwUnlockMask;
	dwErrorCode = NETAPI32$NetUserSetInfo(lpswzServer, lpswzUserName, 1008, (LPBYTE)&NewFlags, &dwParmErr);
	if(NERR_Success != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to enable account: %lX\n", dwErrorCode);
		goto end;
	}

	internal_printf("Account should be enabled\n");

end:
	if(lpExistingInfo)
	{
		NETAPI32$NetApiBufferFree(lpExistingInfo);
		lpExistingInfo = NULL;
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
	BeaconDataParse(&parser, Buffer, Length);
	LPCWSTR lpswzHostName = (LPCWSTR)BeaconDataExtract(&parser, NULL);;
	LPCWSTR lpswzUserName = (LPCWSTR)BeaconDataExtract(&parser, NULL);;

	if(!bofstart())
	{
		return;
	}

	internal_printf("Enabling %S\\%S\n", lpswzHostName, lpswzUserName);

	dwErrorCode = EnableUser(lpswzHostName, lpswzUserName);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "EnableUser failed: %lX\n", dwErrorCode);
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

	dwErrorCode = EnableUser(lpswzHostName, lpswzUserName);
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
