#include <windows.h>
#include <stdio.h>
#include <lmaccess.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


DWORD AddUser(LPWSTR lpswzUserName, LPWSTR lpswzPassword, LPWSTR lpswzServerName)
{
	NET_API_STATUS dwErrorCode = NERR_Success;
	LOCALGROUP_MEMBERS_INFO_3 mi[1] = {0};

    USER_INFO_1 ui       = { 0 };
    memset(&ui, 0, sizeof(ui));

    ui.usri1_name        = lpswzUserName;
    ui.usri1_password    = lpswzPassword;
    ui.usri1_priv        = USER_PRIV_USER;
    ui.usri1_home_dir    = NULL;
    ui.usri1_comment     = NULL;
    ui.usri1_flags       = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
    ui.usri1_script_path = NULL;

	dwErrorCode = NETAPI32$NetUserAdd(lpswzServerName, 1, (LPBYTE)&ui, NULL);

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
	LPWSTR lpswzUserName = (LPWSTR)BeaconDataExtract(&parser, NULL); // $2
	LPWSTR lpswzPassword = (LPWSTR)BeaconDataExtract(&parser, NULL); // $3
	LPWSTR lpswzServerName = (LPWSTR)BeaconDataExtract(&parser, NULL); // $4
	if(lpswzServerName[0] == L'\0'){lpswzServerName = NULL;}

	if(!bofstart())
	{
		return;
	}

	internal_printf("Adding %S to %S\n", lpswzUserName, lpswzServerName ? lpswzServerName : L"the local machine" );

	dwErrorCode = AddUser(lpswzUserName, lpswzPassword, lpswzServerName);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "Adding user failed: %lX\n", dwErrorCode);
		goto go_end;
	}
	
	internal_printf("SUCCESS.\n");

go_end:
	printoutput(TRUE);
	
	bofstop();
};
#else
#define TEST_USERNAME L"Guest"
#define TEST_HOSTNAME NULL
#define TEST_PASSWORD L"Password123!"

int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	LPWSTR lpswzUserName = TEST_USERNAME;
	LPWSTR lpswzPassword = TEST_PASSWORD;
	LPWSTR lpswzServerName = TEST_HOSTNAME;

	internal_printf("Adding %S to %S\n", lpswzUserName, lpswzServerName ? lpswzServerName : L"the local machine" );

	dwErrorCode = AddUser(lpswzUserName, lpswzPassword, lpswzServerName);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "Adding user failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:
	return dwErrorCode;
}
#endif