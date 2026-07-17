#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DWORD YOUNAMEHERE(char const * string_arg, const int int_arg)
{
	DWORD dwErrorCode = ERROR_SUCCESS;

YOUNAMEHERE_end:
	// Peform any clean-up / freeing of local variables, handles, allocations

	return dwErrorCode;
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	// $args = bof_pack($1, "zi", $string_arg, $int_arg);
	datap parser = {0};
	const char * string_arg = NULL;
	int int_arg = 0;

	BeaconDataParse(&parser, Buffer, Length);
	string_arg = BeaconDataExtract(&parser, NULL);
	int_arg = BeaconDataInt(&parser);
	
	if(!bofstart())
	{
		return;
	}

	internal_printf("Calling YOUNAMEHERE with arguments %s and %d\n", string_arg, int_arg );

	dwErrorCode = YOUNAMEHERE(string_arg, int_arg);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "YOUNAMEHERE failed: %lX\n", dwErrorCode);
		goto go_end;
	}

	internal_printf("SUCCESS.\n");

go_end:

	printoutput(TRUE);
	
	bofstop();
};
#else
#define TEST_STRING_ARG "TEST_STRING_ARG"
#define TEST_INT_ARG 12345
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	const char * string_arg = TEST_STRING_ARG;
	int int_arg = TEST_INT_ARG;

	internal_printf("Calling YOUNAMEHERE with arguments %s and %d\n", string_arg, int_arg );

	dwErrorCode = YOUNAMEHERE(string_arg, int_arg);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "YOUNAMEHERE failed: %lX\n", dwErrorCode);	
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif