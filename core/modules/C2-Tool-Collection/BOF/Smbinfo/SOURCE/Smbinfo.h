#pragma once

#include <windows.h>
#include <lm.h>

//NETAPI32
typedef NET_API_STATUS(WINAPI *_NetWkstaGetInfo)(
	LMSTR servername,
	DWORD level,
	LPBYTE *bufptr
	);

typedef NET_API_STATUS(WINAPI *_NetApiBufferFree)(
	LPVOID Buffer
	);
