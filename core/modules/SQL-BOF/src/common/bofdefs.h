#pragma once
#pragma intrinsic(memcmp, memcpy,strcpy,strcmp,_stricmp,strlen)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <winternl.h>
#include <imagehlp.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <windns.h>
#include <dbghelp.h>
#include <winldap.h>
#include <winnetwk.h>
#include <wtsapi32.h>
#include <shlwapi.h>
#include <odbcinst.h>
#include <sql.h>
#include <sqlext.h>

#ifdef _WIN32
#define STDCALL __stdcall
#else
#define STDCALL
#endif

#ifdef BOF

// KERNEL32
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateThread (LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI int WINAPI Kernel32$WideCharToMultiByte (UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);


#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)

// MSVCRT
WINBASEAPI int __cdecl MSVCRT$atoi(const char *_Str);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$rand(void);
WINBASEAPI int __cdecl MSVCRT$srand(unsigned int _Seed);
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strcat(char * __restrict__ _Dest,const char * __restrict__ _Source);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strncat(char * __restrict__ _Dest,const char * __restrict__ _Source,size_t _Count);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strncpy(char * __restrict__ _Dest,const char * __restrict__ _Source,size_t _Count);
WINBASEAPI time_t __cdecl MSVCRT$time(time_t *_Time);
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char * __restrict__ d,size_t n,const char * __restrict__ format,va_list arg);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strcpy(char * __restrict__ __dst, const char * __restrict__ __src);

#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

// ODBC32
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLAllocHandle(SQLSMALLINT HandleType, SQLHANDLE InputHandle, SQLHANDLE* OutputHandlePtr);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLCloseCursor(SQLHSTMT StatementHandle);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLDescribeCol(SQLHSTMT StatementHandle, SQLUSMALLINT ColumnNumber, SQLCHAR* ColumnName, SQLSMALLINT BufferLength, SQLSMALLINT* NameLengthPtr, SQLSMALLINT* DataTypePtr, SQLULEN* ColumnSizePtr, SQLSMALLINT* DecimalDigitsPtr, SQLSMALLINT* NullablePtr);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLDisconnect(SQLHDBC ConnectionHandle);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLDriverConnect(SQLHDBC ConnectionHandle, SQLHWND WindowHandle, SQLCHAR* InConnectionString, SQLSMALLINT StringLength1, SQLCHAR* OutConnectionString, SQLSMALLINT BufferLength, SQLSMALLINT* StringLength2Ptr, SQLUSMALLINT DriverCompletion);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLExecDirect(SQLHSTMT StatementHandle, SQLCHAR* StatementText, SQLINTEGER TextLength);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLFetch(SQLHSTMT StatementHandle);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLFreeHandle(SQLSMALLINT HandleType, SQLHANDLE Handle);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLGetData(SQLHSTMT StatementHandle, SQLUSMALLINT ColumnNumber, SQLSMALLINT TargetType, SQLPOINTER TargetValuePtr, SQLLEN BufferLength, SQLLEN* StrLen_or_IndPtr);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLGetDiagRec(SQLSMALLINT HandleType, SQLHANDLE Handle, SQLSMALLINT RecNumber, SQLCHAR* Sqlstate, SQLINTEGER* NativeErrorPtr, SQLCHAR* MessageText, SQLSMALLINT BufferLength, SQLSMALLINT* TextLengthPtr);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLNumResultCols(SQLHSTMT StatementHandle, SQLSMALLINT* ColumnCountPtr);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLMoreResults(SQLHSTMT StatementHandle);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLSetEnvAttr(SQLHENV EnvironmentHandle, SQLINTEGER Attribute, SQLPOINTER ValuePtr, SQLINTEGER StringLength);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLSetStmtAttr(SQLHSTMT StatementHandle, SQLINTEGER Attribute, SQLPOINTER Value, SQLINTEGER StringLength);

//WS2_32
WINBASEAPI int STDCALL WS2_32$closesocket(SOCKET s);
WINBASEAPI u_short STDCALL WS2_32$htons(u_short hostshort);
WINBASEAPI int STDCALL WS2_32$inet_pton(int af, const char *src, void *dst);
WINBASEAPI int STDCALL WS2_32$recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);
WINBASEAPI int STDCALL WS2_32$sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
WINBASEAPI int STDCALL WS2_32$setsockopt(SOCKET s, int level, int optname, const char *optval, int optlen);
WINBASEAPI int STDCALL WS2_32$socket(int af, int type, int protocol);
WINBASEAPI int STDCALL WS2_32$WSACleanup();
WINBASEAPI int STDCALL WS2_32$WSAGetLastError();
WINBASEAPI int STDCALL WS2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);

#else

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

// KERNEL32
#define KERNEL32$CloseHandle CloseHandle
#define KERNEL32$CreateThread CreateThread
#define Kernel32$WideCharToMultiByte  WideCharToMultiByte 
#define KERNEL32$HeapFree  HeapFree 
#define KERNEL32$GetProcessHeap GetProcessHeap
#define KERNEL32$HeapAlloc HeapAlloc
#define KERNEL32$WaitForSingleObject WaitForSingleObject


// MSVCRT
#define MSVCRT$atoi atoi
#define MSVCRT$calloc calloc
#define MSVCRT$free free
#define MSVCRT$malloc malloc
#define MSVCRT$memcpy memcpy
#define MSVCRT$memset memset
#define MSVCRT$rand rand
#define MSVCRT$srand srand
#define MSVCRT$sprintf sprintf
#define MSVCRT$strcat strcat
#define MSVCRT$strcmp strcmp
#define MSVCRT$strlen strlen
#define MSVCRT$strncat strncat
#define MSVCRT$strncpy strncpy
#define MSVCRT$time time
#define MSVCRT$vsnprintf vsnprintf
#define MSVCRT$strcpy strcpy

// ODBC32
#define ODBC32$SQLAllocHandle SQLAllocHandle
#define ODBC32$SQLCloseCursor SQLCloseCursor
#define ODBC32$SQLDescribeCol SQLDescribeCol
#define ODBC32$SQLDisconnect SQLDisconnect
#define ODBC32$SQLDriverConnect SQLDriverConnect
#define ODBC32$SQLExecDirect SQLExecDirect
#define ODBC32$SQLFetch SQLFetch
#define ODBC32$SQLFreeHandle SQLFreeHandle
#define ODBC32$SQLGetData SQLGetData
#define ODBC32$SQLGetDiagRec SQLGetDiagRec
#define ODBC32$SQLNumResultCols SQLNumResultCols
#define ODBC32$SQLMoreResults SQLMoreResults
#define ODBC32$SQLSetEnvAttr SQLSetEnvAttr
#define ODBC32$SQLSetStmtAttr SQLSetStmtAttr

//WS2_32
#define WS2_32$closesocket closesocket
#define WS2_32$htons htons
#define WS2_32$inet_pton inet_pton
#define WS2_32$recvfrom recvfrom
#define WS2_32$sendto sendto
#define WS2_32$setsockopt setsockopt
#define WS2_32$socket socket
#define WS2_32$WSACleanup WSACleanup
#define WS2_32$WSAGetLastError WSAGetLastError
#define WS2_32$WSAStartup WSAStartup

#endif
