#pragma once
#pragma intrinsic(memcpy,strcpy,strcmp,strlen)
#define SECURITY_WIN32
#include <windows.h>
#include <process.h>
#include <winternl.h>
#include <imagehlp.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <windns.h>
#include <dbghelp.h>
#include <wincred.h>
#include <security.h>
#include <winldap.h>
#include <winnetwk.h>
#include <lm.h>
#include <tlhelp32.h>
#include <winreg.h>
#include <shlwapi.h>
#include <dsgetdc.h>
#include <winhttp.h>


#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size) (ptr) ? KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size) : KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

#ifdef BOF
//KERNEL32
WINBASEAPI void * WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI WINBOOL WINAPI KERNEL32$VirtualProtectEx (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
WINBASEAPI SIZE_T WINAPI KERNEL32$VirtualQueryEx (HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
WINBASEAPI int WINAPI KERNEL32$VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI int WINAPI KERNEL32$VirtualFreeEx (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalAlloc (UINT, SIZE_T);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree (HLOCAL);
WINBASEAPI HGLOBAL KERNEL32$GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
WINBASEAPI HGLOBAL KERNEL32$GlobalFree(HGLOBAL hMem);
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapReAlloc (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI KERNEL32$FormatMessageA (DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list *Arguments);
WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte (UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar (UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
WINBASEAPI int WINAPI KERNEL32$FileTimeToLocalFileTime (CONST FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
WINBASEAPI int WINAPI KERNEL32$FileTimeToSystemTime (CONST FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI int WINAPI KERNEL32$GetDateFormatW (LCID Locale, DWORD dwFlags, CONST SYSTEMTIME *lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate);
WINBASEAPI VOID WINAPI KERNEL32$GetSystemTimeAsFileTime (LPFILETIME lpSystemTimeAsFileTime);
WINBASEAPI VOID WINAPI KERNEL32$GetSystemInfo (LPSYSTEM_INFO lpSystemInfo);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI VOID WINAPI KERNEL32$SetLastError (DWORD dwErrCode);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount (VOID);
WINBASEAPI LPVOID WINAPI KERNEL32$CreateFiber (SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);
WINBASEAPI LPVOID WINAPI KERNEL32$ConvertThreadToFiber (LPVOID lpParameter);
WINBASEAPI WINBOOL WINAPI KERNEL32$ConvertFiberToThread (VOID);
WINBASEAPI VOID WINAPI KERNEL32$DeleteFiber (LPVOID lpFiber);
WINBASEAPI VOID WINAPI KERNEL32$SwitchToFiber (LPVOID lpFiber);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI VOID WINAPI KERNEL32$Sleep (DWORD dwMilliseconds);
WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessW (LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessA (LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (VOID);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread (VOID);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetExitCodeProcess (HANDLE hProcess, LPDWORD lpExitCode);
WINBASEAPI WINBOOL WINAPI KERNEL32$WriteProcessMemory (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI WINBOOL WINAPI KERNEL32$ReadProcessMemory (HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentProcessId (VOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetProcessIdOfThread (HANDLE Thread);
WINBASEAPI WINBOOL WINAPI KERNEL32$ProcessIdToSessionId (DWORD dwProcessId, DWORD *pSessionId);
WINBASEAPI WINBOOL WINAPI KERNEL32$InitializeProcThreadAttributeList (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize);
WINBASEAPI WINBOOL WINAPI KERNEL32$UpdateProcThreadAttribute (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize);
WINBASEAPI VOID WINAPI KERNEL32$DeleteProcThreadAttributeList (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateThread (LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenThread (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwThreadId);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetThreadContext (HANDLE hThread, LPCONTEXT lpContext);
WINBASEAPI WINBOOL WINAPI KERNEL32$SetThreadContext (HANDLE hThread, CONST LPCONTEXT lpContext);
WINBASEAPI DWORD WINAPI KERNEL32$SuspendThread (HANDLE hThread);
WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread (HANDLE hThread);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetComputerNameExW (COMPUTER_NAME_FORMAT NameType, LPWSTR lpBuffer, LPDWORD nSize);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetComputerNameA (LPSTR lpBuffer, LPDWORD nSize);
WINBASEAPI int WINAPI KERNEL32$lstrcmpA (LPCSTR lpString1, LPCSTR lpString2);
WINBASEAPI int WINAPI KERNEL32$lstrcmpW (LPCWSTR lpString1, LPCWSTR lpString2);
WINBASEAPI int WINAPI KERNEL32$lstrcmpiW (LPCWSTR lpString1, LPCWSTR lpString2);
WINBASEAPI int WINAPI KERNEL32$lstrlenA (LPCSTR lpString);
WINBASEAPI int WINAPI KERNEL32$lstrlenW (LPCWSTR lpString);
WINBASEAPI LPWSTR WINAPI KERNEL32$lstrcatW (LPWSTR lpString1, LPCWSTR lpString2);
WINBASEAPI LPWSTR WINAPI KERNEL32$lstrcpynW (LPWSTR lpString1, LPCWSTR lpString2, int iMaxLength);
WINBASEAPI DWORD WINAPI KERNEL32$GetFullPathNameW (LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesW (LPCWSTR lpFileName);
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentDirectoryW (DWORD nBufferLength, LPWSTR lpBuffer);
WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileW (LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
WINBASEAPI WINBOOL WINAPI KERNEL32$FindNextFileW (HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
WINBASEAPI WINBOOL WINAPI KERNEL32$FindClose (HANDLE hFindFile);
WINBASEAPI DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW (LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize);
WINBASEAPI DWORD WINAPI KERNEL32$ExpandEnvironmentStringsA (LPCSTR lpSrc, LPSTR lpDst, DWORD nSize);
WINBASEAPI DWORD WINAPI KERNEL32$GetTempPathW (DWORD nBufferLength, LPWSTR lpBuffer);
WINBASEAPI DWORD WINAPI KERNEL32$GetTempFileNameW (LPCWSTR lpPathName, LPCWSTR lpPrefixString, UINT uUnique, LPWSTR lpTempFileName);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize (HANDLE hFile, LPDWORD lpFileSizeHigh);
WINBASEAPI WINBOOL WINAPI KERNEL32$ReadFile (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI WINBOOL WINAPI KERNEL32$WriteFile (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
WINBASEAPI WINBOOL WINAPI KERNEL32$DeleteFileW (LPCWSTR lpFileName);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileMappingA (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
WINBASEAPI LPVOID WINAPI KERNEL32$MapViewOfFile (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
WINBASEAPI WINBOOL WINAPI KERNEL32$UnmapViewOfFile (LPCVOID lpBaseAddress);
WINBASEAPI LPTCH WINAPI KERNEL32$GetEnvironmentStrings();
WINBASEAPI BOOL WINAPI KERNEL32$FreeEnvironmentStringsA(LPSTR);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags,DWORD th32ProcessID);
WINBASEAPI WINBOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);
WINBASEAPI WINBOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA (LPCSTR lpLibFileName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI WINBOOL WINAPI KERNEL32$FreeLibrary (HMODULE hLibModule);
WINBASEAPI WINBOOL WINAPI KERNEL32$SetEvent (HANDLE hEvent);
WINBASEAPI WINBOOL WINAPI KERNEL32$TerminateThread (HANDLE hThread, DWORD dwExitCode);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateEventA (LPSECURITY_ATTRIBUTES lpEventAttributes, WINBOOL bManualReset, WINBOOL bInitialState, LPCSTR lpName);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR lpModuleName);


//IPHLPAPI
//ULONG WINAPI IPHLPAPI$GetAdaptersInfo (PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);
WINBASEAPI DWORD WINAPI IPHLPAPI$GetAdaptersInfo(PIP_ADAPTER_INFO,PULONG);
WINBASEAPI DWORD WINAPI IPHLPAPI$GetIpForwardTable (PMIB_IPFORWARDTABLE pIpForwardTable, PULONG pdwSize, WINBOOL bOrder);
WINBASEAPI DWORD WINAPI IPHLPAPI$GetNetworkParams(PFIXED_INFO,PULONG);
WINBASEAPI ULONG WINAPI IPHLPAPI$GetUdpTable (PMIB_UDPTABLE UdpTable, PULONG SizePointer, WINBOOL Order);
WINBASEAPI ULONG WINAPI IPHLPAPI$GetTcpTable (PMIB_TCPTABLE TcpTable, PULONG SizePointer, WINBOOL Order);

//MSVCRT
WINBASEAPI char * __cdecl MSVCRT$strcat(char * __restrict__ _Dest,const char * __restrict__ _Source);
WINBASEAPI int __cdecl MSVCRT$_snprintf(char * __restrict__ _Dest,size_t _Count,const char * __restrict__ _Format,...);
WINBASEAPI int __cdecl MSVCRT$sscanf(const char * __restrict__ _Src,const char * __restrict__ _Format,...);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void *__cdecl MSVCRT$realloc(void *_Memory, size_t _NewSize);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI int __cdecl MSVCRT$memcmp(const void *_Buf1,const void *_Buf2,size_t _Size);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char * __restrict__ d,size_t n,const char * __restrict__ format,va_list arg);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char *_Str1,const char *_Str2);
WINBASEAPI PCHAR __cdecl MSVCRT$strchr(const char *haystack, int needle);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);
WINBASEAPI char * __cdecl MSVCRT$strcpy(char * __restrict__ __dst, const char * __restrict__ __src);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
WINBASEAPI int __cdecl MSVCRT$wcsncmp(const wchar_t *_Str1,const wchar_t *_Str2, size_t count);
WINBASEAPI int __cdecl MSVCRT$strncmp(const char *_Str1,const char *_Str2,size_t _MaxCount);
WINBASEAPI size_t __cdecl MSVCRT$strnlen(const char *_Str,size_t _MaxCount);
WINBASEAPI PCHAR __cdecl MSVCRT$strstr(const char *haystack, const char *needle);
WINBASEAPI char *__cdecl MSVCRT$strtok(char * __restrict__ _Str,const char * __restrict__ _Delim);
WINBASEAPI int __cdecl MSVCRT$swprintf(wchar_t *__stream, const wchar_t *__format, ...);
WINBASEAPI int __cdecl MSVCRT$_swprintf(wchar_t * __restrict__ _Dest,const wchar_t * __restrict__ _Format,...);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat(wchar_t * __restrict__ _Dest,const wchar_t * __restrict__ _Source);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcsncat(wchar_t * __restrict__ _Dest, const wchar_t * __restrict__ _Source, size_t _Count);
WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1,const wchar_t *_Str2);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscpy(wchar_t * __restrict__ _Dest, const wchar_t * __restrict__ _Source);
WINBASEAPI errno_t __cdecl MSVCRT$wcscpy_s(wchar_t *_Dst, rsize_t _DstSize, const wchar_t *_Src);
WINBASEAPI _CONST_RETURN wchar_t *__cdecl MSVCRT$wcschr(const wchar_t *_Str, wchar_t _Ch);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcsrchr(const wchar_t *_Str,wchar_t _Ch);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcsstr(const wchar_t *_Str,const wchar_t *_SubStr);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcstok(wchar_t * __restrict__ _Str,const wchar_t * __restrict__ _Delim);
WINBASEAPI unsigned long __cdecl MSVCRT$wcstoul(const wchar_t * __restrict__ _Str,wchar_t ** __restrict__ _EndPtr,int _Radix);
WINBASEAPI long __cdecl MSVCRT$_wtol(const wchar_t * str);
DECLSPEC_IMPORT void __cdecl MSVCRT$srand(unsigned int _Seed);
DECLSPEC_IMPORT int __cdecl MSVCRT$rand(void);
_CRTIMP __time32_t __cdecl MSVCRT$_time32(__time32_t *_Time);
WINBASEAPI int __cdecl MSVCRT$_snwprintf(wchar_t * __restrict__ _Dest,size_t _Count,const wchar_t * __restrict__ _Format,...);
_CRTIMP uintptr_t __cdecl MSVCRT$_beginthreadex(void *_Security,unsigned _StackSize,_beginthreadex_proc_type _StartAddress,void *_ArgList,unsigned _InitFlag,unsigned *_ThrdAddr);
_CRTIMP void __cdecl MSVCRT$_endthreadex(unsigned _Retval) __MINGW_ATTRIB_NORETURN;
WINBASEAPI int __cdecl MSVCRT$swprintf_s(wchar_t *buffer, size_t sizeOfBuffer, const wchar_t *format, ...);

_CRTIMP __time64_t __cdecl MSVCRT$_time64(__time64_t *_Time);

//SHLWAPI
WINBASEAPI LPWSTR WINAPI SHLWAPI$PathCombineW(LPWSTR pszDest,LPCWSTR pszDir,LPCWSTR pszFile);
WINBASEAPI WINBOOL WINAPI SHLWAPI$PathFileExistsW(LPCWSTR pszPath);
WINBASEAPI LPSTR WINAPI SHLWAPI$StrStrA(LPCSTR lpFirst,LPCSTR lpSrch);

//SHELL32
WINBASEAPI WINBOOL WINAPI SHELL32$ShellExecuteExW(SHELLEXECUTEINFOW *pExecInfo);
WINBASEAPI HINSTANCE WINAPI SHELL32$ShellExecuteA (HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd);

//DNSAPI
WINBASEAPI DNS_STATUS WINAPI DNSAPI$DnsQuery_A(PCSTR,WORD,DWORD,PIP4_ARRAY,PDNS_RECORD*,PVOID*);
WINBASEAPI VOID WINAPI DNSAPI$DnsFree(PVOID pData,DNS_FREE_TYPE FreeType);

//WSOCK32
WINBASEAPI unsigned long WINAPI WSOCK32$inet_addr(const char *cp);

//WS2_32
WINBASEAPI u_long WINAPI WS2_32$htonl(u_long hostlong);
WINBASEAPI u_short WINAPI WS2_32$htons(u_short hostshort);
WINBASEAPI char * WINAPI WS2_32$inet_ntoa(struct in_addr in);
WINBASEAPI LPCWSTR WINAPI WS2_32$InetNtopW(INT Family, LPCVOID pAddr, LPWSTR pStringBuf, size_t StringBufSIze);
WINBASEAPI INT WINAPI WS2_32$inet_pton(INT Family, LPCSTR pStringBuf, PVOID pAddr);
WINBASEAPI int WINAPI WS2_32$WSAStartup(WORD wVersionRequested,LPWSADATA lpWSAData);
WINBASEAPI int WINAPI WS2_32$WSAGetLastError(void);
WINBASEAPI int WINAPI WS2_32$socket(int af,int type,int protocol);
WINBASEAPI int WINAPI WS2_32$setsockopt(SOCKET s,int level,int optname,const char *optval,int optlen);
WINBASEAPI int WINAPI WS2_32$sendto(SOCKET s,const char *buf,int len,int flags,const struct sockaddr *to,int tolen);
WINBASEAPI int WINAPI WS2_32$recvfrom(SOCKET s,char *buf,int len,int flags,struct sockaddr *from,int *fromlen);
WINBASEAPI int WINAPI WS2_32$recv(SOCKET s,char *buf,int len,int flags);
WINBASEAPI int WINAPI WS2_32$closesocket(SOCKET s);
WINBASEAPI int WINAPI WS2_32$WSACleanup(void);
WINBASEAPI int WINAPI WS2_32$ntohs(u_short netshort);
WINBASEAPI int WINAPI WS2_32$bind(SOCKET s,const struct sockaddr *addr,int namelen);
WINBASEAPI int WINAPI WS2_32$listen(SOCKET s,int backlog);
WINBASEAPI SOCKET WINAPI WS2_32$accept(SOCKET s,struct sockaddr *addr,int *addrlen);
WINBASEAPI SOCKET WINAPI WS2_32$send(SOCKET s,const char *buf,int len,int flags);

//winhttp
WINBASEAPI HINTERNET WINAPI WINHTTP$WinHttpOpen(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
WINBASEAPI HINTERNET WINAPI WINHTTP$WinHttpConnect(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
WINBASEAPI HINTERNET WINAPI WINHTTP$WinHttpOpenRequest(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
WINBASEAPI WINBOOL WINAPI WINHTTP$WinHttpAddRequestHeaders(HINTERNET,LPCWSTR,DWORD,DWORD);
WINBASEAPI WINBOOL WINAPI WINHTTP$WinHttpSendRequest(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
WINBASEAPI WINBOOL WINAPI WINHTTP$WinHttpReceiveResponse(HINTERNET,LPVOID);
WINBASEAPI WINBOOL WINAPI WINHTTP$WinHttpReadData(HINTERNET,LPVOID,DWORD,LPDWORD);
WINBASEAPI WINBOOL WINAPI WINHTTP$WinHttpCloseHandle(HINTERNET);


//NETAPI32
WINBASEAPI DWORD WINAPI NETAPI32$DsGetDcNameA(LPCSTR ComputerName,LPCSTR DomainName,GUID *DomainGuid,LPCSTR SiteName,ULONG Flags,PDOMAIN_CONTROLLER_INFOA *DomainControllerInfo);
WINBASEAPI DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR ComputerName,LPCWSTR DomainName,GUID *DomainGuid,LPCWSTR SiteName,ULONG Flags,PDOMAIN_CONTROLLER_INFOW *DomainControllerInfo);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetInfo(LPCWSTR servername,LPCWSTR username,DWORD level,LPBYTE *bufptr);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserModalsGet(LPCWSTR servername,DWORD level,LPBYTE *bufptr);
WINBASEAPI DWORD WINAPI NETAPI32$NetServerEnum(LMCSTR servername,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,DWORD servertype,LMCSTR domain,LPDWORD resume_handle);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetGroups(LPCWSTR servername,LPCWSTR username,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetLocalGroups(LPCWSTR servername,LPCWSTR username,DWORD level,DWORD flags,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);
WINBASEAPI DWORD WINAPI NETAPI32$NetGetAnyDCName(LPCWSTR servername,LPCWSTR domainname,LPBYTE *bufptr);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserEnum(LPCWSTR servername,DWORD level,DWORD filter,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,LPDWORD resume_handle);
WINBASEAPI DWORD WINAPI NETAPI32$NetGroupGetUsers(LPCWSTR servername,LPCWSTR groupname,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,PDWORD_PTR ResumeHandle);
WINBASEAPI DWORD WINAPI NETAPI32$NetQueryDisplayInformation(LPCWSTR ServerName,DWORD Level,DWORD Index,DWORD EntriesRequested,DWORD PreferredMaximumLength,LPDWORD ReturnedEntryCount,PVOID *SortedBuffer);
WINBASEAPI DWORD WINAPI NETAPI32$NetLocalGroupEnum(LPCWSTR servername,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,PDWORD_PTR resumehandle);
WINBASEAPI DWORD WINAPI NETAPI32$NetLocalGroupGetMembers(LPCWSTR servername,LPCWSTR localgroupname,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,PDWORD_PTR resumehandle);
WINBASEAPI DWORD WINAPI NETAPI32$NetLocalGroupAddMembers(LPCWSTR servername,LPCWSTR groupname,DWORD level,LPBYTE buf,DWORD totalentries);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserSetInfo(LPCWSTR servername,LPCWSTR username,DWORD level,LPBYTE buf,LPDWORD parm_err);
WINBASEAPI DWORD WINAPI NETAPI32$NetShareEnum(LMSTR servername,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,LPDWORD resume_handle);
WINBASEAPI DWORD WINAPI NETAPI32$NetSessionEnum(LPCWSTR servername, LPCWSTR UncClientName, LPCWSTR username, DWORD level, LPBYTE* bufptr, DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries, LPDWORD resumehandle);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);
WINBASEAPI DWORD WINAPI NETAPI32$NetGroupAddUser(LPCWSTR servername,LPCWSTR GroupName,LPCWSTR userName);
WINBASEAPI DWORD WINAPI NETAPI32$NetGroupAddUser(LPCWSTR servername,LPCWSTR GroupName,LPCWSTR userName);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserAdd(LPCWSTR servername, DWORD level, LPBYTE buf, LPDWORD parm_err);

//MPR
WINBASEAPI DWORD WINAPI MPR$WNetOpenEnumW(DWORD dwScope, DWORD dwType, DWORD dwUsage, LPNETRESOURCEW lpNetResource, LPHANDLE lphEnum);
WINBASEAPI DWORD WINAPI MPR$WNetEnumResourceW(HANDLE hEnum, LPDWORD lpcCount, LPVOID lpBuffer, LPDWORD lpBufferSize);
WINBASEAPI DWORD WINAPI MPR$WNetCloseEnum(HANDLE hEnum);
WINBASEAPI DWORD WINAPI MPR$WNetGetNetworkInformationW(LPCWSTR lpProvider, LPNETINFOSTRUCT lpNetInfoStruct);
WINBASEAPI DWORD WINAPI MPR$WNetGetConnectionW(LPCWSTR lpLocalName, LPWSTR lpRemoteName, LPDWORD lpnLength);
WINBASEAPI DWORD WINAPI MPR$WNetGetResourceInformationW(LPNETRESOURCEW lpNetResource, LPVOID lpBuffer, LPDWORD lpcbBuffer, LPWSTR *lplpSystem);
WINBASEAPI DWORD WINAPI MPR$WNetGetUserW(LPCWSTR lpName, LPWSTR lpUserName, LPDWORD lpnLength);
WINBASEAPI DWORD WINAPI MPR$WNetAddConnection2W(LPNETRESOURCEW lpNetResource, LPCWSTR lpPassword, LPCWSTR lpUserName, DWORD dwFlags);
WINBASEAPI DWORD WINAPI MPR$WNetCancelConnection2W(LPCWSTR lpName, DWORD dwFlags, BOOL fForce);

//USER32
WINUSERAPI LPWSTR WINAPI USER32$CharPrevW(LPCWSTR lpszStart,LPCWSTR lpszCurrent);
WINUSERAPI UINT WINAPI USER32$DdeInitializeA(LPDWORD pidInst,PFNCALLBACK pfnCallback,DWORD afCmd,DWORD ulRes);
WINUSERAPI HCONVLIST WINAPI USER32$DdeConnectList(DWORD idInst,HSZ hszService,HSZ hszTopic,HCONVLIST hConvList,PCONVCONTEXT pCC);
WINUSERAPI WINBOOL WINAPI USER32$DdeDisconnectList(HCONVLIST hConvList);
WINUSERAPI WINBOOL WINAPI USER32$DdeUninitialize(DWORD idInst);
WINUSERAPI int WINAPI USER32$EnumDesktopWindows(HDESK hDesktop,WNDENUMPROC lpfn,LPARAM lParam);
WINUSERAPI WINBOOL WINAPI USER32$EnumWindows(WNDENUMPROC lpEnumFunc,LPARAM lParam);
WINUSERAPI HWND WINAPI USER32$FindWindowA(LPCSTR lpszClass,LPCSTR lpszWindow);
WINUSERAPI HWND WINAPI USER32$FindWindowExA(HWND hWndParent,HWND hWndChildAfter,LPCSTR lpszClass,LPCSTR lpszWindow);
WINUSERAPI int WINAPI USER32$GetClassNameA(HWND hWnd,LPSTR lpClassName,int nMaxCount);
WINUSERAPI HANDLE WINAPI USER32$GetPropA(HWND hWnd,LPCSTR lpString);
WINUSERAPI LONG WINAPI USER32$GetWindowLongA(HWND hWnd,int nIndex);
WINUSERAPI LONG_PTR WINAPI USER32$GetWindowLongPtrA(HWND hWnd,int nIndex);
WINUSERAPI int WINAPI USER32$GetWindowTextA(HWND hWnd,LPSTR lpString,int nMaxCount);
WINUSERAPI DWORD WINAPI USER32$GetWindowThreadProcessId(HWND hWnd,LPDWORD lpdwProcessId);
WINUSERAPI int WINAPI USER32$IsWindowVisible(HWND hWnd);
WINUSERAPI WINBOOL WINAPI USER32$PostMessageA(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam);
WINUSERAPI LRESULT WINAPI USER32$SendMessageA(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam);
WINUSERAPI LRESULT WINAPI USER32$SendMessageTimeoutW(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam,UINT fuFlags,UINT uTimeout,PDWORD_PTR lpdwResult);
WINUSERAPI BOOL WINAPI USER32$SetPropA(HWND hWnd,LPCSTR lpString,HANDLE hData);
WINUSERAPI LONG WINAPI USER32$SetWindowLongA(HWND hWnd,int nIndex, LONG dwNewLong);
WINUSERAPI LONG_PTR WINAPI USER32$SetWindowLongPtrA(HWND hWnd,int nIndex, LONG_PTR dwNewLong);
WINUSERAPI UINT_PTR WINAPI USER32$SetTimer(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc);
WINUSERAPI WINBOOL WINAPI USER32$KillTimer(HWND hWnd, UINT_PTR uIDEvent);
WINUSERAPI WINBOOL WINAPI USER32$PostMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
WINUSERAPI HDC WINAPI USER32$BeginPaint(HWND hWnd, LPPAINTSTRUCT lpPaint);
WINUSERAPI WINBOOL WINAPI USER32$GetClientRect(HWND hWnd, LPRECT lpRect);
WINUSERAPI int WINAPI USER32$FillRect(HDC hDC, CONST RECT *lprc, HBRUSH hbr);
WINUSERAPI int WINAPI USER32$DrawTextW(HDC hdc, LPCWSTR lpchText, int cchText, LPRECT lprc, UINT format);
WINUSERAPI WINBOOL WINAPI USER32$EndPaint(HWND hWnd, CONST PAINTSTRUCT *lpPaint);
WINUSERAPI WINBOOL WINAPI USER32$DestroyWindow(HWND hWnd);
WINUSERAPI VOID WINAPI USER32$PostQuitMessage(int nExitCode);
WINUSERAPI LRESULT WINAPI USER32$DefWindowProcW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
WINUSERAPI LRESULT WINAPI USER32$DispatchMessageW(CONST MSG *lpMsg);
WINUSERAPI WINBOOL WINAPI USER32$TranslateMessage(CONST MSG *lpMsg);
WINUSERAPI WINBOOL WINAPI USER32$GetMessageW(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
WINUSERAPI HWND WINAPI USER32$SetFocus(HWND hWnd);
WINUSERAPI ATOM WINAPI USER32$RegisterClassExW(CONST WNDCLASSEXW *lpwcx);
WINUSERAPI WINBOOL WINAPI USER32$SetForegroundWindow(HWND hWnd);
WINUSERAPI WINBOOL WINAPI USER32$UpdateWindow(HWND hWnd);
WINUSERAPI WINBOOL WINAPI USER32$ShowWindow(HWND hWnd, int nCmdShow);
WINUSERAPI WINBOOL WINAPI USER32$UnregisterClassW(LPCWSTR lpClassName, HINSTANCE hInstance);
WINUSERAPI HWND WINAPI USER32$CreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
WINUSERAPI int WINAPI USER32$GetSystemMetrics(int nIndex);

//SSPICLI
WINBASEAPI DWORD WINAPI SSPICLI$EnumerateSecurityPackagesA(unsigned long*, PSecPkgInfoA*);
WINBASEAPI SECURITY_STATUS WINAPI SSPICLI$FreeContextBuffer(void *pvContextBuffer);

//SECUR32
WINBASEAPI BOOLEAN WINAPI SECUR32$GetUserNameExA (int NameFormat, LPSTR lpNameBuffer, PULONG nSize);
WINBASEAPI BOOLEAN WINAPI SECUR32$GetUserNameExW (int NameFormat, LPWSTR lpNameBuffer, PULONG nSize);
WINBASEAPI BOOLEAN WINAPI SECUR32$GetComputerObjectNameW (int NameFormat, LPWSTR lpNameBuffer, PULONG nSize);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle phCredential);
WINBASEAPI DWORD WINAPI SECUR32$AcquireCredentialsHandleA(LPSTR, LPSTR, unsigned long, void*, void*, SEC_GET_KEY_FN, void *, PCredHandle, PTimeStamp);
WINBASEAPI DWORD WINAPI SECUR32$InitializeSecurityContextA(PCredHandle, PCtxtHandle, SEC_CHAR*, unsigned long, unsigned long, unsigned long, PSecBufferDesc, unsigned long, PCtxtHandle, PSecBufferDesc, unsigned long *, PTimeStamp);
WINBASEAPI DWORD WINAPI SECUR32$InitializeSecurityContextW(PCredHandle, PCtxtHandle, SEC_WCHAR*, unsigned long, unsigned long, unsigned long, PSecBufferDesc, unsigned long, PCtxtHandle, PSecBufferDesc, unsigned long *, PTimeStamp);
WINBASEAPI DWORD WINAPI SECUR32$AcceptSecurityContext(PCredHandle, PCtxtHandle, PSecBufferDesc, unsigned long, unsigned long, PCtxtHandle, PSecBufferDesc, unsigned long *, PTimeStamp);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$DeleteSecurityContext(PCtxtHandle phContext);
WINBASEAPI DWORD WINAPI SECUR32$AcquireCredentialsHandleA(LPSTR, LPSTR, unsigned long, void*, void*, SEC_GET_KEY_FN, void *, PCredHandle, PTimeStamp);
WINBASEAPI DWORD WINAPI SECUR32$AcceptSecurityContext(PCredHandle, PCtxtHandle, PSecBufferDesc, unsigned long, unsigned long, PCtxtHandle, PSecBufferDesc, unsigned long *, PTimeStamp);
WINBASEAPI DWORD WINAPI SECUR32$LsaConnectUntrusted(PHANDLE);
WINBASEAPI NTSTATUS NTAPI SECUR32$LsaDeregisterLogonProcess(HANDLE LsaHandle);
WINBASEAPI NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer (PVOID Buffer);
WINBASEAPI DWORD WINAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
WINBASEAPI DWORD WINAPI SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);

//VERSION
WINBASEAPI WINBOOL WINAPI VERSION$GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
WINBASEAPI WINBOOL WINAPI VERSION$GetFileVersionInfoW(LPCWSTR lptstrFilename,DWORD dwHandle,DWORD dwLen,LPVOID lpData);
WINBASEAPI DWORD WINAPI VERSION$GetFileVersionInfoSizeA(LPCSTR lptstrFilenamea ,LPDWORD lpdwHandle);
WINBASEAPI DWORD WINAPI VERSION$GetFileVersionInfoSizeW(LPCWSTR lptstrFilename,LPDWORD lpdwHandle);
WINBASEAPI WINBOOL WINAPI VERSION$VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen);
WINBASEAPI WINBOOL WINAPI VERSION$VerQueryValueW(LPCVOID pBlock,LPCWSTR lpSubBlock,LPVOID *lplpBuffer,PUINT puLen);

//FLTLIB
HRESULT WINAPI FLTLIB$FilterUnload(LPCWSTR lpFilterName);

//ADVAPI32
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountNameA (LPCSTR lpSystemName, LPCSTR lpAccountName, PSID Sid, LPDWORD cbSid, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetUserNameA (LPSTR lpBuffer, LPDWORD pcbBuffer);
WINADVAPI WINBOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser (HANDLE hToken);
WINADVAPI WINBOOL WINAPI ADVAPI32$LogonUserA (LPCSTR lpszUsername, LPCSTR lpszDomain, LPCSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken);
WINADVAPI WINBOOL WINAPI ADVAPI32$LogonUserW (LPCWSTR lpszUsername, LPCWSTR lpszDomain, LPCWSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken);
WINADVAPI WINBOOL WINAPI ADVAPI32$DuplicateTokenEx (HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
WINADVAPI WINBOOL WINAPI ADVAPI32$AdjustTokenPrivileges (HANDLE TokenHandle, WINBOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
WINADVAPI WINBOOL WINAPI ADVAPI32$CreateProcessAsUserW (HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINADVAPI WINBOOL WINAPI ADVAPI32$CreateProcessWithLogonW (LPCWSTR lpUsername, LPCWSTR lpDomain, LPCWSTR lpPassword, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINADVAPI WINBOOL WINAPI ADVAPI32$CreateProcessWithTokenW (HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenThreadToken (HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetTokenInformation (HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID Sid,LPSTR *StringSid);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID Sid,LPWSTR *StringSid);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidA (LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidW (LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeNameA (LPCSTR lpSystemName, PLUID lpLuid, LPSTR lpName, LPDWORD cchName);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeDisplayNameA (LPCSTR lpSystemName, LPCSTR lpName, LPSTR lpDisplayName, LPDWORD cchDisplayName, LPDWORD lpLanguageId);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeValueA (LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetFileSecurityW (LPCWSTR lpFileName, SECURITY_INFORMATION RequestedInformation, PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD nLength, LPDWORD lpnLengthNeeded);
WINADVAPI VOID WINAPI ADVAPI32$MapGenericMask (PDWORD AccessMask, PGENERIC_MAPPING GenericMapping);
WINADVAPI ULONG WINAPI ADVAPI32$LsaNtStatusToWinError(NTSTATUS);
WINADVAPI WINBOOL WINAPI ADVAPI32$CredMarshalCredentialW(CRED_MARSHAL_TYPE CredType,PVOID Credential,LPWSTR *MarshaledCredential);
WINADVAPI VOID WINAPI ADVAPI32$CredFree (PVOID Buffer);
WINADVAPI WINBOOL WINAPI ADVAPI32$InitializeSecurityDescriptor (PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision);
WINADVAPI WINBOOL WINAPI ADVAPI32$SetSecurityDescriptorDacl (PSECURITY_DESCRIPTOR pSecurityDescriptor, WINBOOL bDaclPresent, PACL pDacl, WINBOOL bDaclDefaulted);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorW(PSECURITY_DESCRIPTOR SecurityDescriptor,DWORD RequestedStringSDRevision,SECURITY_INFORMATION SecurityInformation,LPWSTR *StringSecurityDescriptor,PULONG StringSecurityDescriptorLen);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetSecurityDescriptorOwner (PSECURITY_DESCRIPTOR pSecurityDescriptor, PSID *pOwner, LPBOOL lpbOwnerDefaulted);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetSecurityDescriptorDacl (PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL *pDacl, LPBOOL lpbDaclDefaulted);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetAclInformation (PACL pAcl, LPVOID pAclInformation, DWORD nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetAce (PACL pAcl, DWORD dwAceIndex, LPVOID *pAce);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName,LPCSTR lpDatabaseName,DWORD dwDesiredAccess);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR lpMachineName,LPCWSTR lpDatabaseName,DWORD dwDesiredAccess);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE hSCManager,LPCSTR lpServiceName,DWORD dwDesiredAccess);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE hSCManager,LPCWSTR lpServiceName,DWORD dwDesiredAccess);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceA(SC_HANDLE hSCManager,LPCSTR lpServiceName,LPCSTR lpDisplayName,DWORD dwDesiredAccess,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,LPCSTR lpBinaryPathName,LPCSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCSTR lpDependencies,LPCSTR lpServiceStartName,LPCSTR lpPassword);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceStatus(SC_HANDLE hService,LPSERVICE_STATUS lpServiceStatus);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceConfigA(SC_HANDLE hService,LPQUERY_SERVICE_CONFIGA lpServiceConfig,DWORD cbBufSize,LPDWORD pcbBytesNeeded);
WINADVAPI WINBOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
WINADVAPI WINBOOL WINAPI ADVAPI32$EnumServicesStatusExA(SC_HANDLE hSCManager,SC_ENUM_TYPE InfoLevel,DWORD dwServiceType,DWORD dwServiceState,LPBYTE lpServices,DWORD cbBufSize,LPDWORD pcbBytesNeeded,LPDWORD lpServicesReturned,LPDWORD lpResumeHandle,LPCSTR pszGroupName);
WINADVAPI WINBOOL WINAPI ADVAPI32$EnumServicesStatusExW(SC_HANDLE hSCManager,SC_ENUM_TYPE InfoLevel,DWORD dwServiceType,DWORD dwServiceState,LPBYTE lpServices,DWORD cbBufSize,LPDWORD pcbBytesNeeded,LPDWORD lpServicesReturned,LPDWORD lpResumeHandle,LPCWSTR pszGroupName);
WINADVAPI WINBOOL WINAPI ADVAPI32$EnumDependentServicesA(SC_HANDLE hService,DWORD dwServiceState,LPENUM_SERVICE_STATUSA lpServices,DWORD cbBufSize,LPDWORD pcbBytesNeeded,LPDWORD lpServicesReturned);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE hService,SC_STATUS_TYPE InfoLevel,LPBYTE lpBuffer,DWORD cbBufSize,LPDWORD pcbBytesNeeded);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceConfig2A(SC_HANDLE hService,DWORD dwInfoLevel,LPBYTE lpBuffer,DWORD cbBufSize,LPDWORD pcbBytesNeeded);
WINADVAPI WINBOOL WINAPI ADVAPI32$ChangeServiceConfig2A(SC_HANDLE hService,DWORD dwInfoLevel,LPVOID lpInfo);
WINADVAPI WINBOOL WINAPI ADVAPI32$ChangeServiceConfigA(SC_HANDLE hService,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,LPCSTR lpBinaryPathName,LPCSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCSTR lpDependencies,LPCSTR lpServiceStartName,LPCSTR lpPassword,LPCSTR lpDisplayName);
WINADVAPI WINBOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE hService,DWORD dwNumServiceArgs,LPCSTR *lpServiceArgVectors);
WINADVAPI WINBOOL WINAPI ADVAPI32$ControlService(SC_HANDLE hService,DWORD dwControl,LPSERVICE_STATUS lpServiceStatus);
WINADVAPI WINBOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE hService);
WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);
WINADVAPI LONG WINAPI ADVAPI32$RegConnectRegistryA(LPCSTR lpMachineName,HKEY hKey,PHKEY phkResult);
WINADVAPI LONG WINAPI ADVAPI32$RegCopyTreeA(HKEY src, LPCSTR subkey, HKEY dst);
WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyA(HKEY hKey,LPCSTR lpSubKey,PHKEY phkResult);
WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD Reserved,LPSTR lpClass,DWORD dwOptions,REGSAM samDesired,LPSECURITY_ATTRIBUTES lpSecurityAttributes,PHKEY phkResult,LPDWORD lpdwDisposition);
WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyExW(HKEY hKey,LPCWSTR lpSubKey,DWORD Reserved,LPSTR lpClass,DWORD dwOptions,REGSAM samDesired,LPSECURITY_ATTRIBUTES lpSecurityAttributes,PHKEY phkResult,LPDWORD lpdwDisposition);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyExA(HKEY hKey,LPCSTR lpSubKey,REGSAM samDesired,DWORD Reserved);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyExW(HKEY hKey,LPCWSTR lpSubKey,REGSAM samDesired,DWORD Reserved);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyValueA(HKEY hKey,LPCSTR lpSubKey,LPCSTR lpValueName);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyValueW(HKEY hKey,LPCWSTR lpSubKey,LPCWSTR lpValueName);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteTreeA(HKEY base, LPCSTR subkey);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteTreeW(HKEY base, LPCWSTR subkey);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteValueA(HKEY hKey,LPCSTR lpValueName);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteValueW(HKEY hKey,LPCWSTR lpValueName);
WINADVAPI LONG WINAPI ADVAPI32$RegEnumKeyExA(HKEY hKey,DWORD dwIndex,LPSTR lpName,LPDWORD lpcchName,LPDWORD lpReserved,LPSTR lpClass,LPDWORD lpcchClass,PFILETIME lpftLastWriteTime);
WINADVAPI LONG WINAPI ADVAPI32$RegEnumValueA(HKEY hKey,DWORD dwIndex,LPSTR lpValueName,LPDWORD lpcchValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,LPDWORD lpcbData);
WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyA(HKEY hKey,LPCSTR lpSubKey,PHKEY phkResult);
WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult);
WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExW(HKEY hKey,LPCWSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryInfoKeyA(HKEY hKey,LPSTR lpClass,LPDWORD lpcchClass,LPDWORD lpReserved,LPDWORD lpcSubKeys,LPDWORD lpcbMaxSubKeyLen,LPDWORD lpcbMaxClassLen,LPDWORD lpcValues,LPDWORD lpcbMaxValueNameLen,LPDWORD lpcbMaxValueLen,LPDWORD lpcbSecurityDescriptor,PFILETIME lpftLastWriteTime);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY hKey,LPCSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,LPDWORD lpcbData);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExW(HKEY hKey,LPCWSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,LPDWORD lpcbData);
WINADVAPI LONG WINAPI ADVAPI32$RegSaveKeyExA(HKEY hKey,LPCSTR lpFile,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD Flags);
WINADVAPI LONG WINAPI ADVAPI32$RegSetValueExA(HKEY hKey,LPCSTR lpValueName,DWORD Reserved,DWORD dwType,CONST BYTE *lpData,DWORD cbData);
WINADVAPI LONG WINAPI ADVAPI32$RegSetValueExW(HKEY hKey,LPCWSTR lpValueName,DWORD Reserved,DWORD dwType,CONST BYTE *lpData,DWORD cbData);
WINADVAPI WINBOOL WINAPI ADVAPI32$InitiateSystemShutdownExA(LPSTR lpMachineName, LPSTR lpMessage, DWORD dwTimeout, BOOL bForceAppsClosed, BOOL bRebootAfterShutdown, DWORD dwReason);

//NTDLL
WINBASEAPI NTSTATUS NTAPI NTDLL$NtCreateFile(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtClose(HANDLE Handle);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtRenameKey(HANDLE keyHandle, PUNICODE_STRING New_Name);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtQueueApcThread(_In_ HANDLE ThreadHandle, _In_ PVOID ApcRoutine,	_In_ PVOID ApcRoutineContext OPTIONAL, _In_ PVOID ApcStatusBlock OPTIONAL,	_In_ ULONG ApcReserved OPTIONAL);
NTSYSAPI NTSTATUS NTAPI NTDLL$RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

//IMAGEHLP
WINBASEAPI WINBOOL IMAGEAPI IMAGEHLP$ImageEnumerateCertificates(HANDLE FileHandle,WORD TypeFilter,PDWORD CertificateCount,PDWORD Indices,DWORD IndexCount);
WINBASEAPI WINBOOL IMAGEAPI IMAGEHLP$ImageGetCertificateHeader(HANDLE FileHandle,DWORD CertificateIndex,LPWIN_CERTIFICATE Certificateheader);
WINBASEAPI WINBOOL IMAGEAPI IMAGEHLP$ImageGetCertificateData(HANDLE FileHandle,DWORD CertificateIndex,LPWIN_CERTIFICATE Certificate,PDWORD RequiredLength);

//CRYPT32
WINBASEAPI WINBOOL WINAPI CRYPT32$CryptVerifyMessageSignature (PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara, DWORD dwSignerIndex, const BYTE *pbSignedBlob, DWORD cbSignedBlob, BYTE *pbDecoded, DWORD *pcbDecoded, PCCERT_CONTEXT *ppSignerCert);
WINBASEAPI DWORD WINAPI CRYPT32$CertGetNameStringW (PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara, LPWSTR pszNameString, DWORD cchNameString);
WINBASEAPI WINBOOL WINAPI CRYPT32$CertFreeCertificateContext (PCCERT_CONTEXT pCertContext);
WINBASEAPI BOOL WINAPI CRYPT32$CryptUnprotectData(DATA_BLOB *, LPWSTR *, DATA_BLOB *, PVOID, CRYPTPROTECT_PROMPTSTRUCT *, DWORD, DATA_BLOB *);
WINIMPM WINBOOL WINAPI CRYPT32$CryptEncodeObjectEx (DWORD dwCertEncodingType, LPCSTR lpszStructType, const void *pvStructInfo, DWORD dwFlags, PCRYPT_ENCODE_PARA pEncodePara, void *pvEncoded, DWORD *pcbEncoded);
WINIMPM WINBOOL WINAPI CRYPT32$CryptBinaryToStringW (CONST BYTE *pbBinary, DWORD cbBinary, DWORD dwFlags, LPWSTR pszString, DWORD *pcchString);
WINIMPM HCERTSTORE WINAPI CRYPT32$PFXImportCertStore (CRYPT_DATA_BLOB *pPFX, LPCWSTR szPassword, DWORD dwFlags);
WINIMPM PCCERT_CONTEXT WINAPI CRYPT32$CertEnumCertificatesInStore (HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCertContext);
WINIMPM WINBOOL WINAPI CRYPT32$CertGetCertificateContextProperty (PCCERT_CONTEXT pCertContext, DWORD dwPropId, void *pvData, DWORD *pcbData);
WINIMPM WINBOOL WINAPI CRYPT32$CertAddCertificateContextToStore (HCERTSTORE hCertStore, PCCERT_CONTEXT pCertContext, DWORD dwAddDisposition, PCCERT_CONTEXT *ppStoreContext);
WINIMPM HCERTSTORE WINAPI CRYPT32$CertOpenStore (LPCSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV_LEGACY hCryptProv, DWORD dwFlags, const void *pvPara);
WINIMPM WINBOOL WINAPI CRYPT32$CertCloseStore (HCERTSTORE hCertStore, DWORD dwFlags);
WINIMPM WINBOOL WINAPI CRYPT32$CertDeleteCertificateFromStore (PCCERT_CONTEXT pCertContext);
WINIMPM WINBOOL WINAPI CRYPT32$CryptBinaryToStringA (CONST BYTE *pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD *pcchString);
WINIMPM PCCERT_CONTEXT WINAPI CRYPT32$CertCreateCertificateContext (DWORD dwCertEncodingType, const BYTE *pbCertEncoded, DWORD cbCertEncoded);
WINIMPM PCCERT_CONTEXT WINAPI CRYPT32$CertFindCertificateInStore (HCERTSTORE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags, DWORD dwFindType, const void *pvFindPara, PCCERT_CONTEXT pPrevCertContext);

//DNSAPI
WINBASEAPI VOID WINAPI DNSAPI$DnsFree(PVOID pData,DNS_FREE_TYPE FreeType);
WINBASEAPI int WINAPI DNSAPI$DnsGetCacheDataTable(PVOID data);

//OLE32
WINBASEAPI HRESULT WINAPI OLE32$CoInitializeEx (LPVOID pvReserved, DWORD dwCoInit);
WINBASEAPI HRESULT WINAPI OLE32$CoUninitialize (void);
WINBASEAPI HRESULT WINAPI OLE32$CoInitializeSecurity (PSECURITY_DESCRIPTOR pSecDesc, LONG cAuthSvc, SOLE_AUTHENTICATION_SERVICE *asAuthSvc, void *pReserved1, DWORD dwAuthnLevel, DWORD dwImpLevel, void *pAuthList, DWORD dwCapabilities, void *pReserved3);
WINBASEAPI HRESULT WINAPI OLE32$CoCreateInstance (REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
WINBASEAPI HRESULT WINAPI OLE32$CLSIDFromString (LPCOLESTR lpsz, LPCLSID pclsid);
WINBASEAPI HRESULT WINAPI OLE32$IIDFromString (LPCOLESTR lpsz, LPIID lpiid);
WINBASEAPI int WINAPI OLE32$StringFromGUID2 (REFGUID rguid, LPOLESTR lpsz, int cchMax);
WINBASEAPI HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown* pProxy, DWORD dwAuthnSvc, DWORD dwAuthzSvc, OLECHAR* pServerPrincName, DWORD dwAuthnLevel, DWORD dwImpLevel, RPC_AUTH_IDENTITY_HANDLE pAuthInfo, DWORD dwCapabilities);
WINBASEAPI LPVOID WINAPI OLE32$CoTaskMemAlloc(SIZE_T cb);
WINBASEAPI void WINAPI OLE32$CoTaskMemFree(LPVOID pv);

//OLEAUT32
WINBASEAPI BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR *);
WINBASEAPI INT WINAPI OLEAUT32$SysReAllocString(BSTR *, const OLECHAR *);
WINBASEAPI UINT WINAPI OLEAUT32$SysStringLen(BSTR);
WINBASEAPI BSTR WINAPI OLEAUT32$SysAllocStringByteLen(LPCSTR psz,UINT len);
WINBASEAPI UINT WINAPI OLEAUT32$SysStringByteLen(BSTR bstr);
WINBASEAPI void WINAPI OLEAUT32$SysFreeString(BSTR);
WINBASEAPI void WINAPI OLEAUT32$VariantInit(VARIANTARG *pvarg);
WINBASEAPI void WINAPI OLEAUT32$VariantClear(VARIANTARG *pvarg);
WINBASEAPI HRESULT WINAPI OLEAUT32$SysAddRefString(BSTR);
WINBASEAPI HRESULT WINAPI OLEAUT32$VariantChangeType(VARIANTARG *pvargDest, VARIANTARG *pvarSrc, USHORT wFlags, VARTYPE vt);
WINBASEAPI void WINAPI OLEAUT32$VarFormatDateTime(LPVARIANT pvarIn,int iNamedFormat,ULONG dwFlags,BSTR *pbstrOut);
WINBASEAPI void WINAPI OLEAUT32$SafeArrayDestroy(SAFEARRAY *psa);
WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayLock(SAFEARRAY *psa);
WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayGetLBound(SAFEARRAY *psa, UINT nDim, LONG *plLbound);
WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayGetUBound(SAFEARRAY *psa, UINT nDim, LONG *plUbound);
WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayGetElement(SAFEARRAY *psa, LONG *rgIndices, void *pv);
WINBASEAPI UINT WINAPI OLEAUT32$SafeArrayGetElemsize(SAFEARRAY *psa);

//DBGHELP
WINBASEAPI WINBOOL WINAPI DBGHELP$MiniDumpWriteDump(HANDLE hProcess,DWORD ProcessId,HANDLE hFile,MINIDUMP_TYPE DumpType,CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

//WLDAP32
WINLDAPAPI LDAP* LDAPAPI WLDAP32$ldap_init(PSTR, ULONG);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_bind_s(LDAP *ld,const PSTR dn,const PCHAR cred,ULONG method);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_search_s(LDAP *ld,PSTR base,ULONG scope,PSTR filter,PZPSTR attrs,ULONG attrsonly,PLDAPMessage *res);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_count_entries(LDAP*,LDAPMessage*);
WINLDAPAPI struct berval **LDAPAPI WLDAP32$ldap_get_values_lenA (LDAP *ExternalHandle,LDAPMessage *Message,const PCHAR attr);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_value_free_len(struct berval **vals);
WINLDAPAPI LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP *ld,LDAPMessage *res);
WINLDAPAPI LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP*,LDAPMessage*);
WINLDAPAPI PCHAR LDAPAPI WLDAP32$ldap_first_attribute(LDAP *ld,LDAPMessage *entry,BerElement **ptr);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_count_values(PCHAR);
WINLDAPAPI PCHAR * LDAPAPI WLDAP32$ldap_get_values(LDAP *ld,LDAPMessage *entry,const PSTR attr);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_value_free(PCHAR *);
WINLDAPAPI PCHAR LDAPAPI WLDAP32$ldap_next_attribute(LDAP *ld,LDAPMessage *entry,BerElement *ptr);
WINLDAPAPI VOID LDAPAPI WLDAP32$ber_free(BerElement *pBerElement,INT fbuf);
WINLDAPAPI VOID LDAPAPI WLDAP32$ldap_memfree(PCHAR);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP*);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_unbind_s(LDAP*);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);

//RPCRT4
RPCRTAPI RPC_STATUS RPC_ENTRY RPCRT4$UuidToStringA(UUID *Uuid,RPC_CSTR *StringUuid);
RPCRTAPI RPC_STATUS RPC_ENTRY RPCRT4$RpcStringFreeA(RPC_CSTR *String);

//PSAPI
WINBASEAPI WINBOOL WINAPI PSAPI$EnumProcesses(DWORD *lpidProcess,DWORD cb,DWORD *cbNeeded);
WINBASEAPI WINBOOL WINAPI PSAPI$EnumProcessModules(HANDLE hProcess,HMODULE *lphModule,DWORD cb,LPDWORD lpcbNeeded);
WINBASEAPI DWORD WINAPI PSAPI$GetModuleBaseNameW(HANDLE hProcess,HMODULE hModule,LPWSTR lpBaseName,DWORD nSize);

//bcrypt

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider (BCRYPT_ALG_HANDLE *phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptCreateHash (BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE *phHash, PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptHashData (BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptFinishHash (BCRYPT_HASH_HANDLE hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptDestroyHash (BCRYPT_HASH_HANDLE hHash);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider (BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);

// GDI32 
WINBASEAPI HFONT WINAPI GDI32$CreateFontW(int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight, DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet, DWORD iOutPrecision, DWORD iClipPrecision, DWORD iQuality, DWORD iPitchAndFamily, LPCWSTR pszFaceName);
WINBASEAPI BOOL WINAPI GDI32$DeleteObject(HGDIOBJ ho);
WINBASEAPI HGDIOBJ WINAPI GDI32$SelectObject(HDC hdc, HGDIOBJ h);
WINBASEAPI COLORREF WINAPI GDI32$SetTextColor(HDC hdc, COLORREF color);
WINBASEAPI COLORREF WINAPI GDI32$SetBkColor(HDC hdc, COLORREF color);
WINBASEAPI int WINAPI GDI32$SetBkMode(HDC hdc, int mode);
WINBASEAPI HBRUSH WINAPI GDI32$CreateSolidBrush(COLORREF color);

//SYSTEMFUNCTION
//https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlgenrandom
WINBASEAPI WINBOOL WINAPI ADVAPI32$SystemFunction036(PVOID RandomBuffer,ULONG RandomBufferLength);
#ifdef RtlGenRandom
#undef RtlGenRandom
#endif
#define RtlGenRandom ADVAPI32$SystemFunction036


#else
//KERNEL32
#define KERNEL32$VirtualAlloc VirtualAlloc 
#define KERNEL32$VirtualAllocEx VirtualAllocEx 
#define KERNEL32$VirtualProtectEx VirtualProtectEx 
#define KERNEL32$VirtualQueryEx VirtualQueryEx
#define KERNEL32$VirtualFree VirtualFree 
#define KERNEL32$VirtualFreeEx VirtualFreeEx 
#define KERNEL32$LocalAlloc LocalAlloc 
#define KERNEL32$LocalFree LocalFree 
#define KERNEL32$GlobalAlloc GlobalAlloc
#define KERNEL32$GlobalFree GlobalFree
#define KERNEL32$HeapAlloc HeapAlloc 
#define KERNEL32$HeapReAlloc HeapReAlloc 
#define KERNEL32$GetProcessHeap GetProcessHeap
#define KERNEL32$HeapFree HeapFree 
#define KERNEL32$FormatMessageA FormatMessageA 
#define KERNEL32$WideCharToMultiByte WideCharToMultiByte 
#define KERNEL32$MultiByteToWideChar MultiByteToWideChar 
#define KERNEL32$FileTimeToLocalFileTime FileTimeToLocalFileTime 
#define KERNEL32$FileTimeToSystemTime FileTimeToSystemTime 
#define KERNEL32$GetDateFormatW GetDateFormatW 
#define KERNEL32$GetSystemTimeAsFileTime GetSystemTimeAsFileTime 
#define KERNEL32$GetSystemInfo GetSystemInfo
#define KERNEL32$GetLastError GetLastError 
#define KERNEL32$SetLastError SetLastError 
#define KERNEL32$CloseHandle CloseHandle 
#define KERNEL32$GetTickCount GetTickCount 
#define KERNEL32$CreateFiber CreateFiber 
#define KERNEL32$ConvertThreadToFiber ConvertThreadToFiber 
#define KERNEL32$ConvertFiberToThread ConvertFiberToThread 
#define KERNEL32$DeleteFiber DeleteFiber 
#define KERNEL32$SwitchToFiber SwitchToFiber 
#define KERNEL32$WaitForSingleObject WaitForSingleObject 
#define KERNEL32$Sleep Sleep 
#define KERNEL32$CreateProcessW CreateProcessW 
#define KERNEL32$CreateProcessA CreateProcessA 
#define KERNEL32$OpenProcess OpenProcess 
#define KERNEL32$GetCurrentProcess GetCurrentProcess 
#define KERNEL32$GetCurrentThread GetCurrentThread
#define KERNEL32$GetExitCodeProcess GetExitCodeProcess 
#define KERNEL32$WriteProcessMemory WriteProcessMemory 
#define KERNEL32$ReadProcessMemory ReadProcessMemory 
#define KERNEL32$GetCurrentProcessId GetCurrentProcessId 
#define KERNEL32$GetProcessIdOfThread GetProcessIdOfThread 
#define KERNEL32$ProcessIdToSessionId ProcessIdToSessionId 
#define KERNEL32$InitializeProcThreadAttributeList InitializeProcThreadAttributeList 
#define KERNEL32$UpdateProcThreadAttribute UpdateProcThreadAttribute 
#define KERNEL32$DeleteProcThreadAttributeList DeleteProcThreadAttributeList 
#define KERNEL32$CreateThread CreateThread 
#define KERNEL32$CreateRemoteThread CreateRemoteThread 
#define KERNEL32$OpenThread OpenThread 
#define KERNEL32$GetThreadContext GetThreadContext 
#define KERNEL32$SetThreadContext SetThreadContext 
#define KERNEL32$SuspendThread SuspendThread 
#define KERNEL32$ResumeThread ResumeThread 
#define KERNEL32$GetComputerNameExW GetComputerNameExW 
#define KERNEL32$lstrcmpA lstrcmpA 
#define KERNEL32$lstrcmpW lstrcmpW 
#define KERNEL32$lstrcmpiW lstrcmpiW
#define KERNEL32$lstrlenA lstrlenA 
#define KERNEL32$lstrlenW lstrlenW 
#define KERNEL32$lstrcatW lstrcatW 
#define KERNEL32$lstrcpynW lstrcpynW 
#define KERNEL32$GetFullPathNameW GetFullPathNameW 
#define KERNEL32$GetFileAttributesW GetFileAttributesW 
#define KERNEL32$GetCurrentDirectoryW GetCurrentDirectoryW 
#define KERNEL32$FindFirstFileW FindFirstFileW 
#define KERNEL32$FindNextFileW FindNextFileW 
#define KERNEL32$FindClose FindClose 
#define KERNEL32$ExpandEnvironmentStringsW ExpandEnvironmentStringsW 
#define KERNEL32$ExpandEnvironmentStringsA ExpandEnvironmentStringsA 
#define KERNEL32$GetTempPathW GetTempPathW 
#define KERNEL32$GetTempFileNameW GetTempFileNameW 
#define KERNEL32$CreateFileW CreateFileW 
#define KERNEL32$CreateFileA CreateFileA 
#define KERNEL32$GetFileSize GetFileSize 
#define KERNEL32$ReadFile ReadFile 
#define KERNEL32$WriteFile WriteFile
#define KERNEL32$DeleteFileW DeleteFileW 
#define KERNEL32$CreateFileMappingA CreateFileMappingA 
#define KERNEL32$MapViewOfFile MapViewOfFile 
#define KERNEL32$UnmapViewOfFile UnmapViewOfFile 
#define KERNEL32$GetEnvironmentStrings GetEnvironmentStrings
#define KERNEL32$FreeEnvironmentStringsA FreeEnvironmentStringsA
#define KERNEL32$CreateToolhelp32Snapshot CreateToolhelp32Snapshot
#define KERNEL32$Process32First Process32First
#define KERNEL32$Process32Next Process32Next
#define KERNEL32$LoadLibraryA LoadLibraryA
#define KERNEL32$GetProcAddress GetProcAddress
#define KERNEL32$FreeLibrary FreeLibrary
#define KERNEL32$CloseHandle CloseHandle

//IPHLPAPI
#define IPHLPAPI$GetAdaptersInfo GetAdaptersInfo 
#define IPHLPAPI$GetAdaptersInfo GetAdaptersInfo
#define IPHLPAPI$GetIpForwardTable GetIpForwardTable 
#define IPHLPAPI$GetNetworkParams GetNetworkParams
#define IPHLPAPI$GetUdpTable GetUdpTable 
#define IPHLPAPI$GetTcpTable GetTcpTable 

//MSVCRT
#define MSVCRT$calloc calloc
#define MSVCRT$realloc realloc
#define MSVCRT$free free
#define MSVCRT$memcmp memcmp
#define MSVCRT$memcpy memcpy
#define MSVCRT$memset memset
#define MSVCRT$sprintf sprintf
#define MSVCRT$vsnprintf vsnprintf
#define MSVCRT$_stricmp _stricmp
#define MSVCRT$strchr strchr
#define MSVCRT$strcmp strcmp
#define MSVCRT$strcpy strcpy
#define MSVCRT$strlen strlen
#define MSVCRT$wcsncmp wcsncmp
#define MSVCRT$strncmp strncmp
#define MSVCRT$strnlen strnlen
#define MSVCRT$strstr strstr
#define MSVCRT$strtok strtok
#define MSVCRT$swprintf swprintf
#define MSVCRT$_swprintf _swprintf
#define MSVCRT$wcscat wcscat
#define MSVCRT$wcsncat wcsncat
#define MSVCRT$_wcsicmp _wcsicmp
#define MSVCRT$wcscpy wcscpy
#define MSVCRT$wcscpy_s wcscpy_s
#define MSVCRT$wcschr wcschr
#define MSVCRT$wcsrchr wcsrchr
#define MSVCRT$wcslen wcslen
#define MSVCRT$wcsstr wcsstr
#define MSVCRT$wcstok wcstok
#define MSVCRT$wcstoul wcstoul
#define MSVCRT$_wtol _wtol
#define MSVCRT$swprintf_s swprintf_s

//SHLWAPI
#define SHLWAPI$PathCombineW PathCombineW
#define SHLWAPI$PathFileExistsW PathFileExistsW
#define SHLWAPI$StrStrA StrStrA
#define SHELL32$ShellExecuteExW ShellExecuteExW


//WSOCK32
#define WSOCK32$inet_addr inet_addr

//WS2_32
#define WS2_32$htonl htonl
#define WS2_32$htons htons
#define WS2_32$inet_ntoa inet_ntoa
#define WS2_32$InetNtopW InetNtopW
#define WS2_32$inet_pton inet_pton

//NETAPI32
#define NETAPI32$DsGetDcNameA DsGetDcNameA
#define NETAPI32$DsGetDcNameW DsGetDcNameW
#define NETAPI32$NetUserGetInfo NetUserGetInfo
#define NETAPI32$NetUserModalsGet NetUserModalsGet
#define NETAPI32$NetServerEnum NetServerEnum
#define NETAPI32$NetUserGetGroups NetUserGetGroups
#define NETAPI32$NetUserGetLocalGroups NetUserGetLocalGroups
#define NETAPI32$NetApiBufferFree NetApiBufferFree
#define NETAPI32$NetGetAnyDCName NetGetAnyDCName
#define NETAPI32$NetUserEnum NetUserEnum
#define NETAPI32$NetGroupGetUsers NetGroupGetUsers
#define NETAPI32$NetQueryDisplayInformation NetQueryDisplayInformation
#define NETAPI32$NetLocalGroupEnum NetLocalGroupEnum
#define NETAPI32$NetLocalGroupGetMembers NetLocalGroupGetMembers
#define NETAPI32$NetUserSetInfo NetUserSetInfo
#define NETAPI32$NetShareEnum NetShareEnum
#define NETAPI32$NetSessionEnum NetSessionEnum
#define NETAPI32$NetApiBufferFree NetApiBufferFree
#define NETAPI32$NetGroupAddUser NetGroupAddUser
#define NETAPI32$NetUserAdd NetUserAdd

//MPR
#define MPR$WNetOpenEnumW WNetOpenEnumW
#define MPR$WNetEnumResourceW WNetEnumResourceW
#define MPR$WNetCloseEnum WNetCloseEnum
#define MPR$WNetGetNetworkInformationW WNetGetNetworkInformationW
#define MPR$WNetGetConnectionW WNetGetConnectionW
#define MPR$WNetGetResourceInformationW WNetGetResourceInformationW
#define MPR$WNetGetUserW WNetGetUserW
#define MPR$WNetAddConnection2W WNetAddConnection2W
#define MPR$WNetCancelConnection2W WNetCancelConnection2W

//USER32
#define USER32$CharPrevW CharPrevW
#define USER32$DdeInitializeA DdeInitializeA
#define USER32$DdeConnectList DdeConnectList
#define USER32$DdeDisconnectList DdeDisconnectList
#define USER32$DdeUninitialize DdeUninitialize
#define USER32$EnumDesktopWindows EnumDesktopWindows
#define USER32$EnumWindows EnumWindows
#define USER32$FindWindowA FindWindowA
#define USER32$FindWindowExA FindWindowExA
#define USER32$GetClassNameA GetClassNameA
#define USER32$GetPropA GetPropA
#define USER32$GetWindowThreadProcessId GetWindowThreadProcessId
#define USER32$GetWindowTextA GetWindowTextA
#define USER32$GetWindowLongA GetWindowLongA
#define USER32$GetWindowLongPtrA GetWindowLongPtrA
#define USER32$IsWindowVisible IsWindowVisible 
#define USER32$PostMessageA PostMessageA
#define USER32$SendMessageA SendMessageA
#define USER32$SetPropA SetPropA
#define USER32$SetWindowLongA SetWindowLongA
#define USER32$SetWindowLongPtrA SetWindowLongPtrA
#define USER32$KillTimer KillTimer
#define USER32$SetTimer SetTimer
#define USER32$PostMessageW PostMessageW
#define USER32$BeginPaint BeginPaint
#define USER32$GetClientRect GetClientRect
#define USER32$FillRect FillRect
#define USER32$DrawTextW DrawTextW
#define USER32$EndPaint EndPaint
#define USER32$DestroyWindow DestroyWindow
#define USER32$PostQuitMessage PostQuitMessage
#define USER32$DefWindowProcW DefWindowProcW
#define USER32$DispatchMessageW DispatchMessageW
#define USER32$TranslateMessage TranslateMessage
#define USER32$GetMessageW GetMessageW
#define USER32$SetFocus SetFocus
#define USER32$RegisterClassExW RegisterClassExW
#define USER32$SetForegroundWindow SetForegroundWindow
#define USER32$UpdateWindow UpdateWindow
#define USER32$ShowWindow ShowWindow
#define USER32$UnregisterClassW UnregisterClassW
#define USER32$CreateWindowExW CreateWindowExW
#define USER32$GetSystemMetrics GetSystemMetrics

//SSPICLI
#define SSPICLI$EnumerateSecurityPackagesA EnumerateSecurityPackagesA
#define SSPICLI$FreeContextBuffer FreeContextBuffer

//SECUR32
#define SECUR32$GetUserNameExA GetUserNameExA 
#define SECUR32$GetUserNameExW GetUserNameExW 
#define SECUR32$GetComputerObjectNameW GetComputerObjectNameW 
#define SECUR32$FreeCredentialsHandle FreeCredentialsHandle
#define SECUR32$AcquireCredentialsHandleA AcquireCredentialsHandleA
#define SECUR32$InitializeSecurityContextA InitializeSecurityContextA
#define SECUR32$InitializeSecurityContextW InitializeSecurityContextW
#define SECUR32$AcceptSecurityContext AcceptSecurityContext
#define SECUR32$DeleteSecurityContext DeleteSecurityContext
#define SECUR32$AcquireCredentialsHandleA AcquireCredentialsHandleA
#define SECUR32$AcceptSecurityContext AcceptSecurityContext
#define SECUR32$LsaConnectUntrusted LsaConnectUntrusted
#define SECUR32$LsaDeregisterLogonProcess LsaDeregisterLogonProcess
#define SECUR32$LsaFreeReturnBuffer LsaFreeReturnBuffer 
#define SECUR32$LsaLookupAuthenticationPackage LsaLookupAuthenticationPackage
#define SECUR32$LsaCallAuthenticationPackage LsaCallAuthenticationPackage

//VERSION
#define VERSION$GetFileVersionInfoA GetFileVersionInfoA
#define VERSION$GetFileVersionInfoW GetFileVersionInfoW
#define VERSION$GetFileVersionInfoSizeA GetFileVersionInfoSizeA
#define VERSION$GetFileVersionInfoSizeW GetFileVersionInfoSizeW
#define VERSION$VerQueryValueA VerQueryValueA
#define VERSION$VerQueryValueW VerQueryValueW

//ADVAPI32
#define ADVAPI32$LogonUserA LogonUserA 
#define ADVAPI32$LogonUserW LogonUserW 
#define ADVAPI32$DuplicateTokenEx DuplicateTokenEx 
#define ADVAPI32$AdjustTokenPrivileges AdjustTokenPrivileges 
#define ADVAPI32$CreateProcessAsUserW CreateProcessAsUserW 
#define ADVAPI32$CreateProcessWithLogonW CreateProcessWithLogonW 
#define ADVAPI32$CreateProcessWithTokenW CreateProcessWithTokenW 
#define ADVAPI32$OpenProcessToken OpenProcessToken 
#define ADVAPI32$OpenThreadToken OpenThreadToken 
#define ADVAPI32$GetTokenInformation GetTokenInformation 
#define ADVAPI32$ConvertSidToStringSidA ConvertSidToStringSidA
#define ADVAPI32$ConvertSidToStringSidW ConvertSidToStringSidW
#define ADVAPI32$LookupAccountSidA LookupAccountSidA 
#define ADVAPI32$LookupAccountSidW LookupAccountSidW 
#define ADVAPI32$LookupPrivilegeNameA LookupPrivilegeNameA 
#define ADVAPI32$LookupPrivilegeDisplayNameA LookupPrivilegeDisplayNameA 
#define ADVAPI32$LookupPrivilegeValueA LookupPrivilegeValueA 
#define ADVAPI32$GetFileSecurityW GetFileSecurityW 
#define ADVAPI32$MapGenericMask MapGenericMask 
#define ADVAPI32$LsaNtStatusToWinError LsaNtStatusToWinError
#define ADVAPI32$InitializeSecurityDescriptor InitializeSecurityDescriptor 
#define ADVAPI32$GetSecurityDescriptorOwner GetSecurityDescriptorOwner
#define ADVAPI32$SetSecurityDescriptorDacl SetSecurityDescriptorDacl 
#define ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorW ConvertSecurityDescriptorToStringSecurityDescriptorW
#define ADVAPI32$GetSecurityDescriptorDacl GetSecurityDescriptorDacl 
#define ADVAPI32$GetAclInformation GetAclInformation 
#define ADVAPI32$GetAce GetAce 
#define ADVAPI32$OpenSCManagerA OpenSCManagerA
#define ADVAPI32$OpenSCManagerW OpenSCManagerW
#define ADVAPI32$OpenServiceA OpenServiceA
#define ADVAPI32$OpenServiceW OpenServiceW
#define ADVAPI32$CreateServiceA CreateServiceA
#define ADVAPI32$QueryServiceStatus QueryServiceStatus
#define ADVAPI32$QueryServiceConfigA QueryServiceConfigA
#define ADVAPI32$CloseServiceHandle CloseServiceHandle
#define ADVAPI32$EnumServicesStatusExA EnumServicesStatusExA
#define ADVAPI32$EnumServicesStatusExW EnumServicesStatusExW
#define ADVAPI32$EnumDependentServicesA EnumDependentServicesA
#define ADVAPI32$QueryServiceStatusEx QueryServiceStatusEx
#define ADVAPI32$QueryServiceConfig2A QueryServiceConfig2A
#define ADVAPI32$ChangeServiceConfig2A ChangeServiceConfig2A
#define ADVAPI32$ChangeServiceConfigA ChangeServiceConfigA
#define ADVAPI32$StartServiceA StartServiceA
#define ADVAPI32$ControlService ControlService
#define ADVAPI32$DeleteService DeleteService
#define ADVAPI32$RegCloseKey RegCloseKey
#define ADVAPI32$RegConnectRegistryA RegConnectRegistryA
#define ADVAPI32$RegCopyTreeA RegCopyTreeA
#define ADVAPI32$RegCreateKeyA RegCreateKeyA
#define ADVAPI32$RegCreateKeyExA RegCreateKeyExA
#define ADVAPI32$RegCreateKeyExW RegCreateKeyExW
#define ADVAPI32$RegDeleteKeyExA RegDeleteKeyExA
#define ADVAPI32$RegDeleteKeyExW RegDeleteKeyExW
#define ADVAPI32$RegDeleteKeyValueA RegDeleteKeyValueA
#define ADVAPI32$RegDeleteKeyValueW RegDeleteKeyValueW
#define ADVAPI32$RegDeleteTreeA RegDeleteTreeA
#define ADVAPI32$RegDeleteTreeW RegDeleteTreeW
#define ADVAPI32$RegDeleteValueA RegDeleteValueA
#define ADVAPI32$RegDeleteValueW RegDeleteValueW
#define ADVAPI32$RegEnumValueA RegEnumValueA
#define ADVAPI32$RegEnumKeyExA RegEnumKeyExA
#define ADVAPI32$RegOpenKeyA RegOpenKeyA
#define ADVAPI32$RegOpenKeyExA RegOpenKeyExA
#define ADVAPI32$RegOpenKeyExW RegOpenKeyExW
#define ADVAPI32$RegQueryInfoKeyA RegQueryInfoKeyA
#define ADVAPI32$RegQueryValueExA RegQueryValueExA
#define ADVAPI32$RegQueryValueExW RegQueryValueExW
#define ADVAPI32$RegSaveKeyExA RegSaveKeyExA
#define ADVAPI32$RegSetValueExA RegSetValueExA
#define ADVAPI32$RegSetValueExW RegSetValueExW
#define ADVAPI32$InitiateSystemShutdownExA InitiateSystemShutdownExA

//NTDLL
#define NTDLL$NtCreateFile NtCreateFile
#define NTDLL$NtClose NtClose
#define NTDLL$NtRenameKey NtRenameKey
#define NTDLL$NtQueueApcThread NtQueueApcThread

//IMAGEHLP
#define IMAGEHLP$ImageEnumerateCertificates ImageEnumerateCertificates
#define IMAGEHLP$ImageGetCertificateHeader ImageGetCertificateHeader
#define IMAGEHLP$ImageGetCertificateData ImageGetCertificateData

//CRYPT32
#define CRYPT32$CryptVerifyMessageSignature CryptVerifyMessageSignature 
#define CRYPT32$CertGetNameStringW CertGetNameStringW 
#define CRYPT32$CertFreeCertificateContext CertFreeCertificateContext 
#define CRYPT32$CryptUnprotectData CryptUnprotectData
#define CRYPT32$CryptEncodeObjectEx CryptEncodeObjectEx
#define CRYPT32$CryptBinaryToStringW CryptBinaryToStringW

//DNSAPI
#define DNSAPI$DnsQuery_A DnsQuery_A
#define DNSAPI$DnsFree DnsFree
#define DNSAPI$DnsGetCacheDataTable DnsGetCacheDataTable

//OLE32
#define OLE32$CoInitializeEx CoInitializeEx 
#define OLE32$CoUninitialize CoUninitialize 
#define OLE32$CoInitializeSecurity CoInitializeSecurity 
#define OLE32$CoCreateInstance CoCreateInstance 
#define OLE32$CLSIDFromString CLSIDFromString 
#define OLE32$IIDFromString IIDFromString 
#define OLE32$StringFromGUID2 StringFromGUID2
#define OLE32$CoSetProxyBlanket CoSetProxyBlanket
#define OLE32$CoTaskMemAlloc CoTaskMemAlloc
#define OLE32$CoTaskMemFree CoTaskMemFree

//OLEAUT32
#define OLEAUT32$SysAllocString SysAllocString
#define OLEAUT32$SysReAllocString SysReAllocString
#define OLEAUT32$SysFreeString SysFreeString
#define OLEAUT32$SysStringLen SysStringLen
#define OLEAUT32$VariantInit VariantInit
#define OLEAUT32$VariantClear VariantClear
#define OLEAUT32$SysAddRefString SysAddRefString
#define OLEAUT32$VariantChangeType VariantChangeType
#define OLEAUT32$VarFormatDateTime VarFormatDateTime
#define OLEAUT32$SafeArrayDestroy SafeArrayDestroy
#define OLEAUT32$SafeArrayLock SafeArrayLock
#define OLEAUT32$SafeArrayGetLBound SafeArrayGetLBound
#define OLEAUT32$SafeArrayGetUBound SafeArrayGetUBound
#define OLEAUT32$SafeArrayGetElement SafeArrayGetElement
#define OLEAUT32$SafeArrayGetElemsize SafeArrayGetElemsize

//DBGHELP
#define DBGHELP$MiniDumpWriteDump MiniDumpWriteDump

//WLDAP32
#define WLDAP32$ldap_init ldap_init
#define WLDAP32$ldap_bind_s ldap_bind_s
#define WLDAP32$ldap_search_s ldap_search_s
#define WLDAP32$ldap_count_entries ldap_count_entries
#define WLDAP32$ldap_get_values_lenA ldap_get_values_lenA 
#define WLDAP32$ldap_value_free_len ldap_value_free_len
#define WLDAP32$ldap_first_entry ldap_first_entry
#define WLDAP32$ldap_next_entry ldap_next_entry
#define WLDAP32$ldap_first_attribute ldap_first_attribute
#define WLDAP32$ldap_count_values ldap_count_values
#define WLDAP32$ldap_get_values ldap_get_values
#define WLDAP32$ldap_value_free ldap_value_free
#define WLDAP32$ldap_next_attribute ldap_next_attribute
#define WLDAP32$ber_free ber_free
#define WLDAP32$ldap_memfree ldap_memfree
#define WLDAP32$ldap_unbind ldap_unbind
#define WLDAP32$ldap_unbind_s ldap_unbind_s
#define WLDAP32$ldap_msgfree ldap_msgfree

//RPCRT4
#define RPCRT4$UuidToStringA UuidToStringA
#define RPCRT4$RpcStringFreeA RpcStringFreeA

//PSAPI
#define PSAPI$EnumProcesses EnumProcesses
#define PSAPI$EnumProcessModules EnumProcessModules
#define PSAPI$GetModuleBaseNameW GetModuleBaseNameW

// GDI32
#define GDI32$CreateFontW CreateFontW
#define GDI32$DeleteObject DeleteObject
#define GDI32$SelectObject SelectObject
#define GDI32$SetTextColor SetTextColor
#define GDI32$SetBkColor SetBkColor
#define GDI32$SetBkMode SetBkMode
#define GDI32$CreateSolidBrush CreateSolidBrush

//BEACON
#define BeaconPrintf(x, y, ...) printf(y, ##__VA_ARGS__)
#define internal_printf printf
#endif
