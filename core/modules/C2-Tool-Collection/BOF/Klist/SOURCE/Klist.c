#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE
#define SECURITY_WIN32

#include <windows.h>
#include <ntsecapi.h>
#include <security.h> 

#include "Klist.h"
#include "beacon.h"

#define MAX_MSG_SIZE 256
#define SEC_SUCCESS(Status) ((Status) >= 0) 

INT iGarbage = 1;
LPSTREAM lpStream = (LPSTREAM)1;

HRESULT BeaconPrintToStreamW(_In_z_ LPCWSTR lpwFormat, ...) {
	HRESULT hr = S_OK;
	va_list argList;
	WCHAR chBuffer[1024];
	DWORD dwWritten = 0;

	if (lpStream <= (LPSTREAM)1) {
		hr = OLE32$CreateStreamOnHGlobal(NULL, TRUE, &lpStream);
		if (FAILED(hr)) {
			return hr;
		}
	}

	va_start(argList, lpwFormat);
	MSVCRT$memset(chBuffer, 0, sizeof(chBuffer));
	if (!MSVCRT$_vsnwprintf_s(chBuffer, _countof(chBuffer), _TRUNCATE, lpwFormat, argList)) {
		hr = E_FAIL;
		goto CleanUp;
	}

	if (FAILED(hr = lpStream->lpVtbl->Write(lpStream, chBuffer, (ULONG)MSVCRT$wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
		goto CleanUp;
	}

CleanUp:

	va_end(argList);
	return hr;
}

VOID BeaconOutputStreamW() {
	STATSTG ssStreamData = { 0 };
	SIZE_T cbSize = 0;
	ULONG cbRead = 0;
	LARGE_INTEGER pos;
	LPWSTR lpwOutput = NULL;

	if (FAILED(lpStream->lpVtbl->Stat(lpStream, &ssStreamData, STATFLAG_NONAME))) {
		return;
	}

	cbSize = ssStreamData.cbSize.LowPart;
	lpwOutput = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize + 1);
	if (lpwOutput != NULL) {
		pos.QuadPart = 0;
		if (FAILED(lpStream->lpVtbl->Seek(lpStream, pos, STREAM_SEEK_SET, NULL))) {
			goto CleanUp;
		}

		if (FAILED(lpStream->lpVtbl->Read(lpStream, lpwOutput, (ULONG)cbSize, &cbRead))) {		
			goto CleanUp;
		}

		BeaconPrintf(CALLBACK_OUTPUT, "%ls", lpwOutput);
	}

CleanUp:

	if (lpStream != NULL) {
		lpStream->lpVtbl->Release(lpStream);
		lpStream = NULL;
	}

	if (lpwOutput != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpwOutput);
	}

	return;
}

VOID ShowLastError(LPCWSTR szAPI, DWORD dwError) {
	WCHAR szMsgBuf[MAX_MSG_SIZE];
	DWORD dwRes;

	BeaconPrintf(CALLBACK_ERROR, "Error calling function %ls: %lu\n", szAPI, dwError);

	MSVCRT$memset(&szMsgBuf, 0, MAX_MSG_SIZE);
	dwRes = KERNEL32$FormatMessageW(
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		dwError,
		MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
		szMsgBuf,
		MAX_MSG_SIZE,
		NULL);
	if (0 == dwRes) {
		BeaconPrintf(CALLBACK_ERROR, "FormatMessage failed with %d\n", KERNEL32$GetLastError());
		return;
	}

	BeaconPrintf(CALLBACK_ERROR, "%ls", szMsgBuf);
}

VOID ShowNTError(LPCWSTR szAPI, NTSTATUS Status) {
	ShowLastError(szAPI, ADVAPI32$LsaNtStatusToWinError(Status));
}

VOID PrintKerbName(PKERB_EXTERNAL_NAME Name) {
	ULONG Index = 0;
	
	for (Index = 0; Index < Name->NameCount ; Index++ ) {
		BeaconPrintToStreamW(L"%wZ",&Name->Names[Index]);
		if ((Index+1) < Name->NameCount){
			BeaconPrintToStreamW(L"/");
		}
	}

	BeaconPrintToStreamW(L"\n");
}

VOID PrintTime(LPCWSTR Comment, TimeStamp ConvertTime) {
	BeaconPrintToStreamW(L"%ls", Comment);

	if (ConvertTime.HighPart == 0x7FFFFFFF && ConvertTime.LowPart == 0xFFFFFFFF) {
		BeaconPrintToStreamW(L"Infinite\n");
	}
	else {
		SYSTEMTIME SystemTime;
		FILETIME LocalFileTime;

		if (KERNEL32$FileTimeToLocalFileTime((PFILETIME)&ConvertTime, &LocalFileTime) && KERNEL32$FileTimeToSystemTime(&LocalFileTime, &SystemTime)) {
		   BeaconPrintToStreamW(L"%ld/%ld/%ld %ld:%2.2ld:%2.2ld\n",
				SystemTime.wMonth,
				SystemTime.wDay,
				SystemTime.wYear,
				SystemTime.wHour,
				SystemTime.wMinute,
				SystemTime.wSecond);
		}
		else {
#ifdef _WIN64
			BeaconPrintToStreamW(L"%ld\n", (long)(ConvertTime.QuadPart / (10 * 1000 * 1000)));
#else
			// long long division in gcc results in _divdi3 function. So we need a long division
			BeaconPrintToStreamW(L"%ld\n", (long)((long)(ConvertTime.QuadPart >> 7) / 78125));  // (10 * 1000 * 1000) == 2^7 x 5^7
#endif
		}
	}
}

VOID PrintEType(int etype, BOOL bSession) {
	ETYPE etypes[] = {
		(ETYPE)AddEtype(KERB_ETYPE_NULL),
		(ETYPE)AddEtype(KERB_ETYPE_DES_CBC_CRC),
		(ETYPE)AddEtype(KERB_ETYPE_DES_CBC_MD4),
		(ETYPE)AddEtype(KERB_ETYPE_DES_CBC_MD5),
		(ETYPE)AddEtype(KERB_ETYPE_AES128_CTS_HMAC_SHA1_96),
		(ETYPE)AddEtype(KERB_ETYPE_AES256_CTS_HMAC_SHA1_96),
		(ETYPE)AddEtype(KERB_ETYPE_DES_PLAIN),
		(ETYPE)AddEtype(KERB_ETYPE_RC4_MD4),
		(ETYPE)AddEtype(KERB_ETYPE_RC4_PLAIN2),
		(ETYPE)AddEtype(KERB_ETYPE_RC4_LM),
		(ETYPE)AddEtype(KERB_ETYPE_RC4_SHA),
		(ETYPE)AddEtype(KERB_ETYPE_DES_PLAIN),
		(ETYPE)AddEtype(KERB_ETYPE_RC4_HMAC_OLD),
		(ETYPE)AddEtype(KERB_ETYPE_RC4_PLAIN_OLD),
		(ETYPE)AddEtype(KERB_ETYPE_RC4_HMAC_OLD_EXP),
		(ETYPE)AddEtype(KERB_ETYPE_RC4_PLAIN_OLD_EXP),
		(ETYPE)AddEtype(KERB_ETYPE_RC4_PLAIN),
		(ETYPE)AddEtype(KERB_ETYPE_RC4_PLAIN_EXP),
		(ETYPE)AddEtype(KERB_ETYPE_DSA_SIGN),
		(ETYPE)AddEtype(KERB_ETYPE_RSA_PRIV),
		(ETYPE)AddEtype(KERB_ETYPE_RSA_PUB),
		(ETYPE)AddEtype(KERB_ETYPE_RSA_PUB_MD5),
		(ETYPE)AddEtype(KERB_ETYPE_RSA_PUB_SHA1),
		(ETYPE)AddEtype(KERB_ETYPE_PKCS7_PUB),
		(ETYPE)AddEtype(KERB_ETYPE_DES_CBC_MD5_NT),
		(ETYPE)AddEtype(KERB_ETYPE_RC4_HMAC_NT),
		(ETYPE)AddEtype(KERB_ETYPE_RC4_HMAC_NT_EXP),
		(ETYPE){-1, NULL}
	};

	for (DWORD i = 0; etypes[i].ename != NULL; i++) {
		if (etype == etypes[i].etype) {
			LPWSTR lpwEtype = (LPWSTR)etypes[i].ename + 11;
			if (!bSession) {
				BeaconPrintToStreamW(L"\tKerbTicket Encryption Type: (%d) %ls\n", etype, lpwEtype);
			}
			else {
				BeaconPrintToStreamW(L"\tSession Key Type: (%d) %ls\n", etype, lpwEtype);
			}
			return;
		}
	}

	if (!bSession) {
		BeaconPrintToStreamW(L"\tKerbTicket Encryption Type: %d\n", etype);
	}
	else {
		BeaconPrintToStreamW(L"\tSession Key Type: %d\n", etype);
	}
}

VOID PrintCacheFlags(ULONG flags) {
	BeaconPrintToStreamW(L"\tCache Flags: ");

	if (flags & 1) {
		BeaconPrintToStreamW(L"0x%x -> PRIMARY\n", flags);
	}
	else if (flags & 2) {
		BeaconPrintToStreamW(L"0x%x -> DELEGATION\n", flags);
	}
	else if (flags & 4) {
		BeaconPrintToStreamW(L"0x%x -> S4U\n", flags);
	}
	else if (flags & 8) {
		BeaconPrintToStreamW(L"0x%x -> ASC\n", flags);
	}
	else if (flags & 0x10) {
		BeaconPrintToStreamW(L"0x%x -> ENC-IN-SKEY\n", flags);
	}
	else if (flags & 0x20) {
		BeaconPrintToStreamW(L"0x%x -> X509\n", flags);
	}
	else if (flags & 0x40) {
		BeaconPrintToStreamW(L"0x%x -> FAST\n", flags);
	}
	else {
		BeaconPrintToStreamW(L"%#x\n", flags);
	}
}

VOID PrintTktFlags(ULONG flags) {
	if (flags & KERB_TICKET_FLAGS_reserved) {
		BeaconPrintToStreamW(L"reserved ");
	}
	if (flags & KERB_TICKET_FLAGS_forwardable) {
		BeaconPrintToStreamW(L"forwardable ");
	}
	if (flags & KERB_TICKET_FLAGS_forwarded) {
		BeaconPrintToStreamW(L"forwarded ");
	}
	if (flags & KERB_TICKET_FLAGS_proxiable) {
		BeaconPrintToStreamW(L"proxiable ");
	}
	if (flags & KERB_TICKET_FLAGS_proxy) {
		BeaconPrintToStreamW(L"proxy ");
	}
	if (flags & KERB_TICKET_FLAGS_may_postdate) {
		BeaconPrintToStreamW(L"may_postdate ");
	}
	if (flags & KERB_TICKET_FLAGS_postdated) {
		BeaconPrintToStreamW(L"postdated ");
	}
	if (flags & KERB_TICKET_FLAGS_invalid) {
		BeaconPrintToStreamW(L"invalid ");
	}
	if (flags & KERB_TICKET_FLAGS_renewable) {
		BeaconPrintToStreamW(L"renewable ");
	}
	if (flags & KERB_TICKET_FLAGS_initial) {
		BeaconPrintToStreamW(L"initial ");
	}
	if (flags & KERB_TICKET_FLAGS_pre_authent) {
		BeaconPrintToStreamW(L"pre_authent ");
	}
	if (flags & KERB_TICKET_FLAGS_hw_authent) {
		BeaconPrintToStreamW(L"hw_authent ");
	}
	if (flags & KERB_TICKET_FLAGS_ok_as_delegate) {
		BeaconPrintToStreamW(L"ok_as_delegate ");
	}
	if (flags & KERB_TICKET_FLAGS_name_canonicalize) {
		BeaconPrintToStreamW(L"name_canonicalize ");
	}
	BeaconPrintToStreamW(L"\n");
}

BOOL PurgeTickets(HANDLE LogonHandle, ULONG PackageId) {
	NTSTATUS Status, SubStatus;
	PVOID Response;
	ULONG ResponseSize;

	KERB_PURGE_TKT_CACHE_REQUEST kerbPurgeRequest = { KerbPurgeTicketCacheMessage, {0, 0}, {0, 0, NULL}, {0, 0, NULL} };
	Status = SECUR32$LsaCallAuthenticationPackage(
		LogonHandle,
		PackageId,
		&kerbPurgeRequest, 
		sizeof(KERB_PURGE_TKT_CACHE_REQUEST),
		&Response,
		&ResponseSize,
		&SubStatus
	);

	if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(SubStatus)) {
		ShowNTError(L"LsaCallAuthenticationPackage", Status);
		BeaconPrintf(CALLBACK_ERROR, "Substatus: 0x%x\n", SubStatus);
		return FALSE;
	}

	return TRUE;
}

BOOL ShowTickets(HANDLE LogonHandle, ULONG PackageId, BOOL bPurge) {
	NTSTATUS Status;
	KERB_QUERY_TKT_CACHE_REQUEST CacheRequest;
	//PKERB_QUERY_TKT_CACHE_EX2_RESPONSE CacheResponse = NULL;
	PKERB_QUERY_TKT_CACHE_EX3_RESPONSE_BOF CacheResponse = NULL;
	ULONG ResponseSize;
	NTSTATUS SubStatus;
	ULONG Index;

	CacheRequest.MessageType = KerbQueryTicketCacheEx3MessageBof;
	//CacheRequest.MessageType = KerbQueryTicketCacheEx2Message;
	CacheRequest.LogonId.LowPart = 0;
	CacheRequest.LogonId.HighPart = 0;

	HINSTANCE hModule = LoadLibraryA("Secur32.dll");
	if (hModule == NULL) {
		return FALSE;
	}

	Status = SECUR32$LsaCallAuthenticationPackage(
		LogonHandle,
		PackageId,
		&CacheRequest,
		sizeof(CacheRequest),
		(PVOID*)&CacheResponse,
		&ResponseSize,
		&SubStatus
	);
	if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(SubStatus)) {
		ShowNTError(L"LsaCallAuthenticationPackage", Status);
		BeaconPrintf(CALLBACK_ERROR, "Substatus: 0x%x\n", SubStatus);
		return FALSE;
	}

	BeaconPrintToStreamW(L"\nCached Tickets: (%lu)\n\n", CacheResponse->CountOfTickets);
	for (Index = 0; Index < CacheResponse->CountOfTickets; Index++) {
		BeaconPrintToStreamW(L"#%d>\tClient: %wZ @ %wZ\n", Index, &CacheResponse->Tickets[Index].ClientName, &CacheResponse->Tickets[Index].ClientRealm);
		BeaconPrintToStreamW(L"\tServer: %wZ @ %wZ\n", &CacheResponse->Tickets[Index].ServerName, &CacheResponse->Tickets[Index].ServerRealm);
		PrintEType(CacheResponse->Tickets[Index].EncryptionType, FALSE);
		BeaconPrintToStreamW(L"\tTicket Flags: 0x%x -> ", CacheResponse->Tickets[Index].TicketFlags);
		PrintTktFlags(CacheResponse->Tickets[Index].TicketFlags);
		PrintTime(L"\tStart Time: ", CacheResponse->Tickets[Index].StartTime);
		PrintTime(L"\tEnd Time:   ", CacheResponse->Tickets[Index].EndTime);
		PrintTime(L"\tRenew Time: ", CacheResponse->Tickets[Index].RenewTime);
		PrintEType(CacheResponse->Tickets[Index].SessionKeyType, TRUE);
		PrintCacheFlags(CacheResponse->Tickets[Index].CacheFlags);
		BeaconPrintToStreamW(L"\tKdc Called: %wZ\n", &CacheResponse->Tickets[Index].KdcCalled);
		BeaconPrintToStreamW(L"\r\n");
	}

	if (bPurge) {
		if (CacheResponse->CountOfTickets > 0) {
			if (PurgeTickets(LogonHandle, PackageId)) {
				BeaconPrintToStreamW(L"Ticket(s) purged!\n");
			}
		}
	}

	if (CacheResponse != NULL) {
		SECUR32$LsaFreeReturnBuffer(CacheResponse);
	}

	//Print final Output
	BeaconOutputStreamW();
	return TRUE;
}

BOOL PackageConnectLookup(HANDLE* pLogonHandle, ULONG* pPackageId) {
	LSA_STRING Name;
	NTSTATUS Status;

	Status = SECUR32$LsaConnectUntrusted(pLogonHandle);
	if (!SEC_SUCCESS(Status)) {
		ShowNTError(L"LsaConnectUntrusted", Status);
		return FALSE;
	}

	Name.Buffer = (PCHAR)MICROSOFT_KERBEROS_NAME_A;
	Name.Length = (USHORT)MSVCRT$strlen(Name.Buffer);
	Name.MaximumLength = Name.Length + 1;

	Status = SECUR32$LsaLookupAuthenticationPackage(*pLogonHandle,&Name, pPackageId);
	if (!SEC_SUCCESS(Status)) {
		ShowNTError(L"LsaLookupAuthenticationPackage", Status);
		return FALSE;
	}

	return TRUE;
}

BOOL GetEncodedTicket(HANDLE LogonHandle, ULONG PackageId, LPCWSTR lpwTargetSpn) {
	NTSTATUS Status;
	NTSTATUS SubStatus;
	PKERB_RETRIEVE_TKT_REQUEST CacheRequest = NULL;
	PKERB_RETRIEVE_TKT_RESPONSE CacheResponse = NULL;
	PKERB_EXTERNAL_TICKET Ticket = NULL;
	ULONG ResponseSize = 0;
	BOOLEAN bTrusted = TRUE;
	BOOLEAN bSuccess = FALSE;
	UNICODE_STRING uTarget = { 0 }; 
	UNICODE_STRING uTarget2 = { 0 };

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "GetProcAddress failed.");
		return FALSE;
	}

	RtlInitUnicodeString(&uTarget2, lpwTargetSpn);

	CacheRequest = (PKERB_RETRIEVE_TKT_REQUEST)
		KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, uTarget2.Length + sizeof(KERB_RETRIEVE_TKT_REQUEST));

	CacheRequest->MessageType = KerbRetrieveEncodedTicketMessage;
	CacheRequest->LogonId.LowPart = 0;
	CacheRequest->LogonId.HighPart = 0;

	uTarget.Buffer = (LPWSTR)(CacheRequest + 1);
	uTarget.Length = uTarget2.Length;
	uTarget.MaximumLength = uTarget2.MaximumLength;

	MSVCRT$wcscpy_s(uTarget.Buffer, uTarget2.Length, uTarget2.Buffer);

	CacheRequest->TargetName = uTarget;

	Status = SECUR32$LsaCallAuthenticationPackage(
		LogonHandle,
		PackageId,
		CacheRequest,
		uTarget2.Length + sizeof(KERB_RETRIEVE_TKT_REQUEST),
		(PVOID*)&CacheResponse,
		&ResponseSize,
		&SubStatus
		);

	if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(SubStatus)) {
		ShowNTError(L"LsaCallAuthenticationPackage", Status);
		BeaconPrintf(CALLBACK_ERROR, "Substatus: 0x%x\n", SubStatus);
		ShowNTError(L"Substatus:", SubStatus);
	}
	else{
		Ticket = &(CacheResponse->Ticket);
		BeaconPrintToStreamW(L"\nEncoded Ticket:\n\n");
		BeaconPrintToStreamW(L"#0>\tServiceName: "); PrintKerbName(Ticket->ServiceName);
		BeaconPrintToStreamW(L"\tTargetName: "); PrintKerbName(Ticket->TargetName);
		BeaconPrintToStreamW(L"\tClientName: "); PrintKerbName(Ticket->ClientName);
		
		BeaconPrintToStreamW(L"\tDomainName: %wZ\n", &Ticket->DomainName);
		BeaconPrintToStreamW(L"\tTargetDomainName: %wZ\n", &Ticket->TargetDomainName);
		BeaconPrintToStreamW(L"\tAltTargetDomainName: %wZ\n", &Ticket->AltTargetDomainName);

		BeaconPrintToStreamW(L"\tTicketFlags: (0x%x) ", Ticket->TicketFlags);
		PrintTktFlags(Ticket->TicketFlags);
		PrintTime(L"\tKeyExpirationTime: ", Ticket->KeyExpirationTime);
		PrintTime(L"\tStartTime: ", Ticket->StartTime);
		PrintTime(L"\tEndTime: ", Ticket->EndTime);
		PrintTime(L"\tRenewUntil: ", Ticket->RenewUntil);
		PrintTime(L"\tTimeSkew: ", Ticket->TimeSkew);
		PrintEType(Ticket->SessionKey.KeyType, FALSE);

		bSuccess = TRUE;
		BeaconPrintToStreamW(L"\nA ticket to %ls has been retrieved successfully.\n", lpwTargetSpn);

		//Print final Output
		BeaconOutputStreamW();
	}

	if (CacheResponse != NULL) {
		SECUR32$LsaFreeReturnBuffer(CacheResponse);
	}
	
	if (CacheRequest != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, CacheRequest);
	}

	return bSuccess;
}

VOID go(IN PCHAR Args, IN ULONG Length) {
	HANDLE LogonHandle = NULL;
	ULONG PackageId;
	LPCWSTR lpwCommand = NULL;
	LPCWSTR lpwTargetSpn = NULL;
	BOOL bGetTicket = FALSE;
	BOOL bPurge = FALSE;

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);

	lpwCommand = (WCHAR*)BeaconDataExtract(&parser, NULL);
	if (MSVCRT$_wcsicmp(lpwCommand, L"purge") == 0) {
		bPurge = TRUE;
	}
	else if (MSVCRT$_wcsicmp(lpwCommand, L"get") == 0) {
		lpwTargetSpn = (WCHAR*)BeaconDataExtract(&parser, NULL);
		bGetTicket = TRUE;
	}
	
	if (PackageConnectLookup(&LogonHandle, &PackageId)) {
		if (bGetTicket && lpwTargetSpn != NULL) {
			GetEncodedTicket(LogonHandle, PackageId, lpwTargetSpn);
		}
		else {
			ShowTickets(LogonHandle, PackageId, bPurge);
		}
	}

	if (LogonHandle != NULL) {
		SECUR32$LsaDeregisterLogonProcess(LogonHandle);
	}

	return;
}
