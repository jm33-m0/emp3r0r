#include "_include/functions.c"

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

void PURGE(char* luid) {
    HANDLE hToken = GetCurrentToken(TOKEN_QUERY);
    LUID   currentLuid = GetCurrentLUID(hToken);
    LUID   targetLuid = { 0 };

    bool   IsHighIntegrity = IsSystem(hToken);

    if (luid) {
        targetLuid.LowPart = my_strtol(luid, NULL, 16);
        if (targetLuid.LowPart == 0 || targetLuid.LowPart == LONG_MAX || targetLuid.LowPart == LONG_MIN) {
            PRINT_OUT("[x] Invalid luid\n");
            return;
        }
    }
    else {
        targetLuid = currentLuid;
    }

    if (!IsHighIntegrity && currentLuid.LowPart != targetLuid.LowPart) {
        PRINT_OUT("[X] You need to be in SYSTEM integrity.\n");
        return;
    }

    HANDLE hLsa;
    if (GetLsaHandle(hToken, IsHighIntegrity, &hLsa)) return;

    ULONG authPackage;
    LSA_STRING krbAuth = { .Buffer = "kerberos",.Length = 8,.MaximumLength = 9 };
    if (SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage) == 0) {

        KERB_PURGE_TKT_CACHE_REQUEST purgeRequest;
        purgeRequest.MessageType = KerbPurgeTicketCacheMessage;
        purgeRequest.RealmName = (UNICODE_STRING){ .Buffer = L"", .Length = 0, .MaximumLength = 1 };
        purgeRequest.ServerName = (UNICODE_STRING){ .Buffer = L"", .Length = 0, .MaximumLength = 1 };

        if (IsHighIntegrity)
            purgeRequest.LogonId = targetLuid;
        else
            purgeRequest.LogonId = (LUID){ 0 };

        void* purgeResponse = NULL;
        ULONG responseSize = 0;
        NTSTATUS protocolStatus = 0;
        if (SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, &purgeRequest, sizeof(KERB_PURGE_TKT_CACHE_REQUEST), &purgeResponse, &responseSize, &protocolStatus) || protocolStatus)
            PRINT_OUT("[X] Tickets not purged.\n");
        else
            PRINT_OUT("[+] Successfully purged tickets.\n");
    }
    SECUR32$LsaDeregisterLogonProcess(hLsa);
}

void PURGE_RUN( PCHAR Buffer, IN DWORD Length ) {
    PRINT_OUT("\n[*] Action: Purge Tickets\n\n");

    char* luid = NULL;

    for (int i = 0; i < Length; i++)
        i += GetStrParam(Buffer + i, Length - i, "/luid:", 6, &luid );

    PURGE(luid);
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
        PURGE_RUN( PARAM, PARAM_SIZE );

    FreeBank();

    END_BOF();
}