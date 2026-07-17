#include "asn_convert.c"
#include "crypt_enc.c"

size_t my_wcslen(const wchar_t* str) {
    size_t len = 0;
    while (*str != L'\0') {
        len++;
        str++;
    }
    return len;
}

DateTime GetLocalTimeAdd(uint add) {
    char datatime[18];
    SYSTEMTIME systemTime;
    KERNEL32$GetSystemTime(&systemTime);
    FILETIME fileTime;
    KERNEL32$SystemTimeToFileTime(&systemTime, &fileTime);
    ULARGE_INTEGER uli;
    uli.LowPart = fileTime.dwLowDateTime;
    uli.HighPart = fileTime.dwHighDateTime;
    uli.QuadPart += ((ULONGLONG)add) * 10000000ULL;
    fileTime.dwLowDateTime = uli.LowPart;
    fileTime.dwHighDateTime = uli.HighPart;
    KERNEL32$FileTimeToSystemTime(&fileTime, &systemTime);
    DateTime dt = { 0 };
    dt.year = systemTime.wYear;
    dt.month = systemTime.wMonth;
    dt.day = systemTime.wDay;
    dt.hour = systemTime.wHour;
    dt.minute = systemTime.wMinute;
    dt.second = systemTime.wSecond;
    return dt;
}

DateTime GetGmTimeAdd(UINT add) {
    SYSTEMTIME systemTime;
    KERNEL32$GetSystemTime(&systemTime);
    DateTime dt = { 0 };
    dt.year = systemTime.wYear;
    dt.month = systemTime.wMonth;
    dt.day = systemTime.wDay;
    dt.hour = systemTime.wHour;
    dt.minute = systemTime.wMinute;
    dt.second = systemTime.wSecond;
    return dt;
}

bool IsLittleEndian() {
    int num = 1;
    return (*((byte*)&num) == 1);
}

void ReverseBytes(byte* bytes, size_t length) {
    byte temp;
    for (size_t i = 0; i < length / 2; i++) {
        temp = bytes[i];
        bytes[i] = bytes[length - i - 1];
        bytes[length - i - 1] = temp;
    }
}

void FlasToBytes(UINT32 Options, byte* OptionsBytes) {
    *((UINT32*)OptionsBytes) = Options;
    if (IsLittleEndian())
        ReverseBytes(OptionsBytes, sizeof(UINT32));
}



int CodePoint(wchar_t* str, int* offset) {
    int c = str[(*offset)++];
    if (c >= 0xD800 && c < 0xDC00 && *offset < my_strlen(str)) {
        int d = str[(*offset)];
        if (d >= 0xDC00 && d < 0xE000) {
            (*offset)++;
            c = ((c & 0x3FF) << 10) + (d & 0x3FF) + 0x10000;
        }
    }
    return c;
}

bool EncodeMono(wchar_t* str, int* len, byte** ms) {
    *len = my_wcslen(str);
    *ms = MemAlloc(*len);
    int k = 0;
    while (*str != '\0') {
        (*ms)[k++] = *str;
        str++;
    }
    return false;
}

bool EncodeUTF8(wchar_t* str, int* len, byte** ms) {
    int k = 0;
    int n = my_wcslen(str);
    int capacity = 32;
    int size = 0;
    *ms = MemAlloc(n * 4);
    while (k < n) {
        int cp = CodePoint(str, &k);
        if (cp < 0x80) {
            (*ms)[size++] = (byte)cp;
        }
        else if (cp < 0x800) {
            (*ms)[size++] = (byte)(0xC0 + (cp >> 6));
            (*ms)[size++] = (byte)(0x80 + (cp & 63));
        }
        else if (cp < 0x10000) {
            (*ms)[size++] = (byte)(0xE0 + (cp >> 12));
            (*ms)[size++] = (byte)(0x80 + ((cp >> 6) & 63));
            (*ms)[size++] = (byte)(0x80 + (cp & 63));
        }
        else {
            (*ms)[size++] = (byte)(0xF0 + (cp >> 18));
            (*ms)[size++] = (byte)(0x80 + ((cp >> 12) & 63));
            (*ms)[size++] = (byte)(0x80 + ((cp >> 6) & 63));
            (*ms)[size++] = (byte)(0x80 + (cp & 63));
        }
    }
    *len = size;
    return false;
}

bool EncodeUTF16(const wchar_t* str, int* lenr, byte** buf) {
    size_t len = my_wcslen(str);
    *buf = MemAlloc(len * 2);
    int k = 0;
    for (size_t i = 0; i < len; i++) {
        char c = str[i];
        (*buf)[k++] = (byte)(c >> 8);
        (*buf)[k++] = (byte)c;
    }
    *lenr = len * 2;
    return false;
}

bool EncodeUTF32(const wchar_t* str, int* len, byte** ms) {
    size_t k = 0;
    size_t n = my_wcslen(str);
    size_t capacity = 32;
    size_t size = 0;
    *ms = MemAlloc(n * 4);
    while (k < n) {
        int cp = CodePoint(str, &k);
        (*ms)[size++] = (byte)(cp >> 24);
        (*ms)[size++] = (byte)(cp >> 16);
        (*ms)[size++] = (byte)(cp >> 8);
        (*ms)[size++] = (byte)cp;
    }
    *len = size;
    return false;
}



bool MakePrimitiveInner(int tagClass, int tagValue, byte* val, int off, int len, AsnElt* a) {
    a->objBufSize = len;
    if (my_copybuf(&(a->objBuf), val + off, len)) return true;

    a->objOff = 0;
    a->objLen = -1;
    a->valOff = 0;
    a->valLen = len;
    a->hasEncodedHeader = false;
    a->tagClass = tagClass;
    a->tagValue = tagValue;
    a->sub = NULL;
    a->subCount = 0;
    return false;
}

bool MakeIntegerLong(long long x, AsnElt* asn_elt) {
    int k = 1;
    if (x >= 0) {
        for (unsigned long long w = x; w >= 0x80; w >>= 8)
            k++;
    }
    else {
        for (long long w = x; w <= -(long)0x80; w >>= 8)
            k++;
    }

    byte* v = MemAlloc(k);
    if (!v) return true;
    int len = k;
    for (long long w = x; k > 0; w >>= 8)
        v[--k] = (byte)w;

    return MakePrimitiveInner(ASN_UNIVERSAL, ASN_INTEGER, v, 0, len, asn_elt);
}

bool Make4(int tagClass, int tagValue, AsnElt* subs, int subsCount, AsnElt* a) {
    if (!a) return true;
    if (tagClass < 0 || tagClass > 3 || tagValue < 0) {
        PRINT_OUT("Invalid: tag class - %d\n, tag value - %d\n", tagClass, tagValue);
        return true;
    }
    a->objBuf = NULL;
    a->objBufSize = 0;
    a->objOff = 0;
    a->objLen = -1;
    a->valOff = 0;
    a->valLen = -1;
    a->hasEncodedHeader = false;
    a->tagClass = tagClass;
    a->tagValue = tagValue;
    if (subs == NULL) {
        a->subCount = 0;
        a->sub = 0;
    }
    else {
        a->subCount = subsCount;
        a->sub = MemAlloc(subsCount * sizeof(AsnElt));
        if (!a->sub) {
            PRINT_OUT("[x] Failed alloc memory");
            return true;
        }
        for (int i = 0; i < subsCount; i++)
            a->sub[i] = subs[i];
    }
    return false;
}

bool Make3(int tagValue, AsnElt* subs, int subsCount, AsnElt* a) {
    return Make4(ASN_UNIVERSAL, tagValue, subs, subsCount, a);
}

bool MakeBlob(byte* buf, int off, int len, AsnElt* a) {
    return MakePrimitiveInner(ASN_UNIVERSAL, ASN_OCTET_STRING, buf, off, len, a);
}

bool MakeExplicit(int tagClass, int tagValue, AsnElt* subs, int subsCount, AsnElt* a) {
    return Make4(tagClass, tagValue, subs, subsCount, a);
}

bool MakeImplicit(int tagClass, int tagValue, AsnElt* x, AsnElt* a) {
    if (x->sub != NULL)
        return Make4(tagClass, tagValue, x->sub, x->subCount, a);

    a->objOff = 0;
    a->objLen = -1;
    a->hasEncodedHeader = FALSE;
    a->tagClass = tagClass;
    a->tagValue = tagValue;
    a->sub = NULL;
    a->subCount = 0;
    if (x->objBuf) {
        a->objBuf = x->objBuf;
        a->objBufSize = x->objBufSize;
        a->valOff = x->valOff;
        a->valLen = x->valLen;
    }
    else {
        a->objBuf = MemAlloc(EncodedLength(x));
        a->objBufSize = EncodeValue(x, 0, EncodedLength(x), a->objBuf, 0);
        a->valOff = 0;
        a->valLen = x->objBufSize;
    }
    return false;
}

bool MakeBitString(byte* buf, size_t off, size_t len, AsnElt* a) {
    byte* tmp = MemAlloc(len + 1);
    if (tmp == NULL)
        return true;

    *tmp = 0;
    MemCpy(tmp + 1, buf + off, len);
    return MakePrimitiveInner(ASN_UNIVERSAL, ASN_BIT_STRING, tmp, 0, len + 1, a);
}

bool MakeString(int type, char* str, AsnElt* a) {
    int wlength = KERNEL32$MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    wchar_t* wstr = MemAlloc((wlength) * sizeof(wchar_t));
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, wlength);
    byte* buf;
    int len = 0;
    if( type == ASN_NumericString || type == ASN_PrintableString || type == ASN_UTCTime || type == ASN_GeneralizedTime || type == ASN_TeletexString || type == ASN_IA5String || type == ASN_GeneralString ) {
        if (EncodeMono(wstr, &len, &buf)) return true;
    }
    if ( type == ASN_UTF8String ) {
        if (EncodeUTF8(wstr, &len, &buf)) return true;
    }
    if (type == ASN_BMPString) {
        if (EncodeUTF16(wstr, &len, &buf)) return true;
    }
    if(type == ASN_UniversalString) {
        if (EncodeUTF32(wstr, &len, &buf)) return true;
    }
    return MakePrimitiveInner(ASN_UNIVERSAL, type, buf, 0, len, a);
}



bool PackIntegerLong(int tagValue, int var, AsnElt* varSeqContext) {
    AsnElt varAsn = { 0 }, varSeq = { 0 };
    if ( MakeIntegerLong(var, &varAsn)
         || Make3(ASN_SEQUENCE, &varAsn, 1, &varSeq)
         || MakeImplicit(ASN_CONTEXT, tagValue, &varSeq, varSeqContext) )
        return true;

    return false;
}

bool PackString(int tagValue, int type, char* var, AsnElt* varSeqContext){
    AsnElt varAsn = { 0 }, varSeq = { 0 };
    if ( MakeString( type, var, &varAsn)
         || Make3(ASN_SEQUENCE, &varAsn, 1, &varSeq)
         || MakeImplicit(ASN_CONTEXT, tagValue, &varSeq, varSeqContext) )
        return true;
    return false;
}

bool PackStringExt(int tagValue, int type, int imp_type, char* var, AsnElt* varSeqContext){
    AsnElt varAsn = { 0 }, var2Asn = { 0 }, varSeq = { 0 };
    if ( MakeString( type, var, &varAsn)
         || MakeImplicit(ASN_UNIVERSAL, imp_type, &varAsn, &var2Asn)
         || Make3(ASN_SEQUENCE, &var2Asn, 1, &varSeq)
         || MakeImplicit(ASN_CONTEXT, tagValue, &varSeq, varSeqContext) )
        return true;
    return false;
}

bool PackBitString(int tagValue, byte* var, int varLen, AsnElt* varSeqContext) {
    AsnElt varAsn = { 0 }, varSeq = { 0 };
    if ( MakeBitString(var, 0, varLen, &varAsn)
         || Make3(ASN_SEQUENCE, &varAsn, 1, &varSeq)
         || MakeImplicit(ASN_CONTEXT, tagValue, &varSeq, varSeqContext) )
        return true;
    return false;
}

bool PackBlock(int tagValue, byte* var, int varLen, AsnElt* varSeqContext) {
    AsnElt varAsn = { 0 }, varSeq = { 0 };
    if ( MakeBlob(var, 0, varLen, &varAsn)
         || Make3(ASN_SEQUENCE, &varAsn, 1, &varSeq)
         || MakeImplicit(ASN_CONTEXT, tagValue, &varSeq, varSeqContext) )
        return TRUE;
    return false;
}



bool AsnEncTimeStampToPaDataEncode(EncryptionKey encKey, PA_DATA* pa_data) {
    bool status = false;
    pa_data->type = PADATA_ENC_TIMESTAMP;

    char datatime[18];
    DateTime dt = GetLocalTimeAdd(0);
    MSVCRT$sprintf(datatime, "%04d%02d%02d%02d%02d%02dZ", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);

    AsnElt patimestampSeqContext = { 0 };
    if (PackString(0, ASN_GeneralizedTime, datatime, &patimestampSeqContext)) return true;

    AsnElt totalSeq = { 0 };
    if (Make3(ASN_SEQUENCE, &patimestampSeqContext, 1, &totalSeq)) return true;

    int rawBytesSize = 0;
    byte* rawBytes = 0;
    if (AsnToBytesEncode(&totalSeq, &rawBytesSize, &rawBytes)) return true;

    byte* encBytes;
    if (encrypt(rawBytes, rawBytesSize, encKey.key_value, encKey.key_type, KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &encBytes, &rawBytesSize)) return true;

    EncryptedData* pEncData = MemAlloc(sizeof(EncryptedData));
    if (!pEncData) {
        PRINT_OUT("[x] Failed alloc memory");
        return false;
    }
    pEncData->etype = encKey.key_type;
    pEncData->kvno = 0;
    pEncData->cipher = encBytes;
    pEncData->cipher_size = rawBytesSize;

    pa_data->value = pEncData;
    return false;
}

bool AsnPrincipalNameEncode(PrincipalName* cname, AsnElt* RET) {
    // name-type[0] Int32
    AsnElt nameTypeSeqContext = { 0 };
    if (PackIntegerLong(0, cname->name_type, &nameTypeSeqContext)) return true;

    // name-string[1] SEQUENCE OF KerberosString
    AsnElt* strings = MemAlloc(sizeof(AsnElt) * cname->name_count);
    for (DWORD i = 0; i < cname->name_count; ++i) {
        AsnElt nameStringElt = { 0 }, nameStringEltContext = { 0 };
        if (MakeString(ASN_UTF8String, cname->name_string[i], &nameStringElt)) return true;
        if (MakeImplicit(ASN_UNIVERSAL, ASN_GeneralString, &nameStringElt, &nameStringEltContext)) return true;
        strings[i] = nameStringEltContext;
    }

    AsnElt stringSeq = { 0 }, stringSeq2 = { 0 }, stringSeq2Context = { 0 };
    if (Make3(ASN_SEQUENCE, strings, cname->name_count, &stringSeq)) return true;
    if (Make3(ASN_SEQUENCE, &stringSeq, 1, &stringSeq2)) return true;
    if (MakeImplicit(ASN_CONTEXT, 1, &stringSeq2, &stringSeq2Context)) return true;

    // build the final sequences
    AsnElt preseq[] = { nameTypeSeqContext, stringSeq2Context };
    AsnElt seq = { 0 };
    if (Make3(ASN_SEQUENCE, preseq, 2, &seq)) return true;
    if (Make3(ASN_SEQUENCE, &seq, 1, RET)) return true;
    return false;
}

bool AsnHostAddressEncode(HostAddress* addr, AsnElt* seq) {
    // addr-type[0] Int32
    // addr-string[1] OCTET STRING
    AsnElt addrTypeSeqContext = { 0 };
    if (PackIntegerLong(0, addr->addr_type, &addrTypeSeqContext)) return true;

    AsnElt addrStringSeqContext = { 0 };
    if( PackStringExt(1, ASN_TeletexString, ASN_OCTET_STRING, addr->addr_string, &addrStringSeqContext) ) return true;

    AsnElt seqTotal[] = { addrTypeSeqContext, addrStringSeqContext };
    if (Make3(ASN_SEQUENCE, seqTotal, 2, seq)) return true;

    return false;
}




bool AsnKerbPaPacRequestEncode(KERB_PA_PAC_REQUEST* value, AsnElt* totalSeq) {
    AsnElt ret;
    if (value->include_pac) {
        if (MakeBlob((const unsigned char[]) { 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x01 }, 0, 7, & ret)) return true;
    }
    else {
        if (MakeBlob((const unsigned char[]) { 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00 }, 0, 7, & ret)) return true;
    }
    if (Make3(ASN_SEQUENCE, &ret, 1, totalSeq)) return true;

    return false;
}

bool AsnEncryptedDataEncode(EncryptedData* value, AsnElt* totalSeq) {
    // etype   [0] Int32 -- EncryptionType --,
    AsnElt etypeSeqContext = { 0 };
    if (PackIntegerLong(0, (long)value->etype, &etypeSeqContext)) return true;

    // cipher  [2] OCTET STRING -- ciphertext
    AsnElt cipherSeqContext = { 0 };
    if (PackBlock(2, value->cipher, value->cipher_size, &cipherSeqContext) ) return true;

    if (value->kvno != 0) {
        // kvno    [1] UInt32 OPTIONAL
        AsnElt kvnoSeqContext = { 0 };
        if (PackIntegerLong(1, (long)value->kvno, &kvnoSeqContext)) return true;

        AsnElt allSeq[] = { etypeSeqContext, kvnoSeqContext, cipherSeqContext };
        if (Make3(ASN_SEQUENCE, allSeq, 3, totalSeq))return true;
    }
    else {
        AsnElt allSeq[] = { etypeSeqContext, cipherSeqContext };
        if (Make3(ASN_SEQUENCE, allSeq, 2, totalSeq))return true;
    }
    return false;
}

bool AsnEncryptionKeyEncode(EncryptionKey* key, AsnElt* seq2) {
    // keytype[0] Int32 -- actually encryption type --
    AsnElt keyTypeSeqContext = { 0 };
    if (PackIntegerLong(0, (long)key->key_type, &keyTypeSeqContext)) return true;

    // keyvalue[1] OCTET STRING
    AsnElt blobSeqContext = { 0 };
    if (PackBlock(1, key->key_value, key->key_size, &blobSeqContext) ) return true;

    // build the final sequences (s)
    AsnElt seqTotal[] = { keyTypeSeqContext, blobSeqContext };
    AsnElt seq = { 0 };
    if (Make3(ASN_SEQUENCE, seqTotal, 2, &seq)) return true;
    if (Make3(ASN_SEQUENCE, &seq, 1, seq2)) return true;
    return false;
}

bool AsnTicketEncode(Ticket* ticket, AsnElt* totalSeq2Context) {
    // tkt-vno         [0] INTEGER (5)
    AsnElt tkt_vnoSeqContext = { 0 };
    if (PackIntegerLong(0, ticket->tkt_vno, &tkt_vnoSeqContext)) return true;

    // realm           [1] Realm
    AsnElt realmAsnSeqContext = { 0 };
    if( PackStringExt(1, ASN_IA5String, ASN_GeneralString, ticket->realm, &realmAsnSeqContext) ) return true;

    // sname           [2] PrincipalName
    AsnElt snameAsn = { 0 }, snameAsnContext = { 0 };
    if (AsnPrincipalNameEncode(&(ticket->sname), &snameAsn)) return true;
    if (MakeImplicit(ASN_CONTEXT, 2, &snameAsn, &snameAsnContext)) return true;

    // enc-part        [3] EncryptedData -- EncTicketPart
    AsnElt enc_partAsn = { 0 }, enc_partSeq = { 0 }, enc_partSeqContext = { 0 };
    if (AsnEncryptedDataEncode(&(ticket->enc_part), &enc_partAsn)) return true;
    if (Make3(ASN_SEQUENCE, &enc_partAsn, 1, &enc_partSeq)) return true;
    if (MakeImplicit(ASN_CONTEXT, 3, &enc_partSeq, &enc_partSeqContext)) return true;

    AsnElt seqTotal[] = { tkt_vnoSeqContext, realmAsnSeqContext, snameAsnContext, enc_partSeqContext };
    AsnElt totalSeq = { 0 }, totalSeq2 = { 0 };
    if (Make3(ASN_SEQUENCE, seqTotal, 4, &totalSeq)) return true;
    if (Make3(ASN_SEQUENCE, &totalSeq, 1, &totalSeq2)) return true;
    if (MakeImplicit(ASN_APPLICATION, 1, &totalSeq2, totalSeq2Context)) return true;

    return false;
}

bool AsnKDCReqBodyEncode(KDCReqBody* req_body, AsnElt* RET) {
    DWORD allNodesCount = 6;
    DWORD allNodesIndex = 0;
    if (req_body->cname.name_count)						allNodesCount++;
    if (req_body->rtime > 0)								allNodesCount++;
    if (req_body->addresses_count > 0)						allNodesCount++;
    if (req_body->enc_authorization_data.cipher_size > 0)	allNodesCount++;
    if (req_body->additional_tickets_count > 0)			allNodesCount++;
    AsnElt* allNodes = MemAlloc(sizeof(AsnElt) * allNodesCount);

    // kdc-options             [0] KDCOptions
    byte kdcOptionsBytes[sizeof(UINT32)];
    FlasToBytes(req_body->kdc_options, kdcOptionsBytes);

    AsnElt kdcOptionsSeqContext = { 0 };
    if (PackBitString(0, kdcOptionsBytes, sizeof(UINT32), &kdcOptionsSeqContext)) return true;
    allNodes[allNodesIndex] = kdcOptionsSeqContext; allNodesIndex++;

    // cname                   [1] PrincipalName
    if (req_body->cname.name_count) {
        AsnElt cnameElt = { 0 }, cnameEltContext = { 0 };
        if (AsnPrincipalNameEncode(&(req_body->cname), &cnameElt)) return true;
        if (MakeImplicit(ASN_CONTEXT, 1, &cnameElt, &cnameEltContext)) return true;
        allNodes[allNodesIndex] = cnameEltContext; allNodesIndex++;
    }

    // realm                   [2] Realm
    AsnElt realmSeqContext = { 0 };
    if( PackStringExt(2, ASN_IA5String, ASN_GeneralString, req_body->realm, &realmSeqContext) ) return true;
    allNodes[allNodesIndex] = realmSeqContext; allNodesIndex++;

    // sname                   [3] PrincipalName OPTIONAL
    AsnElt snameElt = { 0 }, snameEltContext = { 0 };
    if (AsnPrincipalNameEncode(&(req_body->sname), &snameElt)) return true;
    if (MakeImplicit(ASN_CONTEXT, 3, &snameElt, &snameEltContext)) return true;
    allNodes[allNodesIndex] = snameEltContext; allNodesIndex++;

    // from                    [4] KerberosTime OPTIONAL

    // till                    [5]
    char datatime[18];
    DateTime dt = GetLocalTimeAdd(req_body->till);
    MSVCRT$sprintf(datatime, "%04d%02d%02d%02d%02d%02dZ", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);

    AsnElt tillSeqContext = { 0 };
    if (PackString(5, ASN_GeneralizedTime, datatime, &tillSeqContext)) return true;
    allNodes[allNodesIndex] = tillSeqContext; allNodesIndex++;

    // rtime                   [6] KerberosTime
    if (req_body->rtime > 0) {
        char tilltime[18];
        dt = GetLocalTimeAdd(req_body->rtime);
        MSVCRT$sprintf(tilltime, "%04d%02d%02d%02d%02d%02dZ", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);


        AsnElt rtimeSeqContext = { 0 };
        if (PackString(6, ASN_GeneralizedTime, tilltime, &rtimeSeqContext)) return true;
        allNodes[allNodesIndex] = rtimeSeqContext; allNodesIndex++;
    }

    // nonce                   [7] UInt32
    AsnElt nonceSeqContext = { 0 };
    if (PackIntegerLong(7, (LONG)req_body->nonce, &nonceSeqContext)) return true;
    allNodes[allNodesIndex] = nonceSeqContext; allNodesIndex++;

    // etype                   [8] SEQUENCE OF Int32 -- EncryptionType -- in preference order --
    AsnElt* etypeList = MemAlloc(sizeof(AsnElt) * req_body->etypes_count);
    for (DWORD i = 0; i < req_body->etypes_count; ++i) {
        AsnElt etypeAsn = { 0 };
        if (MakeIntegerLong((LONG)req_body->etypes[i], &etypeAsn)) return true;
        etypeList[i] = etypeAsn;
    }
    AsnElt etypeSeqTotal1 = { 0 }, etypeSeqTotal2 = { 0 }, etypeSeqTotalContext = { 0 };
    if (Make3(ASN_SEQUENCE, etypeList, req_body->etypes_count, &etypeSeqTotal1)) return true;
    if (Make3(ASN_SEQUENCE, &etypeSeqTotal1, 1, &etypeSeqTotal2)) return true;
    if (MakeImplicit(ASN_CONTEXT, 8, &etypeSeqTotal2, &etypeSeqTotalContext)) return true;
    allNodes[allNodesIndex] = etypeSeqTotalContext; allNodesIndex++;

    // addresses               [9] HostAddresses OPTIONAL
    if (req_body->addresses_count > 0) {
        AsnElt* addrList = MemAlloc(sizeof(AsnElt) * req_body->addresses_count);
        for (int i = 0; i < req_body->addresses_count; i++) {
            AsnElt addrElt = { 0 };
            if (AsnHostAddressEncode(&(req_body->addresses[i]), &addrElt)) return false;
            addrList[i] = addrElt;
        }
        AsnElt addrSeqTotal1 = { 0 }, addrSeqTotal2 = { 0 }, addrSeqTotal2Context = { 0 };
        if (Make3(ASN_SEQUENCE, addrList, req_body->addresses_count, &addrSeqTotal1)) return true;
        if (Make3(ASN_SEQUENCE, &addrSeqTotal1, 1, &addrSeqTotal2)) return true;
        if (MakeImplicit(ASN_CONTEXT, 9, &addrSeqTotal2, &addrSeqTotal2Context)) return true;
        allNodes[allNodesIndex] = addrSeqTotal2Context; allNodesIndex++;
    }

    // enc-authorization-data  [10] EncryptedData OPTIONAL
    if (req_body->enc_authorization_data.cipher_size > 0) {
        AsnElt authorizationEncryptedDataASN = { 0 }, authorizationEncryptedDataSeq = { 0 }, authorizationEncryptedDataSeqContext = { 0 };
        if (AsnEncryptedDataEncode(&(req_body->enc_authorization_data), &authorizationEncryptedDataASN)) return true;
        if (Make3(ASN_SEQUENCE, &authorizationEncryptedDataASN, 1, &authorizationEncryptedDataSeq)) return true;
        if (MakeImplicit(ASN_CONTEXT, 10, &authorizationEncryptedDataSeq, &authorizationEncryptedDataSeqContext)) return true;
        allNodes[allNodesIndex] = authorizationEncryptedDataSeqContext; allNodesIndex++;
    }

    // additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
    if (req_body->additional_tickets_count > 0) {
        AsnElt ticketASN = { 0 }, ticketSeq = { 0 }, ticketSeq2 = { 0 }, ticketSeq2Context = { 0 };
        if (AsnTicketEncode(&(req_body->additional_tickets[0]), &ticketASN)) return true;
        if (Make3(ASN_SEQUENCE, &ticketASN, 1, &ticketSeq)) return true;
        if (Make3(ASN_SEQUENCE, &ticketSeq, 1, &ticketSeq2)) return true;
        if (MakeImplicit(ASN_CONTEXT, 11, &ticketSeq2, &ticketSeq2Context)) return true;
        allNodes[allNodesIndex] = ticketSeq2Context; allNodesIndex++;
    }

    if (Make3(ASN_SEQUENCE, allNodes, allNodesCount, RET)) return true;
    return false;
}

bool AsnChecksumEncode(Checksum* cksum, AsnElt* totalSeq2) {
    // cksumtype       [0] Int32
    AsnElt cksumtypeSeqContext = { 0 };
    if (PackIntegerLong(0, cksum->cksumtype, &cksumtypeSeqContext)) return true;

    // checksum        [1] OCTET STRING
    AsnElt checksumSeqContext = { 0 };
    if (PackBlock(1, cksum->checksum, cksum->checksum_length, &checksumSeqContext) ) return true;

    AsnElt seq[] = { cksumtypeSeqContext, checksumSeqContext };
    AsnElt totalSeq = { 0 };
    if (Make3(ASN_SEQUENCE, seq, 2, &totalSeq)) return true;
    if (Make3(ASN_SEQUENCE, &totalSeq, 1, totalSeq2)) return true;
    return false;
}

bool AsnAuthenticatorEncode(Authenticator* authenticator, AsnElt* finalContext) {
    DWORD allNodesCount = 5;
    DWORD allNodesIndex = 0;
    if (authenticator->cksum.checksum_length > 0)	allNodesCount++;
    if (authenticator->subkey.key_size)				allNodesCount++;
    if (authenticator->seq_number)					allNodesCount++;

    AsnElt* allNodes = MemAlloc(sizeof(AsnElt) * allNodesCount);

    // authenticator-vno       [0] INTEGER (5)
    AsnElt pvnoSeqContext = { 0 };
    if (PackIntegerLong(0, (long)authenticator->authenticator_vno, &pvnoSeqContext)) return true;
    allNodes[allNodesIndex] = pvnoSeqContext; allNodesIndex++;

    // crealm                  [1] Realm
    AsnElt prealmAsnSeqContext = { 0 };
    if( PackStringExt(1, ASN_IA5String, ASN_GeneralString, authenticator->crealm, &prealmAsnSeqContext) ) return true;
    allNodes[allNodesIndex] = prealmAsnSeqContext; allNodesIndex++;

    // cname                   [2] PrincipalName
    AsnElt snameElt = { 0 }, snameEltContext = { 0 };
    if (AsnPrincipalNameEncode(&(authenticator->cname), &snameElt)) return true;
    if (MakeImplicit(ASN_CONTEXT, 2, &snameElt, &snameEltContext)) return true;
    allNodes[allNodesIndex] = snameEltContext; allNodesIndex++;

    // cksum                    [3] Checksum
    if (authenticator->cksum.checksum_length > 0) {
        AsnElt checksumAsn = { 0 }, checksumAsnContext = { 0 };
        if (AsnChecksumEncode(&(authenticator->cksum), &checksumAsn)) return true;
        if (MakeImplicit(ASN_CONTEXT, 3, &checksumAsn, &checksumAsnContext)) return true;
        allNodes[allNodesIndex] = checksumAsnContext; allNodesIndex++;
    }

    // cusec                   [4] Microseconds
    AsnElt nonceSeqContext = { 0 };
    if (PackIntegerLong(4, (long)authenticator->cusec, &nonceSeqContext)) return true;
    allNodes[allNodesIndex] = nonceSeqContext; allNodesIndex++;

    // ctime                   [5] KerberosTime
    char datatime[18];
    MSVCRT$sprintf(datatime, "%04d%02d%02d%02d%02d%02dZ", authenticator->ctime.year, authenticator->ctime.month, authenticator->ctime.day, authenticator->ctime.hour, authenticator->ctime.minute, authenticator->ctime.second);
    AsnElt tillSeqContext = { 0 };
    if (PackString(5, ASN_GeneralizedTime, datatime, &tillSeqContext)) return true;
    allNodes[allNodesIndex] = tillSeqContext; allNodesIndex++;

    // subkey                  [6] EncryptionKey OPTIONAL
    if (authenticator->subkey.key_size) {
        AsnElt keyAsn = { 0 }, keyAsnContext = { 0 };
        if (AsnEncryptionKeyEncode(&(authenticator->subkey), &keyAsn)) return true;
        if (MakeImplicit(ASN_CONTEXT, 6, &keyAsn, &keyAsnContext)) return true;
        allNodes[allNodesIndex] = keyAsnContext; allNodesIndex++;
    }

    // seq-number              [7] UInt32 OPTIONAL
    if (authenticator->seq_number) {
        AsnElt seq_numberASN = { 0 }, seq_numberSeq = { 0 }, seq_numberSeqContext = { 0 };
        if (PackIntegerLong(7, (long)authenticator->seq_number, &seq_numberSeqContext)) return true;
        allNodes[allNodesIndex] = seq_numberSeqContext; allNodesIndex++;
    }

    AsnElt seq = { 0 };
    if (Make3(ASN_SEQUENCE, allNodes, allNodesCount, &seq)) return true;

    AsnElt finalAsn = { 0 };
    if (Make3(ASN_SEQUENCE, &seq, 1, &finalAsn))return true;
    if (MakeImplicit(ASN_APPLICATION, 2, &finalAsn, finalContext))return true;

    return false;
}

bool AsnApReqEncode(AP_REQ* value, AsnElt* totalSeqContext) {
    // pvno            [0] INTEGER (5)
    AsnElt pvnoSeqContext = { 0 };
    if (PackIntegerLong(0, (long)value->pvno, &pvnoSeqContext)) return true;

    // msg-type        [1] INTEGER (14)

    AsnElt msg_typeSeqContext = { 0 };
    if (PackIntegerLong(1, (long)value->msg_type, &msg_typeSeqContext)) return true;

    // ap-options      [2] APOptions
    byte ap_optionsBytes[sizeof(UINT32)];
    FlasToBytes(value->ap_options, ap_optionsBytes);
    AsnElt ap_optionsSeqContext = { 0 };
    if (PackBitString(2, ap_optionsBytes, sizeof(UINT32), &ap_optionsSeqContext)) return true;

    // ticket          [3] Ticket
    AsnElt ticketASN = { 0 }, ticktSeq = { 0 }, ticktSeqContext = { 0 };
    if (AsnTicketEncode(&(value->ticket), &ticketASN)) return true;
    if (Make3(ASN_SEQUENCE, &ticketASN, 1, &ticktSeq)) return true;
    if (MakeImplicit(ASN_CONTEXT, 3, &ticktSeq, &ticktSeqContext)) return true;

    // authenticator   [4] EncryptedData
    if (value->key.key_size == 0) {
        PRINT_OUT("[X] A key for the authenticator is needed to build an AP-REQ\n");
        return true;
    }

    AsnElt authenticatorAsn = { 0 };
    if (AsnAuthenticatorEncode(&(value->authenticator), &authenticatorAsn)) return true;

    byte* authenticatorBytes = NULL;
    int authenticatorBytesLength = 0;
    if (AsnToBytesEncode(&authenticatorAsn, &authenticatorBytesLength, &authenticatorBytes)) return true;

    byte* encBytes = NULL;
    if (encrypt(authenticatorBytes, authenticatorBytesLength, value->key.key_value, value->key.key_type, value->keyUsage, &encBytes, &authenticatorBytesLength)) return true;;

    EncryptedData authenticatorEncryptedData = { 0 };
    authenticatorEncryptedData.etype = value->key.key_type;
    authenticatorEncryptedData.cipher = encBytes;
    authenticatorEncryptedData.cipher_size = authenticatorBytesLength;

    AsnElt authenticatorEncryptedDataASN = { 0 }, authenticatorEncryptedDataSeq = { 0 }, authenticatorEncryptedDataSeqContext = { 0 };
    if (AsnEncryptedDataEncode(&authenticatorEncryptedData, &authenticatorEncryptedDataASN))return true;
    if (Make3(ASN_SEQUENCE, &authenticatorEncryptedDataASN, 1, &authenticatorEncryptedDataSeq)) return true;
    if (MakeImplicit(ASN_CONTEXT, 4, &authenticatorEncryptedDataSeq, &authenticatorEncryptedDataSeqContext)) return true;

    // encode it all into a sequence
    AsnElt totalAsn[] = { pvnoSeqContext , msg_typeSeqContext, ap_optionsSeqContext, ticktSeqContext, authenticatorEncryptedDataSeqContext };
    AsnElt seq = { 0 }, totalSeq = { 0 };
    if (Make3(ASN_SEQUENCE, totalAsn, 5, &seq)) return true;

    // AP-REQ          ::= [APPLICATION 14]
    //  put it all together and tag it with 14
    if (Make3(ASN_SEQUENCE, &seq, 1, &totalSeq)) return true;
    if (MakeImplicit(ASN_APPLICATION, 14, &totalSeq, totalSeqContext)) return true;

    return false;
}

bool AsnS4UUserIDEncode(S4UUserID* id, AsnElt* seqContext) {
    // nonce                   [0] UInt32
    AsnElt nonceSeqContext = { 0 };
    if (PackIntegerLong(0, id->nonce, &nonceSeqContext)) return true;

    // cname                   [1] PrincipalName
    AsnElt cnameElt = { 0 }, cnameEltContext = { 0 };
    if (AsnPrincipalNameEncode(&(id->cname), &cnameElt)) return true;
    if (MakeImplicit(ASN_CONTEXT, 1, &cnameElt, &cnameEltContext)) return true;

    // crealm                  [2] Realm
    AsnElt realmSeqContext = { 0 };
    if( PackStringExt(2, ASN_IA5String, ASN_GeneralString, id->crealm, &realmSeqContext) ) return true;

    // options                 [4] PA_S4U_X509_USER_OPTIONS
    byte optionsBytes[sizeof(UINT32)];
    FlasToBytes(id->options, optionsBytes);

    AsnElt optionsSeqContext = { 0 };
    if (PackBitString(4, optionsBytes, sizeof(UINT32), &optionsSeqContext)) return true;

    AsnElt allNodes[] = { nonceSeqContext, cnameEltContext, realmSeqContext, optionsSeqContext };
    if (Make3(ASN_SEQUENCE, allNodes, 4, seqContext)) return true;

    return false;
}

bool AsnPaPacOptionsEncode(PA_PAC_OPTIONS* value, AsnElt* seq) {
    AsnElt kerberosFlagsAsn = { 0 }, kerberosFlagsAsnContext = { 0 }, parent = { 0 };
    if (MakeBitString(value->kerberosFlags, 0, 4, &kerberosFlagsAsn)) return true;
    if (MakeImplicit(ASN_UNIVERSAL, 3, &kerberosFlagsAsn, &kerberosFlagsAsnContext)) return true;
    if (Make4(ASN_CONTEXT, 0, &kerberosFlagsAsnContext, 1, &parent)) return true;
    if (Make3(ASN_SEQUENCE, &parent, 1, seq)) return true;
    return false;
}

bool AsnPaS4USelfEnc(PA_FOR_USER* value, AsnElt* seq) {
    // userName[0] PrincipalName
    AsnElt userNameAsn = { 0 }, userNameAsnContext = { 0 };
    if (AsnPrincipalNameEncode(&(value->userName), &userNameAsn)) return true;
    if (MakeImplicit(ASN_CONTEXT, 0, &userNameAsn, &userNameAsnContext)) return true;

    // userRealm[1] Realm
    AsnElt userRealmSeqContext = { 0 };
    if( PackStringExt(1, ASN_IA5String, ASN_GeneralString, value->userRealm, &userRealmSeqContext) ) return true;

    // cksum[2] Checksum
    AsnElt checksumAsn = { 0 }, checksumAsnContext = { 0 };
    if (AsnChecksumEncode(&(value->cksum), &checksumAsn)) return true;
    if (MakeImplicit(ASN_CONTEXT, 2, &checksumAsn, &checksumAsnContext)) return true;

    // auth-package[3] KerberosString
    AsnElt auth_packageSeqContext = { 0 };
    if( PackStringExt(3, ASN_IA5String, ASN_GeneralString, value->auth_package, &auth_packageSeqContext) ) return true;

    AsnElt allSeq[] = { userNameAsnContext, userRealmSeqContext, checksumAsnContext, auth_packageSeqContext };
    if (Make3(ASN_SEQUENCE, allSeq, 4, seq)) return true;

    return false;
}

bool AsnPaS4Ux509UserEnc(PA_S4U_X509_USER* value, AsnElt* seq) {
    AsnElt userIDAsn = { 0 }, userIDSeq = { 0 }, userIDSeqContext = { 0 };
    if (AsnS4UUserIDEncode(&(value->user_id), &userIDAsn)) return true;
    if (Make3(ASN_SEQUENCE, &userIDAsn, 1, &userIDSeq)) return true;
    if (MakeImplicit(ASN_CONTEXT, 0, &userIDSeq, &userIDSeqContext)) return true;

    AsnElt checksumAsn = { 0 }, checksumAsnContext = { 0 };
    if (AsnChecksumEncode(&(value->cksum), &checksumAsn)) return true;
    if (MakeImplicit(ASN_CONTEXT, 1, &checksumAsn, &checksumAsnContext)) return true;

    AsnElt totalAsn[] = { userIDSeqContext, checksumAsnContext };
    if (Make3(ASN_SEQUENCE, totalAsn, 2, seq)) return true;

    return false;
}

bool AsnPaKeyListReqEncode(PA_KEY_LIST_REQ* value, AsnElt* seq) {
    AsnElt enctypeAsn = { 0 };
    if (MakeIntegerLong(value->Enctype, &enctypeAsn)) return true;
    if (Make3(ASN_SEQUENCE, &enctypeAsn, 1, seq)) return true;
    return false;
}

bool AsnPaDataEncode(PA_DATA padata, AsnElt* seq) {
    // padata-type     [1] Int32
    AsnElt nameTypeSeqContext = { 0 };
    if (PackIntegerLong(1, (long)padata.type, &nameTypeSeqContext)) return true;

    if (padata.type == PADATA_PA_PAC_REQUEST) {
        // used for AS-REQs
        AsnElt paDataElt = { 0 }, paDataEltContext = { 0 };
        if (AsnKerbPaPacRequestEncode(padata.value, &paDataElt)) return true;
        if (MakeImplicit(ASN_CONTEXT, 2, &paDataElt, &paDataEltContext)) return true;

        AsnElt seqSubs[] = { nameTypeSeqContext, paDataEltContext };
        if (Make3(ASN_SEQUENCE, seqSubs, 2, seq)) return true;
    }
    else if (padata.type == PADATA_ENC_TIMESTAMP) {
        // used for AS-REQs
        AsnElt encData = { 0 };
        if (AsnEncryptedDataEncode(padata.value, &encData)) return true;

        int encDataBytesSize = 0;
        byte* encDataBytes = 0;
        if (AsnToBytesEncode(&encData, &encDataBytesSize, &encDataBytes)) return true;

        AsnElt blobSeqContext = { 0 };
        if (PackBlock(2, encDataBytes, encDataBytesSize, &blobSeqContext) ) return true;

        AsnElt allSeq[] = { nameTypeSeqContext, blobSeqContext };
        if (Make3(ASN_SEQUENCE, allSeq, 2, seq)) return true;
    }
    else if (padata.type == PADATA_AP_REQ) {
        // used for TGS-REQs
        AsnElt encData = { 0 };
        if (AsnApReqEncode(padata.value, &encData)) return true;

        byte* encDataBytes = NULL;
        int   encDataBytesSize = 0;
        if (AsnToBytesEncode(&encData, &encDataBytesSize, &encDataBytes)) return true;

        AsnElt paDataElt = { 0 };
        if (PackBlock(2, encDataBytes, encDataBytesSize, &paDataElt) ) return true;

        AsnElt allSeq[] = { nameTypeSeqContext, paDataElt };
        if (Make3(ASN_SEQUENCE, allSeq, 2, seq)) return true;
    }
    else if (padata.type == PADATA_S4U2SELF) {
        // used for constrained delegation
        AsnElt encData = { 0 };
        if (AsnPaS4USelfEnc(padata.value, &encData)) return true;

        byte* encDataBytes = NULL;
        int   encDataBytesSize = 0;
        if (AsnToBytesEncode(&encData, &encDataBytesSize, &encDataBytes)) return true;

        AsnElt paDataElt = { 0 };
        if (PackBlock(2, encDataBytes, encDataBytesSize, &paDataElt) ) return true;

        AsnElt allSeq[] = { nameTypeSeqContext, paDataElt };
        if (Make3(ASN_SEQUENCE, allSeq, 2, seq)) return true;
    }
    else if (padata.type == PADATA_PA_S4U_X509_USER) {
        // used for constrained delegation
        AsnElt encData = { 0 };
        if (AsnPaS4Ux509UserEnc(padata.value, &encData)) return true;

        byte* encDataBytes = NULL;
        int   encDataBytesSize = 0;
        if (AsnToBytesEncode(&encData, &encDataBytesSize, &encDataBytes)) return true;

        AsnElt paDataElt = { 0 };
        if (PackBlock(2, encDataBytes, encDataBytesSize, &paDataElt) ) return true;

        AsnElt allSeq[] = { nameTypeSeqContext, paDataElt };
        if (Make3(ASN_SEQUENCE, allSeq, 2, seq)) return true;
    }
    else if (padata.type == PADATA_PA_PAC_OPTIONS) {
        AsnElt encData = { 0 };
        if (AsnPaPacOptionsEncode(padata.value, &encData)) return true;

        byte* encDataBytes = NULL;
        int   encDataBytesSize = 0;
        if (AsnToBytesEncode(&encData, &encDataBytesSize, &encDataBytes)) return true;

        AsnElt paDataElt = { 0 };
        if (PackBlock(2, encDataBytes, encDataBytesSize, &paDataElt) ) return true;

        AsnElt allSeq[] = { nameTypeSeqContext, paDataElt };
        if (Make3(ASN_SEQUENCE, allSeq, 2, seq)) return true;
    }
    else if (padata.type == PADATA_PK_AS_REQ) {
        PRINT_OUT("--- AsnPaDataEncode --- PADATA_PK_AS_REQ\n");
        //	AsnElt blob = AsnElt.MakeBlob(((PA_PK_AS_REQ)value).Encode().Encode());
        //	AsnElt blobSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[]{ blob });

        //	paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

        //	AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[]{ nameTypeSeq, paDataElt });
        //	return seq;
    }
    else if (padata.type == PADATA_KEY_LIST_REQ) {
        AsnElt encData = { 0 };
        if (AsnPaKeyListReqEncode(padata.value, &encData)) return true;

        byte* encDataBytes = NULL;
        int   encDataBytesSize = 0;
        if (AsnToBytesEncode(&encData, &encDataBytesSize, &encDataBytes)) return true;

        AsnElt paDataElt = { 0 };
        if (PackBlock(2, encDataBytes, encDataBytesSize, &paDataElt) ) return true;

        AsnElt allSeq[] = { nameTypeSeqContext, paDataElt };
        if (Make3(ASN_SEQUENCE, allSeq, 2, seq)) return true;
    }
    else {
        return true;
    }
    return false;
}

bool AsnKrbCredInfoEncode(KrbCredInfo* cred_info, AsnElt* seq) {
    DWORD allNodesCount = 2;
    DWORD allNodesIndex = 0;
    if (cred_info->prealm)									allNodesCount++;
    if (cred_info->pname.name_count)						allNodesCount++;
    if (cred_info->authtime.isSet)							allNodesCount++;
    if (cred_info->starttime.isSet)							allNodesCount++;
    if (cred_info->endtime.isSet)							allNodesCount++;
    if (cred_info->renew_till.isSet)						allNodesCount++;
    if (cred_info->srealm)									allNodesCount++;
    if (cred_info->sname.name_count)						allNodesCount++;

    AsnElt* asnElements = MemAlloc(sizeof(AsnElt) * allNodesCount);

    // key             [0] EncryptionKey
    AsnElt keyAsn = { 0 }, keyAsnContext = { 0 };
    if (AsnEncryptionKeyEncode(&(cred_info->key), &keyAsn)) return true;
    if (MakeImplicit(ASN_CONTEXT, 0, &keyAsn, &keyAsnContext)) return true;
    asnElements[allNodesIndex] = keyAsnContext; allNodesIndex++;

    // prealm          [1] Realm OPTIONAL
    if (cred_info->prealm) {
        AsnElt prealmAsnSeqContext = { 0 };
        if( PackStringExt(1, ASN_IA5String, ASN_GeneralString, cred_info->prealm, &prealmAsnSeqContext) ) return true;
        asnElements[allNodesIndex] = prealmAsnSeqContext; allNodesIndex++;
    }

    // pname           [2] PrincipalName OPTIONAL
    if (cred_info->pname.name_count) {
        AsnElt pnameAsn = { 0 }, pnameAsnContext = { 0 };
        if (AsnPrincipalNameEncode(&(cred_info->pname), &pnameAsn)) return true;
        if (MakeImplicit(ASN_CONTEXT, 2, &pnameAsn, &pnameAsnContext)) return true;
        asnElements[allNodesIndex] = pnameAsnContext; allNodesIndex++;
    }

    // pname           [2] PrincipalName OPTIONAL
    byte flagBytes[sizeof(UINT32)];
    FlasToBytes(cred_info->flags, flagBytes);
    AsnElt flagBytesSeqContext = { 0 };
    if (PackBitString(3, flagBytes, sizeof(UINT32), &flagBytesSeqContext)) return true;
    asnElements[allNodesIndex] = flagBytesSeqContext; allNodesIndex++;

    // authtime        [4] KerberosTime OPTIONAL
    if (cred_info->authtime.isSet) {
        char datatime[18];
        MSVCRT$sprintf(datatime, "%04d%02d%02d%02d%02d%02dZ", cred_info->authtime.year, cred_info->authtime.month, cred_info->authtime.day, cred_info->authtime.hour, cred_info->authtime.minute, cred_info->authtime.second);
        AsnElt patimestampSeqContext = { 0 };
        if (PackString(4, ASN_GeneralizedTime, datatime, &patimestampSeqContext)) return true;
        asnElements[allNodesIndex] = patimestampSeqContext; allNodesIndex++;
    }

    // starttime       [5] KerberosTime OPTIONAL
    if (cred_info->starttime.isSet) {
        char datatime[18];
        MSVCRT$sprintf(datatime, "%04d%02d%02d%02d%02d%02dZ", cred_info->starttime.year, cred_info->starttime.month, cred_info->starttime.day, cred_info->starttime.hour, cred_info->starttime.minute, cred_info->starttime.second);
        AsnElt starttimeSeqContext = { 0 };
        if (PackString(5, ASN_GeneralizedTime, datatime, &starttimeSeqContext)) return true;
        asnElements[allNodesIndex] = starttimeSeqContext; allNodesIndex++;
    }

    // endtime         [6] KerberosTime OPTIONAL
    if (cred_info->endtime.isSet) {
        char datatime[18];
        MSVCRT$sprintf(datatime, "%04d%02d%02d%02d%02d%02dZ", cred_info->endtime.year, cred_info->endtime.month, cred_info->endtime.day, cred_info->endtime.hour, cred_info->endtime.minute, cred_info->endtime.second);
        AsnElt endtimeSeqContext = { 0 };
        if (PackString(6, ASN_GeneralizedTime, datatime, &endtimeSeqContext)) return true;
        asnElements[allNodesIndex] = endtimeSeqContext; allNodesIndex++;
    }

    // renew-till      [7] KerberosTime OPTIONAL
    if (cred_info->renew_till.isSet) {
        char datatime[18];
        MSVCRT$sprintf(datatime, "%04d%02d%02d%02d%02d%02dZ", cred_info->renew_till.year, cred_info->renew_till.month, cred_info->renew_till.day, cred_info->renew_till.hour, cred_info->renew_till.minute, cred_info->renew_till.second);
        AsnElt renew_tillSeqContext = { 0 };
        if (PackString(7, ASN_GeneralizedTime, datatime, &renew_tillSeqContext)) return true;
        asnElements[allNodesIndex] = renew_tillSeqContext; allNodesIndex++;
    }

    // srealm          [8] Realm OPTIONAL
    if (cred_info->srealm) {
        AsnElt srealmAsnSeqContext = { 0 };
        if( PackStringExt(8, ASN_IA5String, ASN_GeneralString, cred_info->srealm, &srealmAsnSeqContext) ) return true;
        asnElements[allNodesIndex] = srealmAsnSeqContext; allNodesIndex++;
    }

    // sname           [9] PrincipalName OPTIONAL
    if (cred_info->sname.name_count) {
        AsnElt pnameAsn = { 0 }, pnameAsnContext = { 0 };
        if (AsnPrincipalNameEncode(&(cred_info->sname), &pnameAsn)) return true;
        if (MakeImplicit(ASN_CONTEXT, 9, &pnameAsn, &pnameAsnContext)) return true;
        asnElements[allNodesIndex] = pnameAsnContext; allNodesIndex++;
    }

    if (Make3(ASN_SEQUENCE, asnElements, allNodesCount, seq)) return true;
    return false;
}

bool AsnEncKrbCredPartEncode(EncKrbCredPart* cred_part, AsnElt* totalSeq2Context) {
    // ticket-info     [0] SEQUENCE OF KrbCredInfo
    AsnElt infoAsn = { 0 }, seq1 = { 0 }, seq2 = { 0 }, seq2Context = { 0 };
    if (AsnKrbCredInfoEncode(&(cred_part->ticket_info[0]), &infoAsn)) return true;
    if (Make3(ASN_SEQUENCE, &infoAsn, 1, &seq1)) return true;
    if (Make3(ASN_SEQUENCE, &seq1, 1, &seq2)) return true;
    if (MakeImplicit(ASN_CONTEXT, 0, &seq2, &seq2Context)) return true;

    AsnElt totalSeq = { 0 }, totalSeq2 = { 0 };
    if (Make3(ASN_SEQUENCE, &seq2Context, 1, &totalSeq)) return true;
    if (Make3(ASN_SEQUENCE, &totalSeq, 1, &totalSeq2)) return true;
    if (MakeImplicit(ASN_APPLICATION, 29, &totalSeq2, totalSeq2Context)) return true;

    return false;
}

bool AsnKrbCredEncode(KRB_CRED* krb_cred, AsnElt* finalContext) {
    // pvno            [0] INTEGER (5)
    AsnElt pvnoSeqContext = { 0 };
    if (PackIntegerLong(0, krb_cred->pvno, &pvnoSeqContext)) return true;

    // msg-type        [1] INTEGER (22)
    AsnElt msg_typeSeqContext = { 0 };
    if (PackIntegerLong(1, krb_cred->msg_type, &msg_typeSeqContext)) return true;

    // tickets         [2] SEQUENCE OF Ticket
    AsnElt ticketAsn = { 0 }, ticketSeq = { 0 }, ticketSeq2 = { 0 }, ticketSeq2Context = { 0 };
    if (AsnTicketEncode(&(krb_cred->tickets[0]), &ticketAsn)) return true;
    if (Make3(ASN_SEQUENCE, &ticketAsn, 1, &ticketSeq)) return true;
    if (Make3(ASN_SEQUENCE, &ticketSeq, 1, &ticketSeq2)) return true;
    if (MakeImplicit(ASN_CONTEXT, 2, &ticketSeq2, &ticketSeq2Context)) return true;

    // enc-part        [3] EncryptedData -- EncKrbCredPart
    AsnElt enc_partAsn = { 0 };
    if (AsnEncKrbCredPartEncode(&(krb_cred->enc_part), &enc_partAsn)) return true;
    int blobBytesSize = 0;
    byte* blobBytes = 0;
    if (AsnToBytesEncode(&enc_partAsn, &blobBytesSize, &blobBytes)) return true;

    AsnElt blobSeqContext = { 0 };
    if (PackBlock(2, blobBytes, blobBytesSize, &blobSeqContext) ) return true;

    // etype == 0 -> no encryption
    AsnElt etypeSeqContext = { 0 };
    if (PackIntegerLong(0, 0, &etypeSeqContext)) return true;

    AsnElt seq[] = { etypeSeqContext, blobSeqContext };
    AsnElt infoSeq = { 0 }, infoSeq2 = { 0 }, infoSeq2Context = { 0 };
    if (Make3(ASN_SEQUENCE, seq, 2, &infoSeq)) return true;
    if (Make3(ASN_SEQUENCE, &infoSeq, 1, &infoSeq2)) return true;
    if (MakeImplicit(ASN_CONTEXT, 3, &infoSeq2, &infoSeq2Context)) return true;

    // all the components
    AsnElt seqTotal[] = { pvnoSeqContext, msg_typeSeqContext, ticketSeq2Context, infoSeq2Context };
    AsnElt total = { 0 };
    if (Make3(ASN_SEQUENCE, seqTotal, 4, &total)) return true;

    // tag the final total ([APPLICATION 22])
    AsnElt final = { 0 };
    if (Make3(ASN_SEQUENCE, &total, 1, &final)) return true;
    if (MakeImplicit(ASN_APPLICATION, 22, &final, finalContext)) return true;

    return false;
}

bool AsnADEncode(ADIfRelevant* adif, AsnElt** finalContext) {
    AsnElt adTypeSeqContext = { 0 };
    if (PackIntegerLong(0, adif->ad_type, &adTypeSeqContext)) return true;

    AsnElt adDataSeqContext = { 0 };
    if (PackBlock(1, adif->ad_data, adif->ad_data_length, &adDataSeqContext) ) return true;

    AsnElt seq[] = { adTypeSeqContext, adDataSeqContext };
    if (Make3(ASN_SEQUENCE, seq, 2, finalContext)) return true;
    return false;
}

bool AsnADRestrictionEntryEncode(ADRestrictionEntry* adre, AsnElt* finalContext) {
    // KERB-AD-RESTRICTION-ENTRY encoding
    // restriction-type       [0] Int32
    AsnElt adRestrictionEntrySeqContext = { 0 };
    if (PackIntegerLong(0, adre->restriction_type, &adRestrictionEntrySeqContext)) return true;

    // restriction            [1] OCTET STRING
    AsnElt adRestrictionEntryDataSeqContext = { 0 };
    if (PackBlock(1, adre->restriction, adre->restriction_length, &adRestrictionEntryDataSeqContext) ) return true;

    AsnElt seq[] = { adRestrictionEntrySeqContext, adRestrictionEntryDataSeqContext };
    AsnElt seq1 = { 0 }, seq2 = { 0 };
    if (Make3(ASN_SEQUENCE, seq, 2, &seq1)) return true;
    if (Make3(ASN_SEQUENCE, &seq1, 1, &seq2)) return true;

    if (AsnToBytesEncode(&seq2, &(adre->ad_data_length), &(adre->ad_data))) return true;

    if (AsnADEncode(adre, finalContext)) return true;
    return false;
}

bool AsnADIfRelevantEncode(ADIfRelevant* adif, AsnElt* finalContext) {
    // ad-data            [1] OCTET STRING
    if (adif->ADData_count > 0) {
        AsnElt* adList = MemAlloc(sizeof(AsnElt) * adif->ADData_count);

        for (int i = 0; i < adif->ADData_count; i++) {
            AsnElt addrElt = { 0 };

            switch (((ADIfRelevant*)adif->ADData[i])->ad_type) {
                case 141:
                    if (AsnADRestrictionEntryEncode(adif->ADData[i], &addrElt)) return true;
                    break;
                case 142:
                    if (AsnADEncode(adif->ADData[i], &addrElt)) return true;
                    break;
                default:
                    break;
            }

            adList[i] = addrElt;
        }

        AsnElt seq = { 0 };
        if (Make3(ASN_SEQUENCE, adList, adif->ADData_count, &seq)) return true;
        if (AsnToBytesEncode(&seq, &(adif->ad_data_length), &(adif->ad_data))) return true;
    }

    if (AsnADEncode(adif, finalContext)) return true;
    return false;
}

bool ReqToAsnEncode(AS_REQ as_req, int APP_NUM, AsnElt* totalSeqApp) {
    // pvno            [1] INTEGER (5)
    AsnElt pvnoContext = { 0 };
    if (PackIntegerLong(1, as_req.pvno, &pvnoContext)) return true;

    // msg-type        [2] INTEGER (10 -- AS -- )
    AsnElt msg_type_ASNSeqContext = { 0 };
    if (PackIntegerLong(2, as_req.msg_type, &msg_type_ASNSeqContext)) return true;

    // padata          [3] SEQUENCE OF PA-DATA OPTIONAL
    AsnElt *padatas = MemAlloc(sizeof(AsnElt) * as_req.pa_data_count);
    if (!padatas && as_req.pa_data_count) {
        PRINT_OUT("[x] Failed alloc memory\n");
        return true;
    }
    for (int i = 0; i < as_req.pa_data_count; ++i) {
        AsnElt pd = {0};
        if (AsnPaDataEncode(as_req.pa_data[i], &pd)) return true;
        padatas[i] = pd;
    }

    AsnElt padata_ASNSeq = { 0 }, padata_ASNSeq2 = { 0 }, padata_ASNSeqContext = { 0 };
    if (Make3(ASN_SEQUENCE, padatas, as_req.pa_data_count, &padata_ASNSeq)) return true;
    if (Make3(ASN_SEQUENCE, &padata_ASNSeq, 1, &padata_ASNSeq2)) return true;
    if (MakeImplicit(ASN_CONTEXT, 3, &padata_ASNSeq2, &padata_ASNSeqContext)) return true;

    // req-body        [4] KDC-REQ-BODY
    AsnElt req_Body_ASN = { 0 }, req_Body_ASNSeq = { 0 }, req_Body_ASNSeqContext = { 0 };
    if (AsnKDCReqBodyEncode(&(as_req.req_body), &req_Body_ASN)) return true;
    if (Make3(ASN_SEQUENCE, &req_Body_ASN, 1, &req_Body_ASNSeq)) return true;
    if (MakeImplicit(ASN_CONTEXT, 4, &req_Body_ASNSeq, &req_Body_ASNSeqContext)) return true;

    // encode it all into a sequence
    AsnElt total[] = { pvnoContext, msg_type_ASNSeqContext, padata_ASNSeqContext, req_Body_ASNSeqContext };
    AsnElt seq = { 0 };
    if (Make3(ASN_SEQUENCE, total, 4, &seq)) return true;

    // AS-REQ          ::= [APP_NUM 10] KDC-REQ
    // TGS-REQ         ::= [APP_NUM 12] KDC-REQ
    AsnElt totalSeq = { 0 };
    if (Make3(ASN_SEQUENCE, &seq, 1, &totalSeq)) return true;
    if (MakeImplicit(ASN_APPLICATION, APP_NUM, &totalSeq, totalSeqApp)) return true;

    return false;
}

bool AsnEncKrbPrivPartEncode(EncKrbPrivPart* privPart, AsnElt* totalSeq) {
    // user-data       [0] OCTET STRING
    AsnElt new_passwordAsn = { 0 };
    if (MakeBlob(privPart->new_password, 0, my_strlen(privPart->new_password), &new_passwordAsn)) return true;

    AsnElt new_passwordAsnContext = { 0 }, principalAsn = { 0 }, principalAsnContext = { 0 }, realmAsn = { 0 }, realmAsnContext = { 0 }, new_passwordSeq = { 0 };
    if (privPart->username) {
        PrincipalName principal = { 0 };
        principal.name_type = PRINCIPAL_NT_PRINCIPAL;
        principal.name_count = 1;
        if (my_copybuf(&(principal.name_string), privPart->username, my_strlen(privPart->username) + 1)) return true;
        if (AsnPrincipalNameEncode(&principal, &principalAsn)) return true;

        if (MakeString(ASN_GeneralString, privPart->realm, &realmAsn)) return true;

        if (MakeExplicit(ASN_CONTEXT, 0, &new_passwordAsn, 1, &new_passwordAsnContext)) return true;
        if (MakeImplicit(ASN_CONTEXT, 1, &principalAsn, &principalAsnContext)) return true;
        if (MakeExplicit(ASN_CONTEXT, 2, &realmAsn, 1, &realmAsnContext)) return true;

        AsnElt seqPass[] = { new_passwordAsnContext, principalAsnContext, realmAsnContext };
        if (Make3(ASN_SEQUENCE, seqPass, 3, &new_passwordSeq)) return true;
    }
    else {
        if (MakeExplicit(ASN_CONTEXT, 0, &new_passwordAsn, 1, &new_passwordAsnContext)) return true;
        if (Make3(ASN_SEQUENCE, &new_passwordAsnContext, 1, &new_passwordSeq)) return true;
    }

    AsnElt new_passwordBlobAsn = { 0 }, new_passwordSeqContext = { 0 };
    char* new_passwordBlob = NULL;
    int new_passwordBlobSize = 0;
    if (AsnToBytesEncode(&new_passwordSeq, &new_passwordBlobSize, &new_passwordBlob))return true;
    if (MakeBlob(new_passwordBlob, 0, new_passwordBlobSize, &new_passwordBlobAsn)) return true;
    if (MakeExplicit(ASN_CONTEXT, 0, &new_passwordBlobAsn, 1, &new_passwordSeqContext)) return true;

    // seq-number      [3] UInt32 OPTIONAL
    AsnElt seq_numberSeqContext = { 0 };
    if (PackIntegerLong(3, privPart->seq_number, &seq_numberSeqContext)) return true;

    //  s-address       [4] HostAddress
    AsnElt hostAddressTypeSeqContext = { 0 };
    if (PackIntegerLong(0, 20, &hostAddressTypeSeqContext)) return true;

    AsnElt hostAddressAddressSeqContext = { 0 };
    if (PackBlock(1, privPart->host_name, my_strlen(privPart->host_name), &hostAddressAddressSeqContext) ) return true;

    AsnElt hostAddressSeq = { 0 }, hostAddressSeq2 = { 0 }, hostAddressSeq2Context = { 0 };
    AsnElt seqHostAddress[] = { hostAddressTypeSeqContext, hostAddressAddressSeqContext };
    if (Make3(ASN_SEQUENCE, seqHostAddress, 2, &hostAddressSeq)) return true;
    if (Make3(ASN_SEQUENCE, &hostAddressSeq, 1, &hostAddressSeq2)) return true;
    if (MakeImplicit(ASN_CONTEXT, 4, &hostAddressSeq2, &hostAddressSeq2Context)) return true;

    AsnElt seqAsn = { 0 }, seqAsnContext = { 0 };
    AsnElt seq[] = { new_passwordSeqContext, seq_numberSeqContext, hostAddressSeq2Context };
    if (Make3(ASN_SEQUENCE, seq, 3, &seqAsn)) return true;
    if (Make3(ASN_SEQUENCE, &seqAsn, 1, &seqAsnContext)) return true;

    if (MakeImplicit(ASN_APPLICATION, 28, &seqAsnContext, totalSeq)) return true;

    return false;
}

bool AsnKrbPrivEncode(KRB_PRIV* privPart, AsnElt* totalSeq) {
    // pvno            [0] INTEGER (5)
    AsnElt pvnoSeqContext = { 0 };
    if (PackIntegerLong(0, privPart->pvno, &pvnoSeqContext)) return true;

    // msg-type        [1] INTEGER (21)
    AsnElt msg_typeSeqContext = { 0 };
    if (PackIntegerLong(1, privPart->msg_type, &msg_typeSeqContext)) return true;

    // enc-part        [3] EncryptedData -- EncKrbPrivPart
    AsnElt enc_partAsn = { 0 };
    if (AsnEncKrbPrivPartEncode(&(privPart->enc_part), &enc_partAsn)) return true;
    byte* enc_partByte = NULL;
    int enc_partByteSize = 0;
    if (AsnToBytesEncode(&enc_partAsn, &enc_partByteSize, &enc_partByte)) return true;

    byte* encBytes = NULL;
    int encBytesSize = 0;
    if (encrypt(enc_partByte, enc_partByteSize, privPart->ekey.key_value, privPart->ekey.key_type, KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART, &encBytes, &encBytesSize)) return true;

    AsnElt blobSeqContext = { 0 };
    if (PackBlock(2, encBytes, encBytesSize, &blobSeqContext) ) return true;

    // etype
    AsnElt etypeSeqContext = { 0 };
    if (PackIntegerLong(0, privPart->ekey.key_type, &etypeSeqContext)) return true;

    AsnElt encPrivSeq = { 0 }, encPrivSeq2 = { 0 }, encPrivSeq2Context = { 0 };
    AsnElt seqBlobAsn[] = { etypeSeqContext,  blobSeqContext };
    if (Make3(ASN_SEQUENCE, seqBlobAsn, 2, &encPrivSeq)) return true;
    if (Make3(ASN_SEQUENCE, &encPrivSeq, 1, &encPrivSeq2)) return true;
    if (MakeImplicit(ASN_CONTEXT, 3, &encPrivSeq2, &encPrivSeq2Context)) return true;

    AsnElt totalAsn = { 0 }, finalAsn = { 0 };
    AsnElt seqTotal[] = { pvnoSeqContext,  msg_typeSeqContext, encPrivSeq2Context };
    if (Make3(ASN_SEQUENCE, seqTotal, 3, &totalAsn)) return true;
    // tag the final total ([APPLICATION 21])
    if (Make3(ASN_SEQUENCE, &totalAsn, 1, &finalAsn)) return true;
    if (MakeImplicit(ASN_APPLICATION, 21, &finalAsn, totalSeq)) return true;

    return false;
}
