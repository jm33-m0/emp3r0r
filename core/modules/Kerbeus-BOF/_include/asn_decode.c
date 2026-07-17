#include "asn_convert.c"

bool BytesToAsnDecode9(byte* buf, int off, int maxLen, int* tc, int* tv, bool* cons, int* valOff, int* valLen, int* ret);


bool CheckOff(int off, int lim) {
    if (off >= lim)
        return true;
    return false;
}

int Dec2(byte* s, int off, bool* good) {
    if (off < 0 || off >= (my_strlen(s) - 1)) {
        *good = FALSE;
        return -1;
    }
    char c1 = s[off];
    char c2 = s[off + 1];
    if (c1 < '0' || c1 > '9' || c2 < '0' || c2 > '9') {
        *good = FALSE;
        return -1;
    }
    return 10 * (c1 - '0') + (c2 - '0');
}

int IndexOf(byte* str, int len, byte c) {
    int j = -1;
    for (int i = 0; i < len; i++) {
        if (str[i] == c) {
            j = i;
            break;
        }
    }
    return j;
}

bool CheckTag(AsnElt* a, int tc, int tv) {
    if (a->tagClass != tc || a->tagValue != tv)
        return true;
    return false;
}

bool ValueByte(AsnElt* a, int off, int* ret) {
    if (off < 0) {
        PRINT_OUT("invalid value offset: &d\n", off);
        return true;
    }
    if (a->objBuf == NULL) {
        int k = 0;
        for (int i = 0; i < a->subCount; a++) {
            int slen = EncodedLength(&(a->sub[i]));
            if ((k + slen) > off) {
                return ValueByte(a, off - k, ret);
            }
        }
    }
    else {
        if (off < a->valLen) {
            *ret = a->objBuf[a->valOff + off];
            return false;
        }
    }
    PRINT_OUT("invalid value offset {0} (length = {1})");
    return true;
}

int CopyValue3(AsnElt* a, byte* dst, int off) {
    return EncodeValue(a, 0, INT_MAX, dst, off);
}



bool DecodeUTF8(byte* buf, int off, int len, byte** ret, int* ret_length) {
    if (len >= 3 && buf[off] == 0xEF && buf[off + 1] == 0xBB && buf[off + 2] == 0xBF) {
        off += 3;
        len -= 3;
    }
    wchar_t* tc = MemAlloc(len * 2 + 1);
    int tcOff;
    for (int k = 0; k < 2; k++) {
        tcOff = 0;
        for (int i = 0; i < len; i++) {
            int c = buf[off + i];
            int e;
            if (c < 0x80) {
                e = 0;
            }
            else if (c < 0xC0) {
            }
            else if (c < 0xE0) {
                c &= 0x1F;
                e = 1;
            }
            else if (c < 0xF0) {
                c &= 0x0F;
                e = 2;
            }
            else if (c < 0xF8) {
                c &= 0x07;
                e = 3;
            }
            else {
                return true;
            }
            while (e-- > 0) {
                if (++i >= len) return true;

                int d = buf[off + i];
                if (d < 0x80 || d > 0xBF) {
                    return true;
                }
                c = (c << 6) + (d & 0x3F);
            }
            if (c > 0x10FFFF) return true;

            if (c > 0xFFFF) {
                c -= 0x10000;
                int hi = 0xD800 + (c >> 10);
                int lo = 0xDC00 + (c & 0x3FF);
                tc[tcOff] = (char)hi;
                tc[tcOff + 1] = (char)lo;
                tcOff += 2;
            }
            else {
                tc[tcOff] = (wchar_t)c;
                tcOff++;
            }
        }
    }
    tc[tcOff] = 0;
    *ret_length = tcOff + 1;
    *ret = tc;
    return false;
}

bool DecodeMono(byte* buf, int off, int len, int type, byte** outBuf, int* outLen) {
    if (my_copybuf(outBuf, buf + off, len + 1)) return true;
    (*outBuf)[len] = 0;

    *outLen = len;
    return false;
}


bool DecodeNoCopyLength(byte* buf, int off, int len, int* ret) {
    int tc, tv, valOff, valLen, objLen;
    bool cons;
    if (BytesToAsnDecode9(buf, off, len, &tc, &tv, &cons, &valOff, &valLen, &objLen))
        return true;
    if (cons) {
        off = valOff;
        int lim = valOff + valLen;
        while (off < lim) {
            int oLength = 0;
            if (DecodeNoCopyLength(buf, off, lim - off, &oLength))
                return true;
            off += oLength;
        }
    }
    *ret = objLen;
    return false;
}

bool DecodeNoCopy(byte* buf, int off, int len, AsnElt* a) {
    int tc, tv, valOff, valLen, objLen;
    bool cons;
    if (BytesToAsnDecode9(buf, off, len, &tc, &tv, &cons, &valOff, &valLen, &objLen))
        return true;

    a->tagClass = tc;
    a->tagValue = tv;
    a->objBuf = buf;
    a->objBufSize = len;
    a->objOff = off;
    a->objLen = objLen;
    a->valOff = valOff;
    a->valLen = valLen;
    a->hasEncodedHeader = true;

    if (cons) {
        off = valOff;
        int lim = valOff + valLen;

        int count = 0;

        while (off < lim) {
            int oLength = 0;
            if (DecodeNoCopyLength(buf, off, lim - off, &oLength))
                return true;
            off += oLength;
            count++;
        }

        off = valOff;
        lim = valOff + valLen;
        int index = 0;
        AsnElt* subs = MemAlloc(sizeof(AsnElt) * count);
        if (!subs) {
            PRINT_OUT("[x] Failed alloc memory");
            return true;
        }
        while (off < lim && index <= count) {
            AsnElt b = { 0 };
            if (DecodeNoCopy(buf, off, lim - off, &b)) {
                return true;
            }
            off += b.objLen;
            subs[index] = b;
            index++;
        }
        a->sub = subs;
        a->subCount = count;
    }
    else {
        a->sub = NULL;
        a->subCount = 0;
    }
    return false;
}

bool BytesToAsnDecode9(byte* buf, int off, int maxLen, int* tc, int* tv, bool* cons, int* valOff, int* valLen, int* ret) {
    bool status = false;

    int lim = off + maxLen;
    int orig = off;

    if (CheckOff(off, lim)) return true;
    *tv = buf[off++];
    *cons = (*tv & 0x20) != 0;
    *tc = *tv >> 6;
    *tv &= 0x1F;
    if (*tv == 0x1F) {
        *tv = 0;
        for (;;) {
            if (CheckOff(off, lim)) return true;
            int c = buf[off++];
            if (*tv > 0xFFFFFF) {
                PRINT_OUT("tag value overflow\n");
                return true;
            }
            *tv = (*tv << 7) | (c & 0x7F);
            if ((c & 0x80) == 0) {
                break;
            }
        }
    }

    if (CheckOff(off, lim)) return true;
    int vlen = buf[off++];
    if (vlen == 0x80) {
        vlen = -1;
        if (!(*cons)) {
            PRINT_OUT("indefinite length but not constructed\n");
            return true;
        }
    }
    else if (vlen > 0x80) {
        int lenlen = vlen - 0x80;
        if (CheckOff(off + lenlen - 1, lim)) return true;
        vlen = 0;
        while (lenlen-- > 0) {
            if (vlen > 0x7FFFFF) {
                PRINT_OUT("length overflow\n");
                return true;
            }
            vlen = (vlen << 8) + buf[off++];
        }
    }

    *valOff = off;
    if (vlen < 0) {
        for (;;) {
            int tc2, tv2, valOff2, valLen2;
            bool cons2;
            int slen = 0;
            if (BytesToAsnDecode9(buf, off, lim - off, &tc2, &tv2, &cons2, &valOff2, &valLen2, &slen))
                return true;

            if (tc2 == 0 && tv2 == 0) {
                if (cons2 || valLen2 != 0) {
                    PRINT_OUT("invalid null tag\n");
                    return true;
                }
                *valLen = off - *valOff;
                off += slen;
                break;
            }
            else {
                off += slen;
            }
        }
    }
    else {
        if (vlen > (lim - off)) {
            PRINT_OUT("value overflow\n");
            return true;
        }
        off += vlen;
        *valLen = off - *valOff;
    }
    *ret = off - orig;
    return false;
}

bool BytesToAsnDecode4(byte* buf, int off, int len, bool exactLength, AsnElt* a) {
    int tc, tv, valOff, valLen, objLen;
    bool cons;
    if (BytesToAsnDecode9(buf, off, len, &tc, &tv, &cons, &valOff, &valLen, &objLen)) return true;

    if (exactLength && objLen != len) {
        PRINT_OUT("trailing garbage\n");
        return true;
    }
    byte* nbuf = 0;
    if (my_copybuf(&nbuf, buf + off, objLen)) return true;
    return DecodeNoCopy(nbuf, 0, objLen, a);
}

bool BytesToAsnDecode3(byte* buf, int len, bool exactLength, AsnElt* a) {
    return BytesToAsnDecode4(buf, 0, len, exactLength, a);
}

bool BytesToAsnDecode(byte* buf, int len, AsnElt* a) {
    return BytesToAsnDecode4(buf, 0, len, true, a);
}



bool AsnGetInteger(AsnElt* a, long* ret) {
    if ( !a )
        return 0;

    if ( a->sub ) {
//        PRINT_OUT("invalid INTEGER (constructed)\n");
        return true;
    }
    int vlen = ValueLength(a);
    if (vlen == 0) {
//        PRINT_OUT("invalid INTEGER (length = 0)\n");
        return true;
    }
    int v = 0;
    if (ValueByte(a, 0, &v)) return true;

    long long x;
    if ((v & 0x80) != 0) {
        x = -1;
        for (int k = 0; k < vlen; k++) {
            long long l = -1;
            l = l << 55;
            if (x < l) {
//                PRINT_OUT("integer overflow (negative)\n");
                return true;
            }
            int ll = 0;
            if (ValueByte(a, k, &ll))
                return true;
            x = (x << 8) + (long)ll;
        }
    }
    else {
        x = 0;
        for (int k = 0; k < vlen; k++) {
            long long l = 1;
            l = l << 55;
            if (x >= l) {
//                PRINT_OUT("integer overflow (positive): %d >= %d\n", x, l);
                return true;
            }
            int ll = 0;
            if (ValueByte(a, k, &ll))
                return true;
            x = (x << 8) + (long)ll;
        }
    }
    *ret = (long) x;
    return false;
}

bool AsnGetOctetString3(AsnElt* a, byte* dst, int off, int* ret) {
    if (!a)
        return true;

    if ( a->sub ) {
        int orig = off;
        for (int i = 0; i < a->subCount; i++) {
            if (CheckTag(&(a->sub[i]), ASN_UNIVERSAL, ASN_OCTET_STRING))
                return true;
            int ii = 0;
            if (AsnGetOctetString3(&(a->sub[i]), dst, off, &ii))
                return true;
            off += ii;
        }
        *ret = off - orig;
        return false;

    }
    if ( dst ) {
        *ret = CopyValue3(a, dst, off);
        return false;
    }
    else {
        *ret = ValueLength(a);
        return false;
    }
}

bool AsnGetOctetString(AsnElt* a, byte** ret, int* len) {
    if (AsnGetOctetString3(a, NULL, 0, len)) return true;

    *ret = MemAlloc(*len);
    if (!*ret) {
        PRINT_OUT("[x] Failed alloc memory");
        return true;
    }

    if (AsnGetOctetString3(a, *ret, 0, len))
        return true;

    return false;
}

bool AsnGetString(AsnElt* a, byte** ret) {
    int len = 0;
    char* r = 0;
    if (AsnGetOctetString(a, &r, &len)) return true;

    if (my_copybuf(ret, r, len + 1)) {
        return true;
    }
    (*ret)[len] = 0;
    return false;
}

bool AsnGetPrincipalName(AsnElt* a, PrincipalName* pname) {
    if (AsnGetInteger(&(a->sub[0].sub[0]), &(pname->name_type))) return true;
    pname->name_count = a->sub[1].sub[0].subCount;
    pname->name_string = MemAlloc(sizeof(void*) * pname->name_count);
    for (int i = 0; i < pname->name_count; i++) {
        byte* s = 0;
        int len = ValueLength(&(a->sub[1].sub[0].sub[i]));
        if (AsnGetString(&(a->sub[1].sub[0].sub[i]), &s)) {
            return true;
        }
        wchar_t* ws = 0;
        int ws_length = 0;
        if (DecodeUTF8(s, 0, len, &ws, &ws_length)) return true;

        pname->name_string[i] = MemAlloc(ws_length);
        KERNEL32$WideCharToMultiByte(CP_ACP, 0, ws, ws_length, pname->name_string[i], ws_length, NULL, 0);
    }
    return false;
}

bool AsnGetEncryptedData(AsnElt* a, EncryptedData* encdata) {
    long long tmpLong = 0;
    for (int i = 0;i < a->subCount; i++) {
        switch (a->sub[i].tagValue) {
            case 0:
                if (AsnGetInteger(&(a->sub[i].sub[0]), &tmpLong)) return true;
                encdata->etype = (int)tmpLong;
                break;
            case 1:
                if (AsnGetInteger(&(a->sub[i].sub[0]), &tmpLong)) return true;
                encdata->kvno = (uint)(tmpLong & 0x00000000ffffffff);
                break;
            case 2:
                if (AsnGetOctetString(&(a->sub[i].sub[0]), &(encdata->cipher), &(encdata->cipher_size))) return true;
                break;
            default:
                break;
        }
    }
    return false;
}

bool AsnGetTicket(AsnElt* a, Ticket* ticket) {
    long long tmpLong = 0;
    for (int i = 0; i < a->subCount; i++) {
        switch (a->sub[i].tagValue) {
            case 0:
                if (AsnGetInteger(&(a->sub[i].sub[0]), &tmpLong)) return true;
                ticket->tkt_vno = (INT)tmpLong;
                break;
            case 1:
                if (AsnGetString(&(a->sub[i].sub[0]), &(ticket->realm))) return true;
                break;
            case 2:
                if (AsnGetPrincipalName(&(a->sub[i].sub[0]), &(ticket->sname))) return true;
                break;
            case 3:
                if (AsnGetEncryptedData(&(a->sub[i].sub[0]), &(ticket->enc_part))) return true;
                break;
            default:
                break;
        }
    }
    return false;
}

bool AsnGetErrorCode(AsnElt* a, uint* error) {
    long long tmpLong = 0;
    for (int i = 0; i < a->subCount; i++) {
        if (a->sub[i].tagValue == 6) {
            if (AsnGetInteger(&(a->sub[i].sub[0]), &tmpLong))
                return true;
            *error = (uint)tmpLong;
            break;
        }
    }
    return false;
}

bool AsnGetEncryptionKey(AsnElt* a, EncryptionKey* enc_key) {
    long long tmpLong = 0;
    AsnElt s = a->sub[0];
    for (int i = 0; i < s.subCount; i++) {
        switch (s.sub[i].tagValue) {
            case 0:
                if (AsnGetInteger(&(s.sub[i].sub[0]), &tmpLong)) return true;
                enc_key->key_type = (int)tmpLong;
                break;
            case 1:
                if (AsnGetOctetString(&(s.sub[i].sub[0]), &(enc_key->key_value), &(enc_key->key_size))) return true;
                break;
            case 2:
                if (AsnGetOctetString(&(s.sub[i].sub[0]), &(enc_key->key_value), &(enc_key->key_size))) return true;
                break;
            default:
                break;
        }
    }
    return false;
}

bool NodeAsnGetSting(AsnElt* a, int type, int* len, byte** ret) {
    if (a->sub != NULL) {
        PRINT_OUT("invalid string (constructed)");
        return true;
    }
    if (type == ASN_NumericString || type == ASN_PrintableString || type == ASN_IA5String || type == ASN_TeletexString ||type == ASN_UTCTime ||type == ASN_GeneralizedTime ){
        if (DecodeMono(a->objBuf, a->valOff, a->valLen, type, ret, len)) return true;
    }
    else if (type == ASN_UTF8String){
        //return DecodeUTF8(objBuf, valOff, valLen);
    }
    else if ( type == ASN_BMPString ) {
        //return DecodeUTF16(objBuf, valOff, valLen);
    }
    else if (type == ASN_UniversalString) {
        //return DecodeUTF32(objBuf, valOff, valLen);
    }
    else {
        PRINT_OUT("unsupported string type: %d\n", type);
        return true;
    }
    return false;
}

bool AsnGetTime2(AsnElt* a, int type, DateTime* dt) {
    bool isGen = FALSE;
    switch (type) {
        case ASN_UTCTime:
            break;
        case ASN_GeneralizedTime:
            isGen = TRUE;
            break;
        default:
            PRINT_OUT("unsupported date type: %d\n", type);
            return true;
    }

    int sLen = 0;
    byte* s = 0;
    if (NodeAsnGetSting(a, type, &sLen, &s)) return true;

    for (int i = 0; i < sLen; i++) {
        if (s[i] >= '0' && s[i] <= '9')
            continue;
        if (s[i] == '.' || s[i] == '+' || s[i] == '-' || s[i] == 'Z')
            continue;
        PRINT_OUT("invalid time string:");
        return true;
    }

    bool good = TRUE;
    int  tzHours = 0;
    int  tzMinutes = 0;
    bool negZ = FALSE;
    bool noTZ = FALSE;
    if (s[sLen - 1] == 'Z') {
        s[sLen - 1] = 0;
        sLen--;
    }
    else {
        int j = IndexOf(s, sLen, '+');
        if (j < 0) {
            int j = IndexOf(s, sLen, '-');
            negZ = TRUE;
        }
        if (j < 0) {
            noTZ = TRUE;
        }
        else {
            byte* t = s + j + 1;
        }
    }

    if ((noTZ && !isGen) || (sLen < 4)) {
        PRINT_OUT("invalid time string");
        return true;
    }
    byte* stime = s;
    int year = Dec2(stime, 0, &good);
    if (isGen) {
        year = year * 100 + Dec2(stime, 2, &good);
        stime += 4;
        sLen -= 4;
    }
    else {
        if (year < 50) year += 100;
        year += 1900;
        stime += 2;
        sLen -= 2;
    }
    int month = Dec2(stime, 0, &good);
    int day = Dec2(stime, 2, &good);
    int hour = Dec2(stime, 4, &good);
    int minute = Dec2(stime, 6, &good);
    int second = 0;
    int millisecond = 0;
    if (isGen) {
        second = Dec2(stime, 8, &good);
        if (sLen >= 12 && stime[10] == '.') {
            stime += 11;
            for (int i = 0; stime[i]; i++) {
                if (stime[i] < '0' || stime[i] > '9') {
                    good = FALSE;
                    break;
                }
            }
            millisecond = 10 * Dec2(stime, 0, &good) + Dec2(stime, 2, &good) / 10;
        }
        else if (sLen != 10) {
            good = FALSE;
        }
    }
    else {
        switch (sLen) {
            case 8:
                break;
            case 10:
                second = Dec2(s, 8, &good);
                break;
            default:
                PRINT_OUT("invalid time string");
                return true;
        }
    }

    if (!good) {
        PRINT_OUT("invalid time string");
        return true;
    }

    if (second == 60)
        second = 59;

    dt->isSet = TRUE;
    dt->year = year;
    dt->month = month;
    dt->day = day;
    dt->hour = hour;
    dt->minute = minute;
    dt->second = second;
    dt->millisecond = millisecond;
    return false;
}

bool AsnGetTime(AsnElt* a, DateTime* dt) {
    if (a->tagClass != ASN_UNIVERSAL) {
        PRINT_OUT("cannot infer date type: %d:%d\n", a->tagClass, a->tagValue);
        return true;
    }
    return AsnGetTime2(a, a->tagValue, dt);
}

bool AsnGetLastReq(AsnElt* a, LastReq* last_req) {
    long long tmpLong = 0;
    AsnElt s = a->sub[0];
    for (int i = 0; i < s.subCount; i++) {
        switch (s.sub[i].tagValue) {
            case 0:
                if (AsnGetInteger(&(s.sub[i].sub[0]), &tmpLong)) return true;
                last_req->lr_type = (int)tmpLong;
                break;
            case 1:
                if (AsnGetTime(&(s.sub[i].sub[0]), &(last_req->lr_value))) return true;
                break;
            default:
                break;
        }
    }
    return false;
}

bool AsnGetEncryptedPAData(AsnElt* body, EncryptedPAData* data) {
    for (int i = 0; i < body->sub[0].subCount; i++) {
        long long ll = 0;
        switch (body->sub[0].sub[i].tagValue) {
            case 1:
                if (AsnGetInteger(&(body->sub[0].sub[i].sub[0]), &ll)) return true;
                data->keytype = (int)ll;
                break;
            case 2:
                if (AsnGetOctetString(&(body->sub[0].sub[i].sub[0]), &(data->keyvalue), &(data->keysize))) return true;
                break;
            default:
                break;
        }
    }

    if (data->keytype == 162) { // KEY_LIST_REP
        AsnElt ae = { 0 };
        if (BytesToAsnDecode(data->keyvalue, data->keysize, &ae)) return true;
        if (AsnGetEncryptionKey(&ae, &(data->encryptionKey))) return true;
    }
    return false;
}

bool AsnGetEncKDCRepPart(AsnElt* a, EncKDCRepPart* rep_part) {
    for (int i = 0; i < a->subCount; i++) {
        int tagValue = a->sub[i].tagValue;
        if( tagValue == 0 ){
            if (AsnGetEncryptionKey(&(a->sub[i]), &(rep_part->key))) return true;
        }
        if( tagValue == 1 ){
            if (AsnGetLastReq(&(a->sub[i].sub[0]), &(rep_part->lastReq))) return true;
        }
        if( tagValue == 2 ){
            long long tmpLong = 0;
            if (AsnGetInteger(&(a->sub[i].sub[0]), &tmpLong)) return true;
            rep_part->nonce = (uint)tmpLong;
        }
        if( tagValue == 3 ){
            if (AsnGetTime(&(a->sub[i].sub[0]), &(rep_part->key_expiration))) return true;
        }
        if( tagValue == 4 ){
            long long tmpLong = 0;
            if (AsnGetInteger(&(a->sub[i].sub[0]), &tmpLong)) return true;
            rep_part->flags = (uint)tmpLong;
        }
        if( tagValue == 5 ){
            if (AsnGetTime(&(a->sub[i].sub[0]), &(rep_part->authtime))) return true;
        }
        if( tagValue == 6 ){
            if (AsnGetTime(&(a->sub[i].sub[0]), &(rep_part->starttime))) return true;
        }
        if( tagValue == 7 ){
            if (AsnGetTime(&(a->sub[i].sub[0]), &(rep_part->endtime))) return true;
        }
        if( tagValue == 8 ){
            if (AsnGetTime(&(a->sub[i].sub[0]), &(rep_part->renew_till))) return true;
        }
        if( tagValue == 9 ){
            if (AsnGetString(&(a->sub[i].sub[0]), &(rep_part->realm))) return true;
        }
        if( tagValue == 10 ){
            if (AsnGetPrincipalName(&(a->sub[i].sub[0]), &(rep_part->sname))) return true;
        }
        if( tagValue == 12 ){
            if (AsnGetEncryptedPAData(&(a->sub[i].sub[0]), &(rep_part->encryptedPaData))) return true;
        }
    }
    return false;
}

bool AsnGetKrbCredInfo(AsnElt* body, KrbCredInfo* info) {
    for (int i = 0; i < body->subCount; i++) {
        int tagValue = body->sub[i].tagValue;
        if (tagValue == 0) {
            if (AsnGetEncryptionKey(&(body->sub[i]), &(info->key))) return true;
        }
        if (tagValue == 1) {
            if (AsnGetString(&(body->sub[i].sub[0]), &(info->prealm))) return true;
        }
        if (tagValue == 2) {
            if (AsnGetPrincipalName(&(body->sub[i].sub[0]), &(info->pname))) return true;
        }
        if (tagValue == 3) {
            long tmpLong = 0;
            if (AsnGetInteger(&(body->sub[i].sub[0]), &tmpLong)) return true;
            info->flags = (uint)tmpLong;
        }
        if (tagValue == 4) {
            if (AsnGetTime(&(body->sub[i].sub[0]), &(info->authtime))) return true;
        }
        if (tagValue == 5) {
            if (AsnGetTime(&(body->sub[i].sub[0]), &(info->starttime))) return true;
        }
        if (tagValue == 6) {
            if (AsnGetTime(&(body->sub[i].sub[0]), &(info->endtime))) return true;
        }
        if (tagValue == 7) {
            if (AsnGetTime(&(body->sub[i].sub[0]), &(info->renew_till))) return true;
        }
        if (tagValue == 8) {
            if (AsnGetString(&(body->sub[i].sub[0]), &(info->srealm))) return true;
        }
        if (tagValue == 9) {
            if (AsnGetPrincipalName(&(body->sub[i].sub[0]), &(info->sname))) return true;
        }
    }
    return false;
}

bool AsnGetEncKrbCredPart(AsnElt* body, EncKrbCredPart* cred_part) {
    int octetStringLength = 0;
    byte* octetString = 0;
    if (AsnGetOctetString(&(body->sub[1].sub[0]), &octetString, &octetStringLength)) return true;

    AsnElt body2 = { 0 };
    if (BytesToAsnDecode3(octetString, octetStringLength, false, &body2)) return true;

    KrbCredInfo info = { 0 };
    if (AsnGetKrbCredInfo(&(body2.sub[0].sub[0].sub[0].sub[0]), &info)) return true;

    cred_part->ticket_count = 1;
    cred_part->ticket_info = MemAlloc(cred_part->ticket_count * sizeof(KrbCredInfo));
    cred_part->ticket_info[0] = info;

    return false;
}

bool AsnGetKrbCred(AsnElt* body, KRB_CRED* cred) {
    for (int i = 0; i < body->subCount; i++) {
        switch (body->sub[i].tagValue) {
            case 0:
                if (AsnGetInteger(&(body->sub[i].sub[0]), &(cred->pvno))) return true;
                break;
            case 1:
                if (AsnGetInteger(&(body->sub[i].sub[0]), &(cred->msg_type))) return true;
                break;
            case 2:
                cred->ticket_count = body->sub[i].sub[0].sub[0].subCount;
                if (cred->ticket_count) {
                    cred->tickets = MemAlloc(sizeof(Ticket) * cred->ticket_count);
                    for (int j = 0; j < cred->ticket_count; j++) {
                        Ticket ticket = { 0 };
                        if (AsnGetTicket(&(body->sub[i].sub[0].sub[0].sub[j]), &ticket)) return true;
                        cred->tickets[j] = ticket;
                    }
                }
                break;
            case 3:
                if (AsnGetEncKrbCredPart(&(body->sub[i].sub[0]), &(cred->enc_part))) return true;
                break;
            default:
                break;
        }
    }
    return false;
}

bool AsnGet_ETYPE_INFO2_ENTRY(AsnElt* body, ETYPE_INFO2_ENTRY* entry) {
    for (int i = 0; i < body->sub[0].subCount; i++) {
        long long ll = 0;
        switch (body->sub[0].sub[i].tagValue) {
            case 0:
                if (AsnGetInteger(&(body->sub[0].sub[i].sub[0]), &ll)) return true;
                entry->etype = (int)ll;
                break;
            case 1:
                if (AsnGetString(&(body->sub[0].sub[i].sub[0]), &(entry->salt))) return true;
                break;
            default:
                break;
        }
    }
    return false;
}

bool AsnGetPaData(AsnElt* body, PA_DATA* padata) {
    byte* valueBytes = NULL;
    int   valueBytesLength = 0;

    if (body->subCount > 1 && body->sub[0].subCount && body->sub[1].subCount) {
        AsnGetInteger(&(body->sub[0].sub[0]), &(padata->type));
        AsnGetOctetString(&(body->sub[1].sub[0]), &valueBytes, &valueBytesLength);
    }
    else if (body->subCount && body->sub[0].subCount > 1 && body->sub[0].sub[0].subCount && body->sub[0].sub[1].subCount) {
        AsnGetInteger(&(body->sub[0].sub[0].sub[0]), &(padata->type));
        AsnGetOctetString(&(body->sub[0].sub[1].sub[0]), &valueBytes, &valueBytesLength);
    }
    else {
        return true;
    }

    switch (padata->type) {
        case PADATA_PA_PAC_REQUEST:
            PRINT_OUT("--- AsnGetPaData --- case PADATA_PA_PAC_REQUEST");
            //	value = new KERB_PA_PAC_REQUEST(AsnElt.Decode(body.Sub[1].Sub[0].CopyValue()));
            break;
        case PADATA_PK_AS_REP:
            PRINT_OUT("--- AsnGetPaData --- case PADATA_PK_AS_REP");
            //	value = new PA_PK_AS_REP(AsnElt.Decode(body.Sub[1].Sub[0].CopyValue()));
            break;
        case PADATA_PA_S4U_X509_USER:
            break;
        case PADATA_ETYPE_INFO2:
            padata->value = MemAlloc(sizeof(ETYPE_INFO2_ENTRY));

            int masLength = ValueLength(&(body->sub[1].sub[0]));
            byte* mas = MemAlloc(masLength);
            masLength = EncodeValue(&(body->sub[1].sub[0]), 0, masLength, mas, 0);

            AsnElt a = { 0 };
            if (BytesToAsnDecode(mas, masLength, &a)) return true;

            if (AsnGet_ETYPE_INFO2_ENTRY(&a, padata->value)) return true;
            break;
    }
    return false;
}

bool AsnGetTGS_REP(AsnElt* asn_TGS_REP, TGS_REP* tgs_rep) {
    // TGS - REP::= [APPLICATION 13] KDC - REP

    if ((asn_TGS_REP->subCount != 1) || (asn_TGS_REP->sub[0].tagValue != 16)) {
        PRINT_OUT("First TGS-REP sub should be a sequence\n");
        return true;
    }
    AsnElt* kdc_rep = asn_TGS_REP->sub[0].sub;
    for (int i = 0; i < asn_TGS_REP->sub[0].subCount; i++) {
        int tagValue = kdc_rep[i].tagValue;
        if( tagValue == 0 ) {
            if (AsnGetInteger(&(kdc_rep[i].sub[0]), &(tgs_rep->pvno))) return true;
        }
        if( tagValue == 1 ) {
            if (AsnGetInteger(&(kdc_rep[i].sub[0]), &(tgs_rep->msg_type))) return true;
        }
        if( tagValue == 2 ) {
            if (AsnGetPaData(&(kdc_rep[i].sub[0]), &(tgs_rep->padata))) return true;
        }
        if( tagValue == 3 ) {
            if (AsnGetString(&(kdc_rep[i].sub[0]), &(tgs_rep->crealm))) return true;
        }
        if( tagValue == 4 ) {
            if (AsnGetPrincipalName(&(kdc_rep[i].sub[0]), &(tgs_rep->cname))) return true;
        }
        if( tagValue == 5 ) {
            if (AsnGetTicket(&(kdc_rep[i].sub[0].sub[0]), &(tgs_rep->ticket))) return true;
        }
        if( tagValue == 6 ) {
            if (AsnGetEncryptedData(&(kdc_rep[i].sub[0]), &(tgs_rep->enc_part))) return true;
        }
    }
    return false;
}
