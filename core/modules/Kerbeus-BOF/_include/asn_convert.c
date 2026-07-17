#pragma once
#include "functions.c"

int AsnToBytesEncode5(AsnElt* a, int start, int end, byte* dst, int dstOff);

int ValueLength(AsnElt* a);

int TagLength(int tagValue) {
    if (tagValue < 0x1F) return 1;
    int k = 0;
    for (int v = tagValue; v > 0; v >>= 7, k += 7);
    return (k / 7) + 1;
}

int LengthLength(int vlen) {
    if (vlen < 0x80) return 1;
    int k = 0;
    for (int v = vlen; v > 0; v >>= 8, k += 8);
    return (k / 8) + 1;
}

int EncodedLength(AsnElt* a) {
    if (a->objLen < 0) {
        int vlen = ValueLength(a);
        a->objLen = TagLength(a->tagValue) + LengthLength(vlen) + vlen;
    }
    return a->objLen;
}

int ValueLength(AsnElt* a) {
    if (a->valLen < 0) {
        if (a->sub != NULL) {
            int vlen = 0;
            for (int i = 0; i < a->subCount; i++) {
                if (&(a->sub[i]))
                    vlen += EncodedLength(&(a->sub[i]));
            }
            a->valLen = vlen;
        }
        else {
            a->valLen = a->objLen;
        }
    }
    return a->valLen;
}

int EncodeValue(AsnElt* a, int start, int end, byte* dst, int dstOff) {
    if (!a)
        return 0;

    int orig = dstOff;
    if (a->objBuf == NULL) {
        int k = 0;
        for (int i = 0; i < a->subCount; i++) {
            int slen = EncodedLength(&(a->sub[i]));
            dstOff += AsnToBytesEncode5(&(a->sub[i]), start - k, end - k, dst, dstOff);
            k += slen;
        }
    }
    else {
        int from = (start > 0) ? start : 0;
        int to = (end > a->valLen) ? a->valLen : end;
        int len = to - from;
        if (len > 0) {
            MemCpy(dst + dstOff, a->objBuf + (a->valOff + from), len);
            dstOff += len;
        }
    }
    return dstOff - orig;
}

int AsnToBytesEncode5(AsnElt* a, int start, int end, byte* dst, int dstOff) {
    if (a->hasEncodedHeader) {
        int from = a->objOff + ((start > 0) ? start : 0);
        int to = a->objOff + ((end > a->objLen) ? a->objLen : end);
        int len = to - from;
        if (len > 0) {
            MemCpy(&dst[dstOff], &a->objBuf[from], len);
            return len;
        }
        else {
            return 0;
        }
    }

    int off = 0;

    int fb = (a->tagClass << 6) + ((a->sub != NULL) ? 0x20 : 0x00);
    if (a->tagValue < 0x1F) {
        fb |= (a->tagValue & 0x1F);
        if (start <= off && off < end)
            dst[dstOff++] = (byte)fb;
        off++;
    }
    else {
        fb |= 0x1F;
        if (start <= off && off < end)
            dst[dstOff++] = (byte)fb;

        off++;
        int k = 0;
        for (int v = a->tagValue; v > 0; v >>= 7, k += 7);
        while (k > 0) {
            k -= 7;
            int v = (a->tagValue >> k) & 0x7F;
            if (k != 0)
                v |= 0x80;
            if (start <= off && off < end)
                dst[dstOff++] = (byte)v;
            off++;
        }
    }

    int vlen = ValueLength(a);
    if (vlen < 0x80) {
        if (start <= off && off < end)
            dst[dstOff++] = (byte)vlen;
        off++;
    }
    else {
        int k = 0;
        for (int v = vlen; v > 0; v >>= 8, k += 8);
        if (start <= off && off < end)
            dst[dstOff++] = (byte)(0x80 + (k >> 3));
        off++;
        while (k > 0) {
            k -= 8;
            if (start <= off && off < end)
                dst[dstOff++] = (byte)(vlen >> k);
            off++;
        }
    }

    EncodeValue(a, start - off, end - off, dst, dstOff);
    off += vlen;

    return (off > 0) ? off : 0;
}

int AsnToBytesEncode3(AsnElt* a, byte* dst, int dstOff) {
    return AsnToBytesEncode5(a, 0, INT_MAX, dst, dstOff);
}

bool AsnToBytesEncode(AsnElt* a, int* size, byte** ret) {
    *ret = MemAlloc(EncodedLength(a));
    if (!*ret) {
        PRINT_OUT("[x] Failed alloc memory");
        return true;
    }
    *size = AsnToBytesEncode3(a, *ret, 0);
    return false;
}
