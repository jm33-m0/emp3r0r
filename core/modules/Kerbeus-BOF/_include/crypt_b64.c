#pragma once
#include "functions.c"

char* base64_encode(byte* input, size_t input_len) {
    char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t output_len = 4 * ((input_len + 2) / 3);
    byte* output = MemAlloc(output_len + 1);
    if (output == NULL)
        return NULL;

    size_t i = 0, j = 0;
    while (i < input_len) {
        UINT octet_a = i < input_len ? input[i++] : 0;
        UINT octet_b = i < input_len ? input[i++] : 0;
        UINT octet_c = i < input_len ? input[i++] : 0;

        UINT triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        output[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        output[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        output[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        output[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }

    if (input_len % 3 == 1) {
        output[output_len - 1] = '=';
        output[output_len - 2] = '=';
    }
    else if (input_len % 3 == 2) {
        output[output_len - 1] = '=';
    }

    output[output_len] = '\0';
    return output;
}

int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1; // Invalid character
}

byte* base64_decode(byte* input, int* output_len) {
    int input_len = my_strlen(input);
    int padding = 0;
    if (input_len == 0) {
        *output_len = 0;
        return NULL;
    }

    if (input[input_len - 1] == '=') {
        padding++;
        if (input[input_len - 2] == '=') {
            padding++;
        }
    }

    *output_len = (input_len * 3) / 4 - padding;
    byte* output = MemAlloc(*output_len);
    if (output == NULL)
        return NULL;

    size_t i = 0, j = 0;
    while (i < input_len - padding) {
        UINT sextet_a = input[i] == '=' ? 0 : (UINT)base64_decode_char(input[i++]);
        UINT sextet_b = input[i] == '=' ? 0 : (UINT)base64_decode_char(input[i++]);
        UINT sextet_c = input[i] == '=' ? 0 : (UINT)base64_decode_char(input[i++]);
        UINT sextet_d = input[i] == '=' ? 0 : (UINT)base64_decode_char(input[i++]);

        UINT triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < *output_len)
            output[j++] = (triple >> 16) & 0xFF;
        if (j < *output_len)
            output[j++] = (triple >> 8) & 0xFF;
        if (j < *output_len)
            output[j++] = triple & 0xFF;
    }
    return output;
}