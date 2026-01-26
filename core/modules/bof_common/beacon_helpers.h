#ifndef BEACON_HELPERS_H
#define BEACON_HELPERS_H

#include "syscall_helpers.h"

// Data parser struct
typedef struct {
    char *buffer;    // Current position
    int length;      // Remaining length
    int size;        // Initial size (not always used but kept for compat)
} datap;

// Initialize parser
static inline void BeaconDataParse(datap *parser, char *buffer, int size) {
    if (size < 4) {
        parser->buffer = buffer;
        parser->length = 0;
        parser->size = 0;
        return;
    }
    // First 4 bytes are total length of the body
    int len = *(int*)buffer;
    parser->buffer = buffer + 4;
    parser->length = len;
    parser->size = len;
}

// Read integer (4 bytes)
static inline int BeaconDataInt(datap *parser) {
    if (parser->length < 4) return 0;
    int val = *(int*)parser->buffer;
    parser->buffer += 4;
    parser->length -= 4;
    return val;
}

// Read short (2 bytes)
static inline short BeaconDataShort(datap *parser) {
    if (parser->length < 2) return 0;
    short val = *(short*)parser->buffer;
    parser->buffer += 2;
    parser->length -= 2;
    return val;
}

// Read length (4 bytes) - usually helper for Extract
static inline int BeaconDataLength(datap *parser) {
    if (parser->length < 4) return 0;
    int val = *(int*)parser->buffer;
    parser->buffer += 4;
    parser->length -= 4;
    return val;
}

// Extract binary/string data
static inline char *BeaconDataExtract(datap *parser, int *size) {
    if (parser->length < 4) {
        if (size) *size = 0;
        return NULL;
    }
    int len = *(int*)parser->buffer;
    parser->buffer += 4;
    parser->length -= 4;
    
    if (len > parser->length) {
        if (size) *size = 0;
        return NULL;
    }
    
    char *ptr = parser->buffer;
    parser->buffer += len;
    parser->length -= len;
    
    if (size) *size = len;
    return ptr;
}

// Helper for 'S' type strings (null terminated)
// Returns pointer to string.
static inline char *BeaconDataString(datap *parser) {
    int len = 0;
    char *str = BeaconDataExtract(parser, &len);
    // 'S' type guarantees null terminator at the end of the buffer?
    // In loader_linux.go we wrote len+1 bytes, including the null.
    // So str[len-1] should be 0.
    return str; 
}

#endif
