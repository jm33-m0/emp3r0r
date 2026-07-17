#include <windows.h>
/*
 * Beacon Object Files (BOF)
 * -------------------------
 * A Beacon Object File is a light-weight post exploitation tool that runs
 * with Beacon's inline-execute command.
 *
 * Additional BOF resources are available here:
 *   - https://github.com/Cobalt-Strike/bof_template
 *
 * Cobalt Strike 4.x
 * ChangeLog:
 *    1/25/2022: updated for 4.5
 *    7/18/2023: Added BeaconInformation API for 4.9
 *    7/31/2023: Added Key/Value store APIs for 4.9
 *                  BeaconAddValue, BeaconGetValue, and BeaconRemoveValue
 *    8/31/2023: Added Data store APIs for 4.9
 *                  BeaconDataStoreGetItem, BeaconDataStoreProtectItem,
 *                  BeaconDataStoreUnprotectItem, and BeaconDataStoreMaxEntries
 *    9/01/2023: Added BeaconGetCustomUserData API for 4.9
 */

/* data API */
typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT char *  BeaconDataPtr(datap * parser, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap * parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap * parser);
DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);

/* format API */
typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, char * text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp * format, int * size);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp * format, int value);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

DECLSPEC_IMPORT void   BeaconOutput(int type, char * data, int len);
DECLSPEC_IMPORT void   BeaconPrintf(int type, char * fmt, ...);


/* Token Functions */
DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken();
DECLSPEC_IMPORT BOOL   BeaconIsAdmin();

/* Spawn+Inject Functions */
DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
DECLSPEC_IMPORT void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pInfo);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
DECLSPEC_IMPORT BOOL   toWideChar(char * src, wchar_t * dst, int max);

/* Beacon Information */
/*
 *  ptr  - pointer to the base address of the allocated memory.
 *  size - the number of bytes allocated for the ptr.
 */
typedef struct {
    char * ptr;
    size_t size;
} HEAP_RECORD;
#define MASK_SIZE 13

/*
 *  sleep_mask_ptr        - pointer to the sleep mask base address
 *  sleep_mask_text_size  - the sleep mask text section size
 *  sleep_mask_total_size - the sleep mask total memory size
 *
 *  beacon_ptr   - pointer to beacon's base address
 *                 The stage.obfuscate flag affects this value when using CS default loader.
 *                    true:  beacon_ptr = allocated_buffer - 0x1000 (Not a valid address)
 *                    false: beacon_ptr = allocated_buffer (A valid address)
 *                 For a UDRL the beacon_ptr will be set to the 1st argument to DllMain
 *                 when the 2nd argument is set to DLL_PROCESS_ATTACH.
 *  sections     - list of memory sections beacon wants to mask. These are offset values
 *                 from the beacon_ptr and the start value is aligned on 0x1000 boundary.
 *                 A section is denoted by a pair indicating the start and end offset values.
 *                 The list is terminated by the start and end offset values of 0 and 0.
 *  heap_records - list of memory addresses on the heap beacon wants to mask.
 *                 The list is terminated by the HEAP_RECORD.ptr set to NULL.
 *  mask         - the mask that beacon randomly generated to apply
 */
typedef struct {
    char  * sleep_mask_ptr;
    DWORD   sleep_mask_text_size;
    DWORD   sleep_mask_total_size;

    char  * beacon_ptr;
    DWORD * sections;
    HEAP_RECORD * heap_records;
    char    mask[MASK_SIZE];
} BEACON_INFO;

DECLSPEC_IMPORT void   BeaconInformation(BEACON_INFO * info);

/* Key/Value store functions
 *    These functions are used to associate a key to a memory address and save
 *    that information into beacon.  These memory addresses can then be
 *    retrieved in a subsequent execution of a BOF.
 *
 *    key - the key will be converted to a hash which is used to locate the
 *          memory address.
 *
 *    ptr - a memory address to save.
 *
 * Considerations:
 *    - The contents at the memory address is not masked by beacon.
 *    - The contents at the memory address is not released by beacon.
 *
 */
DECLSPEC_IMPORT BOOL BeaconAddValue(const char * key, void * ptr);
DECLSPEC_IMPORT void * BeaconGetValue(const char * key);
DECLSPEC_IMPORT BOOL BeaconRemoveValue(const char * key);

/* Beacon Data Store functions
 *    These functions are used to access items in Beacon's Data Store.
 *    BeaconDataStoreGetItem returns NULL if the index does not exist.
 *
 *    The contents are masked by default, and BOFs must unprotect the entry
 *    before accessing the data buffer. BOFs must also protect the entry
 *    after the data is not used anymore.
 *
 */

#define DATA_STORE_TYPE_EMPTY 0
#define DATA_STORE_TYPE_GENERAL_FILE 1

typedef struct {
    int type;
    DWORD64 hash;
    BOOL masked;
    char* buffer;
    size_t length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

DECLSPEC_IMPORT PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index);
DECLSPEC_IMPORT void BeaconDataStoreProtectItem(size_t index);
DECLSPEC_IMPORT void BeaconDataStoreUnprotectItem(size_t index);
DECLSPEC_IMPORT size_t BeaconDataStoreMaxEntries();

/* Beacon User Data functions */
DECLSPEC_IMPORT char * BeaconGetCustomUserData();
