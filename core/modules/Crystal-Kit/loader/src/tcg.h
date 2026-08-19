/*
 * Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
// used by both the Pico Loader and DLL loader
typedef struct {
    __typeof__(LoadLibraryA)   * LoadLibraryA;
    __typeof__(GetProcAddress) * GetProcAddress;
} IMPORTFUNCS;
 
// linker intrinsic to map a function hash to a hook registered via Crystal Palace
FARPROC __resolve_hook(DWORD funcHash);
 
/*
 * Structs used by our DLL loader
 */
 
#define PTR_OFFSET(x, y) ( (void *)(x) + (ULONG)(y) )
#define DEREF( name )*(UINT_PTR *)(name)
 
typedef struct {
    IMAGE_DOS_HEADER      * DosHeader;
    IMAGE_NT_HEADERS      * NtHeaders;
    IMAGE_OPTIONAL_HEADER * OptionalHeader;
} DLLDATA;
 
/*
 * utility functions
 */
DWORD adler32sum(unsigned char * buffer, DWORD length);
DWORD ror13hash(const char * c);
 
/*
 * printf-style debugging.
 */
void dprintf(char * format, ...);
 
/*
 * PICO running functions
 */
typedef void (*PICOMAIN_FUNC)(char * arg);
 
PICOMAIN_FUNC PicoGetExport(char * src, char * base, int tag);
PICOMAIN_FUNC PicoEntryPoint(char * src, char * base);
int PicoCodeSize(char * src);
int PicoDataSize(char * src);
void PicoLoad(IMPORTFUNCS * funcs, char * src, char * dstCode, char * dstData);
 
/*
 * Resolve functions by walking the export address table
 */
FARPROC findFunctionByHash(HANDLE hModule, DWORD wantedFunctionHash);
HANDLE findModuleByHash(DWORD moduleHash);
 
/*
 * DLL parsing and loading functions
 */
typedef BOOL WINAPI (*DLLMAIN_FUNC)(HINSTANCE, DWORD, LPVOID);
 
DLLMAIN_FUNC EntryPoint(DLLDATA * dll, void * base);
IMAGE_DATA_DIRECTORY * GetDataDirectory(DLLDATA * dll, UINT entry);
void LoadDLL(DLLDATA * dll, char * src, char * dst);
void LoadSections(DLLDATA * dll, char * src, char * dst);
void ParseDLL(char * src, DLLDATA * data);
void ProcessImports(IMPORTFUNCS * funcs, DLLDATA * dll, char * dst);
void ProcessRelocations(DLLDATA * dll, char * src, char * dst);
DWORD SizeOfDLL(DLLDATA * data);
 
/*
 * A macro to figure out our caller
 * https://github.com/rapid7/ReflectiveDLLInjection/blob/81cde88bebaa9fe782391712518903b5923470fb/dll/src/ReflectiveLoader.c#L34C1-L46C1
 */
#ifdef __MINGW32__
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#pragma intrinsic(_ReturnAddress)
#define WIN_GET_CALLER() _ReturnAddress()
#endif