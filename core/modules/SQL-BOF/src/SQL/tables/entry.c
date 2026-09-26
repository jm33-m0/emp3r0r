#include "bofdefs.h"
#include "base.c"
#include "sql.c"


void CheckTables(char* server, char* database, char* link, char* impersonate)
{
    SQLHENV env		= NULL;
    SQLHSTMT stmt 	= NULL;
	SQLHDBC dbc 	= NULL;
	char* query 	= NULL;
	SQLRETURN ret;

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
		internal_printf("[*] Enumerating tables in the %s database on %s\n\n", database, server);
	}
	else
	{
		internal_printf("[*] Enumerating tables in the %s database on %s via %s\n\n", database, link, server);
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

	//
	// Construct query
	//
	char* prefix = "SELECT * FROM ";
	char* suffix = ".INFORMATION_SCHEMA.TABLES;";
	
	size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(database) + MSVCRT$strlen(suffix) + 1;
	query = (char*)intAlloc(totalSize * sizeof(char));
	
	MSVCRT$strcpy(query, prefix);
	MSVCRT$strncat(query, database, totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, suffix, 	totalSize - MSVCRT$strlen(query) - 1);

	//
	// Run the query
	//
	if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE)){
		goto END;
	}

	PrintQueryResults(stmt, TRUE);

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

	//
	// parse beacon args 
	//
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	
	server	 	= BeaconDataExtract(&parser, NULL);
	database 	= BeaconDataExtract(&parser, NULL);
	link 		= BeaconDataExtract(&parser, NULL);
	impersonate = BeaconDataExtract(&parser, NULL);

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
	
	CheckTables(server, database, link, impersonate);

	printoutput(TRUE);
};

#else

int main()
{
	internal_printf("============ BASE TEST ============\n\n");
	CheckTables("castelblack.north.sevenkingdoms.local", "master", NULL, NULL);

	internal_printf("\n\n============ IMPERSONATE TEST ============\n\n");
	CheckTables("castelblack.north.sevenkingdoms.local", "master", NULL, "sa");

	internal_printf("\n\n============ LINK TEST ============\n\n");
	CheckTables("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL);
}

#endif
