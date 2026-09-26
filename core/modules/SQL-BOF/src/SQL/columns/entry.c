#include "bofdefs.h"
#include "base.c"
#include "sql.c"


void CheckTableColumns(char* server, char* database, char* link, char* impersonate, char* table)
{
    SQLHENV env		= NULL;
    SQLHSTMT stmt 	= NULL;
	SQLHDBC dbc 	= NULL;
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
		internal_printf("[*] Displaying columns from table %s in %s on %s\n\n", table, database, server);
	}
	else
	{
		internal_printf("[*] Displaying columns from table %s in %s on %s via %s\n\n", table, database, link, server);
	}
	

	//
	// allocate statement handle
	//
	ret = ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
	if (!SQL_SUCCEEDED(ret)) {
		internal_printf("[!] Error allocating statement handle\n");
		goto END;
	}

	if (link == NULL)
	{

		//
		// Construct USE database statement
		//
		char* dbPrefix = "USE ";
		char* dbSuffix = ";";

		size_t useStmtSize = MSVCRT$strlen(dbPrefix) + MSVCRT$strlen(database) + MSVCRT$strlen(dbSuffix) + 1;
		char* useStmt = (char*)intAlloc(useStmtSize  * sizeof(char));

		MSVCRT$strcpy(useStmt, dbPrefix);
		MSVCRT$strncat(useStmt, database, useStmtSize - MSVCRT$strlen(useStmt) -1);
		MSVCRT$strncat(useStmt, dbSuffix, useStmtSize - MSVCRT$strlen(useStmt) -1);

		if (!HandleQuery(stmt, (SQLCHAR*)useStmt, link, impersonate, FALSE)){
			goto END;
		}

		//
		// Construct query
		//
		char* tablePrefix = "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
							"WHERE TABLE_NAME = '";
		char* tableSuffix = "' ORDER BY ORDINAL_POSITION;";
		
		size_t querySize = MSVCRT$strlen(tablePrefix) + MSVCRT$strlen(table) + MSVCRT$strlen(tableSuffix) + 1;
		char* query = (char*)intAlloc(querySize * sizeof(char));
		
		MSVCRT$strcpy(query, tablePrefix);
		MSVCRT$strncat(query, table, MSVCRT$strlen(query) -1);
		MSVCRT$strncat(query, tableSuffix, MSVCRT$strlen(query) -1);

		//
		// Run the query
		//
		if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE)){
			goto END;
		}
		PrintQueryResults(stmt, TRUE);

		intFree(query);
		intFree(useStmt);
	}
	else
	{
		//
		// Construct query
		//
		char* dbPrefix = "SELECT COLUMN_NAME FROM ";
		char* tablePrefix = ".INFORMATION_SCHEMA.COLUMNS "
							"WHERE TABLE_NAME = '";
		char* tableSuffix = "' ORDER BY ORDINAL_POSITION;";
		
		size_t querySize = MSVCRT$strlen(dbPrefix) + MSVCRT$strlen(database) + MSVCRT$strlen(tablePrefix) + MSVCRT$strlen(table) + MSVCRT$strlen(tableSuffix) + 1;
		char* query = (char*)intAlloc(querySize * sizeof(char));

		MSVCRT$strcpy(query, dbPrefix);
		MSVCRT$strncat(query, database, querySize - MSVCRT$strlen(query) -1);
		MSVCRT$strncat(query, tablePrefix, querySize - MSVCRT$strlen(query) -1);
		MSVCRT$strncat(query, table, querySize - MSVCRT$strlen(query) -1);
		MSVCRT$strncat(query, tableSuffix, querySize - MSVCRT$strlen(query) -1);

		//
		// Run the query
		//
		if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE)){
			goto END;
		}
		PrintQueryResults(stmt, TRUE);

		intFree(query);
	}

END:
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
	char* table;
	char* link;
	char* impersonate;

	//
	// parse beacon args 
	//
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	
	server	 	= BeaconDataExtract(&parser, NULL);
	database 	= BeaconDataExtract(&parser, NULL);
	table 		= BeaconDataExtract(&parser, NULL);
	link 		= BeaconDataExtract(&parser, NULL);
	impersonate = BeaconDataExtract(&parser, NULL);


	server = *server == 0 ? "localhost" : server;
	database = *database == 0 ? "master" : database;
	table = *table == 0 ? NULL : table;
	link = *link  == 0 ? NULL : link;
	impersonate = *impersonate == 0 ?  NULL : impersonate;

	if(!bofstart())
	{
		return;
	}

	if (table == NULL)
	{
		internal_printf("[!] Table argument is required\n");
		printoutput(TRUE);
		return;
	}

	if (UsingLinkAndImpersonate(link, impersonate))
	{
		return;
	}
	
	CheckTableColumns(server, database, link, impersonate, table);

	printoutput(TRUE);
};

#else

int main()
{
	internal_printf("============ BASE TEST ============\n\n");
	CheckTableColumns("castelblack.north.sevenkingdoms.local", "master", NULL, NULL, "spt_monitor");

	internal_printf("\n\n============ IMPERSONATE TEST ============\n\n");
	CheckTableColumns("castelblack.north.sevenkingdoms.local", "master", NULL, "sa", "spt_monitor");

	internal_printf("\n\n============ LINK TEST ============\n\n");
	CheckTableColumns("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL, "spt_monitor");
}

#endif
