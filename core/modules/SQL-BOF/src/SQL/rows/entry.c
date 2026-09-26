#include "bofdefs.h"
#include "base.c"
#include "sql.c"


void CheckTableRows(char* server, char* database, char* link, char* impersonate, char* table)
{
    SQLHENV env		= NULL;
    SQLHSTMT stmt 	= NULL;
	SQLHDBC dbc 	= NULL;
	char* useStmt	= NULL;
	char* query		= NULL;
	char* schema	= NULL;
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
		internal_printf("[*] Getting row count from table %s in %s on %s\n\n", table, database, server);
	}
	else
	{
		internal_printf("[*] Getting row count from table %s in %s on %s via %s\n\n", table, database, link, server);
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
	// Construct USE database statement
	//
	char* dbPrefix = "USE ";
	char* dbSuffix = "; ";
	char* tablePrefix = "SELECT COUNT(*) as row_count FROM ";
	char* tableSuffix = ";";

	if (link == NULL)
	{
		//
		// Not using link; need to execute two queries
		//
		size_t useStmtSize = MSVCRT$strlen(dbPrefix) + MSVCRT$strlen(database) + MSVCRT$strlen(dbSuffix) + 1;
		useStmt = (char*)intAlloc(useStmtSize * sizeof(char));

		MSVCRT$strcpy(useStmt, dbPrefix);
		MSVCRT$strncat(useStmt, database, useStmtSize - MSVCRT$strlen(useStmt) - 1);
		MSVCRT$strncat(useStmt, dbSuffix, useStmtSize - MSVCRT$strlen(useStmt) - 1);

		if (!HandleQuery(stmt, (SQLCHAR*)useStmt, link, impersonate, TRUE)){
			goto END;
		}

		//
		// leave cursor open
		//

		//
		// Construct query
		//
		size_t totalSize = MSVCRT$strlen(tablePrefix) + MSVCRT$strlen(table) + MSVCRT$strlen(tableSuffix) + 1;
		query = (char*)intAlloc(totalSize * sizeof(char));
		
		MSVCRT$strcpy(query, tablePrefix);
		MSVCRT$strncat(query, table, totalSize - MSVCRT$strlen(query) - 1);
		MSVCRT$strncat(query, tableSuffix, totalSize - MSVCRT$strlen(query) - 1);

		//
		// Run the query
		//
		if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE)){
			goto END;
		}

		PrintQueryResults(stmt, TRUE);
	}
	else
	{
		char* sep = ".";

		//
		// linked RPC query funkiness, idk what to do so lets get the table schema
		//
		if (!GetTableShema(stmt, link, database, table)){
			internal_printf("[!] Failed to get table schema for %s\n", table);
			goto END;
		}

		schema = GetSingleResult(stmt, FALSE);
		internal_printf("[*] Table schema for %s is: %s\n\n", table, schema);

		//
		// Close the cursor
		//
		ret = ODBC32$SQLCloseCursor(stmt);
		if (!SQL_SUCCEEDED(ret))
		{
			internal_printf("[!] Error closing cursor\n");
			goto END;
		}

		//
		// Prep statement for linked RPC query
		// tableprefix + database + sep + schema + sep + table + suffix
		//
		size_t totalSize = MSVCRT$strlen(tablePrefix) + MSVCRT$strlen(database) + MSVCRT$strlen(sep) + MSVCRT$strlen(schema) + MSVCRT$strlen(sep) + MSVCRT$strlen(table) + MSVCRT$strlen(tableSuffix) + 1;
		query = (char*)intAlloc(totalSize * sizeof(char));

		MSVCRT$strcpy(query, tablePrefix);
		MSVCRT$strncat(query, database,	totalSize - MSVCRT$strlen(query) - 1);
		MSVCRT$strncat(query, sep,		totalSize - MSVCRT$strlen(query) - 1);
		MSVCRT$strncat(query, schema,	totalSize - MSVCRT$strlen(query) - 1);
		MSVCRT$strncat(query, sep,		totalSize - MSVCRT$strlen(query) - 1);
		MSVCRT$strncat(query, table,	totalSize - MSVCRT$strlen(query) - 1);

		if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE)){
			goto END;
		}

		PrintQueryResults(stmt, TRUE);
	}

END:
	if (useStmt != NULL) intFree(useStmt);
	if (query != NULL) intFree(query);
	if (schema != NULL) intFree(schema);
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
	
	CheckTableRows(server, database, link, impersonate, table);

	printoutput(TRUE);
};

#else

int main()
{
	internal_printf("============ BASE TEST ============\n\n");
	CheckTableRows("castelblack.north.sevenkingdoms.local", "master", NULL, NULL, "spt_monitor");

	internal_printf("\n\n============ IMPERSONATE TEST ============\n\n");
	CheckTableRows("castelblack.north.sevenkingdoms.local", "master", NULL, "sa", "spt_monitor");

	internal_printf("\n\n============ LINK TEST ============\n\n");
	CheckTableRows("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL, "spt_monitor");
}

#endif
