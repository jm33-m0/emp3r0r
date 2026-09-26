#include "bofdefs.h"
#include "base.c"
#include "sql.c"


void CheckDatabases(char* server, char* database, char* link, char* impersonate)
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
		internal_printf("[*] Enumerating databases on %s\n\n", server);
	}
	else
	{
		internal_printf("[*] Enumerating databases on %s via %s\n\n", link, server);
	}
	

	//
	// allocate statement handle
	//
	ret = ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
	if (!SQL_SUCCEEDED(ret)) {
		internal_printf("[!] SQLAllocHandle failed\n");
		goto END;
	}

	//
	// Run the query
	//
	SQLCHAR* query = (SQLCHAR*)"SELECT sd.dbid, sd.name, SUSER_SNAME(sd.sid) AS db_owner, d.is_trustworthy_on, sd.crdate, sd.filename "
		"FROM master.dbo.sysdatabases sd "
		"LEFT JOIN sys.databases d ON sd.dbid = d.database_id;";
	if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE)){
		goto END;
	}
	PrintQueryResults(stmt, TRUE);

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
	
	CheckDatabases(server, database, link, impersonate);

	printoutput(TRUE);
};

#else

int main()
{
	internal_printf("============ BASE TEST ============\n\n");
	CheckDatabases("castelblack.north.sevenkingdoms.local", "master", NULL, NULL);

	internal_printf("\n\n============ IMPERSONATE TEST ============\n\n");
	CheckDatabases("castelblack.north.sevenkingdoms.local", "master", NULL, "sa");

	internal_printf("\n\n============ LINK TEST ============\n\n");
	CheckDatabases("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL);
}

#endif
