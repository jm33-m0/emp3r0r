#include "bofdefs.h"
#include "base.c"
#include "sql.c"
#include "sql_modules.c"
#include "sql_agent.c"


void CheckAgentStatus(char* server, char* database, char* link, char* impersonate)
{
    SQLHENV env			 = NULL;
    SQLHSTMT stmt 		 = NULL;
	SQLHDBC dbc 		 = NULL;
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
		internal_printf("[*] Getting SQL agent status on %s\n\n", server);
	}
	else
	{
		internal_printf("[*] Getting SQL agent status on %s via %s\n\n", link, server);
	}

	//
	// allocate statement handle
	//
	ret = ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
	if (!SQL_SUCCEEDED(ret)) {
		internal_printf("[!] Failed to allocate statement handle\n");
		goto END;
	}

	if (!IsAgentRunning(stmt, link, impersonate))
	{
		internal_printf("[!] SQL Agent is not running\n");
		goto END;
	}

	//
	// Close the cursor
	//
	ret = ODBC32$SQLCloseCursor(stmt);
	if (!SQL_SUCCEEDED(ret)) {
		internal_printf("[!] Failed to close cursor\n");
		goto END;
	}

	internal_printf("[*] SQL Agent is running\n\n");

	if (!GetAgentJobs(stmt, link, impersonate))
	{
		internal_printf("[!] Failed to get agent jobs\n");
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
	
	CheckAgentStatus(server, database, link, impersonate);

	printoutput(TRUE);
};

#else

int main()
{
	//
	// GOAD uses SQLExpress so turning to makeshift lab here
	//
	internal_printf("============ BASE TEST ============\n\n");
	CheckAgentStatus("192.168.0.215", "master", NULL, NULL);

	internal_printf("\n\n============ IMPERSONATE TEST ============\n\n");
	CheckAgentStatus("192.168.0.215", "master", NULL, "sa");

	internal_printf("\n\n============ LINK TEST ============\n\n");
	CheckAgentStatus("192.168.0.215", "master", "TRETOGOR", NULL);
}

#endif
