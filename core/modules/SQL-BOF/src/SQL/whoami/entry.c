#include "bofdefs.h"
#include "base.c"
#include "sql.c"

void FreeResults(char** results)
{
	for (int i = 0; results[i] != NULL; i++)
	{
		intFree(results[i]);
	}
	intFree(results);
}

void PrintMemberStatus(char* roleName, char* status)
{
	if (status[0] == '0') {
		internal_printf(" |--> User is NOT a member of the %s role\n", roleName);
	}
	else {
		internal_printf(" |--> User is a member of the %s role\n", roleName);
	}
}

void Whoami(char* server, char* database, char* link, char* impersonate)
{
    SQLHENV env			= NULL;
    SQLHSTMT stmt 		= NULL;
	SQLHDBC dbc 		= NULL;
	char* sysUser 		= NULL;
	char* mappedUser 	= NULL;
	char** dbRoles 		= NULL;
	SQLRETURN ret;

	//
	// default server roles
	//
	char* roles[] = { 
		"sysadmin",
		"setupadmin", 
		"serveradmin", 
		"securityadmin",
        "processadmin",
		"diskadmin",
		"dbcreator",
		"bulkadmin"
	};

    if (link == NULL)
	{
		dbc = ConnectToSqlServer(&env, server, database);
	}
	else
	{
		dbc = ConnectToSqlServer(&env, server, NULL);
	}

    if (dbc == NULL)
	{
		goto END;
	}

	if (link == NULL)
	{
		internal_printf("[*] Determining user permissions on %s\n", server);
	}
	else
	{
		internal_printf("[*] Determining user permissions on %s via %s\n", link, server);
	}
	

	//
	// allocate statement handle
	//
	ret = ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
	if (!SQL_SUCCEEDED(ret))
	{
		internal_printf("[!] Failed to allocate statement handle\n");
		goto END;
	}

	//
	// first query
	//
	SQLCHAR* query = (SQLCHAR*)"SELECT SYSTEM_USER;";
	if (!HandleQuery(stmt, query, link, impersonate, FALSE))
	{
		goto END;
	}
	sysUser = GetSingleResult(stmt, FALSE);
	internal_printf("[*] Logged in as %s\n", sysUser);

	//
	// close the cursor
	//
	ODBC32$SQLCloseCursor(stmt);

	//
	// second query
	//
	query = (SQLCHAR*)"SELECT USER_NAME();";
	if (!HandleQuery(stmt, query, link, impersonate, FALSE))
	{
		goto END;
	}
	mappedUser = GetSingleResult(stmt, FALSE);
	internal_printf("[*] Mapped to the user %s\n", mappedUser);

	//
	// close the cursor
	//
	ODBC32$SQLCloseCursor(stmt);

	//
	// third query
	//
	internal_printf("[*] Gathering roles...\n");
	query = (SQLCHAR*)"SELECT [name] from sysusers where issqlrole = 1;";
	if (!HandleQuery(stmt, query, link, impersonate, FALSE))
	{
		goto END;
	}
	dbRoles = GetMultipleResults(stmt, FALSE);
	
	//
	// close the cursor
	//
	ODBC32$SQLCloseCursor(stmt);
	
	//
	// fourth query (loop)
	//
	for (int i = 0; dbRoles[i] != NULL; i++)
	{
		char* role = dbRoles[i];
		char* query = (char*)intAlloc(MSVCRT$strlen(role) + 32);
		MSVCRT$sprintf(query, "SELECT IS_MEMBER('%s');", role);
		if (!HandleQuery(stmt, query, link, impersonate, FALSE))
		{
			goto END;
		}
		
		char* result = GetSingleResult(stmt, FALSE);
		PrintMemberStatus(role, result);
		
		intFree(query);
		intFree(result);
		
		ret = ODBC32$SQLCloseCursor(stmt);
		if (!SQL_SUCCEEDED(ret))
		{
			internal_printf("[!] Failed to close cursor\n");
			goto END;
		}
	}
	
	//
	// fifth query (loop)
	//
	for (int i = 0; i < sizeof(roles) / sizeof(roles[0]); i++)
	{
		char* role = roles[i];
		char* query = (char*)intAlloc(MSVCRT$strlen(role) + 32);
		MSVCRT$sprintf(query, "SELECT IS_SRVROLEMEMBER('%s');", role);
		if (!HandleQuery(stmt, query, link, impersonate, FALSE))
		{
			goto END;
		}
		
		char* result = GetSingleResult(stmt, FALSE);
		PrintMemberStatus(role, result);

		intFree(query);
		intFree(result);
		
		ret = ODBC32$SQLCloseCursor(stmt);
		if (!SQL_SUCCEEDED(ret))
		{
			internal_printf("[!] Failed to close cursor\n");
			goto END;
		}
	}

END:
	if (sysUser != NULL) intFree(sysUser);
	if (mappedUser != NULL) intFree(mappedUser);
	if (dbRoles != NULL) FreeResults(dbRoles);
	ODBC32$SQLCloseCursor(stmt);
	DisconnectSqlServer(env, dbc, stmt);
}


#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	//
	// usage: whoami <server> <database> <link> <impersonate>
	//
	char* server;
	char* database;
	char* link;
	char* impersonate;

	//
	// parse beacon args 
	//
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);

	server 		= BeaconDataExtract(&parser, NULL);
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

	Whoami(server, database, link, impersonate);

	printoutput(TRUE);
};

#else

int main()
{
	internal_printf("============ BASE TEST ============\n\n");
	Whoami("castelblack.north.sevenkingdoms.local", "master", NULL, NULL);

	internal_printf("\n============ IMPERSONATE TEST ============\n\n");
	Whoami("castelblack.north.sevenkingdoms.local", "master", NULL, "sa");

	internal_printf("\n============ LINK TEST ====\n\n");
	Whoami("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL);
}

#endif
