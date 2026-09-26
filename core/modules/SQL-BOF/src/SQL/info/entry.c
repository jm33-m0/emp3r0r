#include "bofdefs.h"
#include "base.c"
#include "sql.c"

typedef struct SQLINFO {
	char* 	ComputerName;
	char* 	DomainName;
	char*	ServicePid;
	char* 	ServiceName;
	char* 	ServiceAccount;
	char*	AuthenticationMode;
	char*	ForcedEncryption;
	char*	Clustered;
	char*	SqlServerVersionNumber;
	char*	SqlServerMajorVersion;
	char*	SqlServerEdition;
	char*	SqlServerServicePack;
	char*	OsArchitecture;
	char*	OsMachineType;
	char*	OsVersion;
	char*	OsVersionNumber;
	char*	CurrentLogin;
	BOOL	IsSysAdmin;
	char*	ActiveSessions;
} SQLINFO;

void FreeAttr(char* attr) {
	if (attr == NULL) {
		return;
	}

	intFree(attr);
}

void FreeSqlInfo(SQLINFO* info) {
    if (info == NULL) {
        return;
    }

	FreeAttr(info->ComputerName);
	FreeAttr(info->DomainName);
	FreeAttr(info->ServicePid);
	FreeAttr(info->ServiceName);
	FreeAttr(info->ServiceAccount);
	FreeAttr(info->AuthenticationMode);
	FreeAttr(info->ForcedEncryption);
	FreeAttr(info->Clustered);
	FreeAttr(info->SqlServerVersionNumber);
	FreeAttr(info->SqlServerMajorVersion);
	FreeAttr(info->SqlServerEdition);
	FreeAttr(info->SqlServerServicePack);
	FreeAttr(info->OsArchitecture);
	FreeAttr(info->OsMachineType);
	FreeAttr(info->OsVersion);
	FreeAttr(info->OsVersionNumber);
	FreeAttr(info->CurrentLogin);
	FreeAttr(info->ActiveSessions);
}


void GetSQLInfo(char* server, char* database) {
	SQLHENV env		= NULL;
	SQLHSTMT stmt 	= NULL;
	SQLRETURN ret;
	SQLINFO info;
	memset(&info, 0, sizeof(SQLINFO));
	
	SQLHDBC dbc = ConnectToSqlServer(&env, server, database);

	if (dbc == NULL)
	{
		goto END;
	}

	internal_printf("[*] Extracting SQL server information\n");

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
	// first query - IsSysAdmin
	//
	SQLCHAR* query = (SQLCHAR*)"SELECT IS_SRVROLEMEMBER('sysadmin');";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	char* result = GetSingleResult(stmt, FALSE);
	if ( result[0] == '1')
	{
		info.IsSysAdmin = TRUE;
	}
	else
	{
		info.IsSysAdmin = FALSE;
	}

	intFree(result);
	ODBC32$SQLCloseCursor(stmt);

	//
	// second query - DomainName
	//
	query = (SQLCHAR*)"SELECT @@SERVERNAME;";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.ComputerName = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// third query - DomainName
	//
	query = (SQLCHAR*)"SELECT default_domain();";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.DomainName = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// fourth query - ServicePid
	//
	query = (SQLCHAR*)"SELECT CONVERT(VARCHAR(255), SERVERPROPERTY('processid'));";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.ServicePid = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// fifth query - ServiceName
	//
	query = (SQLCHAR*)"DECLARE @SQLServerServiceName varchar(250)\n"
            "DECLARE @SQLServerInstance varchar(250)\n"
            "if @@SERVICENAME = 'MSSQLSERVER'\n"
            "BEGIN\n"
            "set @SQLServerInstance = 'SYSTEM\\CurrentControlSet\\Services\\MSSQLSERVER'\n"
            "set @SQLServerServiceName = 'MSSQLSERVER'\n"
            "END\n"
            "ELSE\n"
            "BEGIN\n"
            "set @SQLServerInstance = 'SYSTEM\\CurrentControlSet\\Services\\MSSQL$'+cast(@@SERVICENAME as varchar(250))\n"
            "set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))\n"
            "END\n"
            "SELECT @SQLServerServiceName;";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.ServiceName = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// sixth query - ServiceAccount
	//
	query = (SQLCHAR*)"DECLARE @SQLServerInstance varchar(250)\n"
            "if @@SERVICENAME = 'MSSQLSERVER'\n"
            "BEGIN\n"
            "set @SQLServerInstance = 'SYSTEM\\CurrentControlSet\\Services\\MSSQLSERVER'\n"
            "END\n"
            "ELSE\n"
            "BEGIN\n"
            "set @SQLServerInstance = 'SYSTEM\\CurrentControlSet\\Services\\MSSQL$'+cast(@@SERVICENAME as varchar(250))\n"
            "END\n"
            "DECLARE @ServiceAccountName varchar(250)\n"
            "EXECUTE master.dbo.xp_instance_regread\n"
            "N'HKEY_LOCAL_MACHINE', @SQLServerInstance,\n"
            "N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'\n"
            "SELECT @ServiceAccountName;";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.ServiceAccount = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// seventh query - AuthenticationMode
	//
	query = (SQLCHAR*)"DECLARE @AuthenticationMode INT\n"
            "EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',\n"
            "N'Software\\Microsoft\\MSSQLServer\\MSSQLServer',\n"
            "N'LoginMode', @AuthenticationMode OUTPUT\n"
            "(SELECT CASE @AuthenticationMode\n"
            "WHEN 1 THEN 'Windows Authentication'\n"
            "WHEN 2 THEN 'Windows and SQL Server Authentication'\n"
            "ELSE 'Unknown'\n"
            "END);";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.AuthenticationMode = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// eighth query - ForcedEncryption
	//
	query = (SQLCHAR*)"BEGIN TRY\n"
            "DECLARE @ForcedEncryption INT\n"
            "EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',\n"
            "N'SOFTWARE\\MICROSOFT\\Microsoft SQL Server\\MSSQLServer\\SuperSocketNetLib',\n"
            "N'ForceEncryption', @ForcedEncryption OUTPUT\n"
            "END TRY\n"
            "BEGIN CATCH	            \n"
            "END CATCH\n"
            "SELECT @ForcedEncryption;";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.ForcedEncryption = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// ninth query - Clustered
	//
	query = (SQLCHAR*)"SELECT CASE  SERVERPROPERTY('IsClustered')\n"
            "WHEN 0\n"
            "THEN 'No'\n"
            "ELSE 'Yes'\n"
            "END";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.Clustered = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// 10th query - SqlServerVesionNumber
	//
	query = (SQLCHAR*)"SELECT CONVERT(VARCHAR(255), SERVERPROPERTY('productversion'));";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.SqlServerVersionNumber = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// 11th query - SqlServerMajorVersion
	//
	query = (SQLCHAR*)"SELECT SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4);";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.SqlServerMajorVersion = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// 12th query - SqlServerEdition
	//
	query = (SQLCHAR*)"SELECT CONVERT(VARCHAR(255), SERVERPROPERTY('Edition'));";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.SqlServerEdition = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// 12th query - SqlServerServicePack
	//
	query = (SQLCHAR*)"SELECT CONVERT(VARCHAR(255), SERVERPROPERTY('ProductLevel'));";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.SqlServerServicePack = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// 13th query - OsArchitecture
	//
	query = (SQLCHAR*)"SELECT SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3);";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.OsArchitecture = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// 14th query - OsMachineType
	//
	if (info.IsSysAdmin)
	{
		query = (SQLCHAR*)"DECLARE @MachineType  SYSNAME\n"
                "EXECUTE master.dbo.xp_regread\n"
                "@rootkey		= N'HKEY_LOCAL_MACHINE',\n"
                "@key			= N'SYSTEM\\CurrentControlSet\\Control\\ProductOptions',\n"
                "@value_name	= N'ProductType',\n"
                "@value			= @MachineType output\n"
                "SELECT @MachineType;";
		if (!ExecuteQuery(stmt, query))
		{
			goto END;
		}
		info.OsMachineType = GetSingleResult(stmt, FALSE);
		ODBC32$SQLCloseCursor(stmt);
	}

	//
	// 15th query - OsVersion
	//
	if (info.IsSysAdmin)
	{
		query = (SQLCHAR*)"DECLARE @ProductName  SYSNAME\n"
                "EXECUTE master.dbo.xp_regread\n"
                "@rootkey		= N'HKEY_LOCAL_MACHINE',\n"
                "@key			= N'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion',\n"
                "@value_name	= N'ProductName',\n"
                "@value			= @ProductName output\n"
                "SELECT @ProductName;";
		if (!ExecuteQuery(stmt, query))
		{
			goto END;
		}
		info.OsVersion = GetSingleResult(stmt, FALSE);
		ODBC32$SQLCloseCursor(stmt);
	}

	//
	// 16th query - OsVersionNumber
	//
	query = (SQLCHAR*)"SELECT RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows Server', @@VERSION), 19), 4);";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.OsVersionNumber = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// 17th query - CurrentLogin
	//
	query = (SQLCHAR*)"SELECT SYSTEM_USER;";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.CurrentLogin = GetSingleResult(stmt, FALSE);
	ODBC32$SQLCloseCursor(stmt);

	//
	// 18th query - ActiveSessions
	//
	query = (SQLCHAR*)"SELECT COUNT(*) FROM [sys].[dm_exec_sessions] WHERE status = 'running';";
	if (!ExecuteQuery(stmt, query))
	{
		goto END;
	}
	info.ActiveSessions = GetSingleResult(stmt, FALSE);

	

	//
	// print all the results
	//
	internal_printf("%-30s: %s\n", " |--> ComputerName", info.ComputerName);
	internal_printf("%-30s: %s\n", " |--> DomainName", info.DomainName);
	internal_printf("%-30s: %s\n", " |--> ServicePid", info.ServicePid);
	internal_printf("%-30s: %s\n", " |--> ServiceName", info.ServiceName);
	internal_printf("%-30s: %s\n", " |--> ServiceAccount", info.ServiceAccount);
	internal_printf("%-30s: %s\n", " |--> AuthenticationMode", info.AuthenticationMode);
	internal_printf("%-30s: %s\n", " |--> ForcedEncryption", info.ForcedEncryption);
	internal_printf("%-30s: %s\n", " |--> Clustered", info.Clustered);
	internal_printf("%-30s: %s\n", " |--> SqlServerVersionNumber", info.SqlServerVersionNumber);
	internal_printf("%-30s: %s\n", " |--> SqlServerMajorVersion", info.SqlServerMajorVersion);
	internal_printf("%-30s: %s\n", " |--> SqlServerEdition", info.SqlServerEdition);
	internal_printf("%-30s: %s\n", " |--> SqlServerServicePack", info.SqlServerServicePack);
	internal_printf("%-30s: %s\n", " |--> OsArchitecture", info.OsArchitecture);

	if (info.IsSysAdmin)
	{
		internal_printf("%-30s: %s\n", " |--> OsMachineType", info.OsMachineType);
		internal_printf("%-30s: %s\n", " |--> OsVersion", info.OsVersion);
	}

	internal_printf("%-30s: %s\n", " |--> OsVersionNumber", info.OsVersionNumber);
	internal_printf("%-30s: %s\n", " |--> CurrentLogin", info.CurrentLogin);
	internal_printf("%-30s: %s\n", " |--> IsSysAdmin", info.IsSysAdmin ? "True" : "False");
	internal_printf("%-30s: %s\n", " |--> ActiveSessions", info.ActiveSessions);

END:
	FreeSqlInfo(&info);
	ODBC32$SQLCloseCursor(stmt);
	DisconnectSqlServer(env, dbc, stmt);
}


#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	char* server 	= NULL;
	char* database 	= NULL;

	//
	// parse beacon args 
	//
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	server = BeaconDataExtract(&parser, NULL);
	database = BeaconDataExtract(&parser, NULL);

	server = *server == 0 ? "localhost" : server;
	database = *database == 0 ? "master" : database;

	if(!bofstart())
	{
		return;
	}
	
	GetSQLInfo(server, database);

	printoutput(TRUE);
};

#else

int main()
{
	internal_printf("============ BASE TEST ============\n\n");
	GetSQLInfo("castelblack.north.sevenkingdoms.local", "master");
}

#endif
