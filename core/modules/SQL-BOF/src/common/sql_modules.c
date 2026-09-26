//
// imported by bof entry files to check or toggle status of modules
// include statmenet should be after the sql.c include
//
#include <windows.h>
#include <sql.h>
#include "bofdefs.h"

//
// Configure sp_serveroption or sp_configure
//
BOOL ToggleModule(SQLHSTMT stmt, char* name, char* value, char* link, char* impersonate) {
    char* query = NULL;
    size_t totalSize;
    SQLRETURN ret;

    if (MSVCRT$strcmp(name, "rpc") == 0)
    {
        char* prefix = "EXEC sp_serveroption '";
        char* middle = "', 'rpc out', '";
        char* suffix = "';";

        totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(link) + MSVCRT$strlen(middle) + MSVCRT$strlen(value) + MSVCRT$strlen(suffix) + 1;
        query = (char*)intAlloc(totalSize * sizeof(char));

        MSVCRT$strcpy(query, prefix);
        MSVCRT$strncat(query, link,     totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, middle,   totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, value,    totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, suffix,   totalSize - MSVCRT$strlen(query) - 1);

        //
        // link will always be passed as NULL here
        //
        BOOL result = HandleQuery(stmt, (SQLCHAR*)query, NULL, impersonate, FALSE);

        intFree(query);

        return result;
    }
    else
    {
        char* reconfigure = "RECONFIGURE;";
        char* advOpts = "EXEC sp_configure 'show advanced options', 1;";
        
        //
        // setting TRUE for using rpc query
        //
        if (!HandleQuery(stmt, (SQLCHAR*)advOpts, link, impersonate, TRUE))
        {
            return FALSE;
        }


        //
        // Clear the cursor
        //
        ClearCursor(stmt);

        //
        // Reconfigure
        //
        if (!HandleQuery(stmt, (SQLCHAR*)reconfigure, link, impersonate, TRUE))
        {
            return FALSE;
        }

        //
        // Clear the cursor
        //
        ClearCursor(stmt);

        //
        // toggle on or off
        //
        char* prefix = "EXEC sp_configure '";
        char* middle = "', ";
        char* suffix = ";";
        
        totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(name) + MSVCRT$strlen(middle) + MSVCRT$strlen(value) + MSVCRT$strlen(suffix) + 1;
        query = (char*)intAlloc(totalSize * sizeof(char));

        MSVCRT$strcpy(query, prefix);
        MSVCRT$strncat(query, name,     totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, middle,   totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, value,    totalSize - MSVCRT$strlen(query) - 1);
        MSVCRT$strncat(query, suffix,   totalSize - MSVCRT$strlen(query) - 1);

        if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE))
        {
            intFree(query);
            return FALSE;
        }

        //
        // Clear the cursor
        //
        ClearCursor(stmt);

        //
        // Reconfigure
        //
        BOOL result = HandleQuery(stmt, (SQLCHAR*)reconfigure, link, impersonate, TRUE);

        intFree(query);

        return result;
    }
}

//
// Query the status of RPC on a linked server
//
BOOL CheckRpcOnLink(SQLHSTMT stmt, char* link, char* impersonate)
{
    char* prefix = "SELECT is_rpc_out_enabled FROM sys.servers WHERE lower(name) like '%";
    char* suffix = "%';";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(link) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, link,     totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix,    totalSize - MSVCRT$strlen(query) - 1);

    BOOL result = HandleQuery(stmt, (SQLCHAR*)query, NULL, impersonate, FALSE);

    intFree(query);

    return result;
}

//
// Used to verify rpc status before executing a rpc linked query
//
BOOL IsRpcEnabled(SQLHSTMT stmt, char* link)
{
    BOOL enabled;

    char* prefix = "SELECT is_rpc_out_enabled "
                   "FROM sys.servers WHERE name = '";
    char* suffix = "';";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(link) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize * sizeof(char));
    
    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, link, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix, totalSize - MSVCRT$strlen(query) - 1);

    if (!HandleQuery(stmt, (SQLCHAR*)query, NULL, NULL, FALSE))
    {
        intFree(query);
        return FALSE;
    }

    char* result = GetSingleResult(stmt, FALSE);
    
    if (result[0] == '1')
    {
        enabled = TRUE;
    }
    else
    {
        enabled = FALSE;
    }

    intFree(query);
    intFree(result);

    return enabled;
}

//
// Execute query and hold results for printing
//
BOOL CheckModuleStatus(SQLHSTMT stmt, char* name, char* link, char* impersonate)
{
    char* prefix = "SELECT CAST(name AS NVARCHAR(128)) AS name, "
                   "CAST(value_in_use AS INT) AS value_in_use\n"
                   "FROM sys.configurations\n"
                   "WHERE name = '";
    char* suffix = "';";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(name) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize * sizeof(char));
    
    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, name, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix, totalSize - MSVCRT$strlen(query) - 1);

    BOOL result = HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE);

    intFree(query);

    return result;
}

//
// Used to verify module status before executing
//
BOOL IsModuleEnabled(SQLHSTMT stmt, char* name, char* link, char* impersonate)
{
    BOOL enabled;

    char* prefix = "SELECT CAST(value_in_use AS INT) AS value_in_use "
                  "FROM sys.configurations "
                  "WHERE name = '";
    char* suffix = "';";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(name) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize * sizeof(char));
    
    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, name, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix, totalSize - MSVCRT$strlen(query) - 1);

    if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE))
    {
        return FALSE;
    }

    char* result = GetSingleResult(stmt, FALSE);
    
    if (result[0] == '1')
    {
        enabled = TRUE;
    }
    else
    {
        enabled = FALSE;
    }

    intFree(query);
    intFree(result);

    return enabled;
}