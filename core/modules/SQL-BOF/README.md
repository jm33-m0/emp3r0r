# SQL-BOF

> ## emp3r0r integration
>
> This tree is the [Tw1sm/SQL-BOF](https://github.com/Tw1sm/SQL-BOF) suite
> adopted as an emp3r0r module suite. `config.json` registers every command as
> a top-level console command; the per-parameter help text (shown by
> `<command> --help`) is the command documentation. Run `./make_all.sh` to
> build the `.o` objects, or let `core/build.py` do it during a release build.
>
> Argument order in `config.json` follows the `BeaconDataExtract()` order in
> `src/SQL/<name>/entry.c`, not the order shown in the upstream README, because
> emp3r0r packs parameters in declaration order. In particular `sql-columns`
> and `sql-rows` take `server, database, table, link, impersonate`.
>
> `sql-clr` requires the base64-encoded assembly (`--dll`) and its SHA-512
> hash (`--hash`, uppercase hex); the hash is inserted into
> `sys.trusted_assemblies`.
>
> Compiled objects are build artifacts and are not checked in.

A library of beacon object files to interact with remote SQL servers and data. This collection is templated off the TrustedSec [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) collection and models the functionality of the [SQLRecon](https://github.com/skahwah/SQLRecon) project.

## Usage
- Cobalt Strike: Load the aggressor script located at `SQL/SQL.cna`
- Havoc: Load the python script located at `SQL/SQL.py`
- Adaptix: Load the ax script located at `SQL/SQL.axs`
- Outflank C2: Load the python script located at `SQL/sql_bof.s1.py`

## Available commands
|Commands|Usage|Notes|
|--------|-----|-----|
|sql-1434udp|[server IP] |Enumerate SQL Server connection info |
|sql-adsi|[server] [ADSI_linkedserver] [opt: port] [opt: database] [opt: linkedserver] [opt: impersonate] |Obtain ADSI creds from ADSI linked server |
|sql-agentcmd |[server] [command] [opt: database] [opt: linkedserver] [opt: impersonate] |Execute a system command using agent jobs |
|sql-agentstatus |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Enumerate SQL agent status and jobs |
|sql-checkrpc |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Enumerate RPC status of linked servers |
|sql-clr |[server] [dll_path] [function] [opt: database] [opt: linkedserver] [opt: impersonate] |Load and execute .NET assembly in a stored procedure |
|sql-columns |[server] [table] [opt: database] [opt: linkedserver] [opt: impersonate] |Enumerate columns within a table |
|sql-databases |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Enumerate databases on a server|
|sql-disableclr |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Disable CLR integration |
|sql-disableole |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Disable OLE Automation Procedures |
|sql-disablerpc |[server] [linkedserver] [opt: database] [opt: impersonate] |Disable RPC and RPC out on a linked server |
|sql-disablexp |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Disable xp_cmdshell |
|sql-enableclr |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Enable CLR integration |
|sql-enableole |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Enable OLE Automation Procedures |
|sql-enablerpc |[server] [linkedserver] [opt: database] [opt: impersonate] |Enable RPC and RPC out on a linked server |
|sql-enablexp |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Enable xp_cmdshell |
|sql-impersonate |[server] [opt: database] |Enumerate users that can be impersonated |
|sql-info |[server] [opt: database] |Gather information about the SQL server |
|sql-links |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Enumerate linked servers |
|sql-olecmd |[server] [command] [opt: database] [opt: linkedserver] [opt: impersonate] |Execute a system command using OLE automation procedures |
|sql-query |[server] [query] [opt: database] [opt: linkedserver] [opt: impersonate] |Execute a custom SQL query |
|sql-rows |[server] [table] [opt: database] [opt: linkedserver] [opt: impersonate] |Get the count of rows in a table |
|sql-search |[server] [search] [opt: database] [opt: linkedserver] [opt: impersonate] |Search a table for a column name |
|sql-smb |[server] [\\\\listener] [opt: database] [opt: linkedserver] [opt: impersonate] |Coerce NetNTLM auth via xp_dirtree |
|sql-tables |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Enumerate tables within a database |
|sql-users |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Enumerate users with database access |
|sql-whoami |[server] [opt: database] [opt: linkedserver] [opt: impersonate] |Gather logged in user, mapped user and roles |
|sql-xpcmd |[server] [command] [opt: database] [opt: linkedserver] [opt: impersonate] |Execute a system command via xp_cmdshell |

## References
- [SQLRecon](https://github.com/skahwah/SQLRecon) by [@sanjivkawa](https://twitter.com/sanjivkawa)
- [PySQLRecon](https://github.com/Tw1sm/PySQLRecon)
- [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
