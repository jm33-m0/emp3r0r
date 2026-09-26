from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException

BASE_DIR = "/shared/bofs/SQL-BOF/SQL"

# Helper to coerce None to empty string for STR args
_def = lambda s: s if s is not None else ""

# Strip matching outer single or double quotes from a string
def _strip_outer_quotes(s: str) -> str:
    if s is None:
        return s
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1]
    return s

def _rewrite_all(arguments: List[str]) -> List[str]:
    try:
        return [_strip_outer_quotes(a) for a in arguments]
    except Exception:
        return arguments


class SqlWhoamiBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-whoami",
            base_binary_name="whoami",
            base_binary_path=f"{BASE_DIR}/whoami",
        )
        self.parser.description = "Gather logged in user, mapped user and roles"
        self.parser.add_argument("server")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
        ]


class SqlInfoBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-info",
            base_binary_name="info",
            base_binary_path=f"{BASE_DIR}/info",
        )
        self.parser.description = "Gather information about the SQL server"
        self.parser.add_argument("server")
        self.parser.add_argument("database", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
        ]


class SqlImpersonateBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-impersonate",
            base_binary_name="impersonate",
            base_binary_path=f"{BASE_DIR}/impersonate",
        )
        self.parser.description = "Enumerate users that can be impersonated"
        self.parser.add_argument("server")
        self.parser.add_argument("database", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
        ]


class SqlLinksBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-links",
            base_binary_name="links",
            base_binary_path=f"{BASE_DIR}/links",
        )
        self.parser.description = "Enumerate linked servers"
        self.parser.add_argument("server")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
        ]


class SqlUsersBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-users",
            base_binary_name="users",
            base_binary_path=f"{BASE_DIR}/users",
        )
        self.parser.description = "Enumerate users with database access"
        self.parser.add_argument("server")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
        ]


class SqlDatabasesBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-databases",
            base_binary_name="databases",
            base_binary_path=f"{BASE_DIR}/databases",
        )
        self.parser.description = "Enumerate databases on a server"
        self.parser.add_argument("server")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
        ]


class SqlTablesBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-tables",
            base_binary_name="tables",
            base_binary_path=f"{BASE_DIR}/tables",
        )
        self.parser.description = "Enumerate tables within a database"
        self.parser.add_argument("server")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
        ]


class SqlColumnsBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-columns",
            base_binary_name="columns",
            base_binary_path=f"{BASE_DIR}/columns",
        )
        self.parser.description = "Enumerate columns within a table"
        self.parser.add_argument("server")
        self.parser.add_argument("table")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.table)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
        ]


class SqlRowsBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-rows",
            base_binary_name="rows",
            base_binary_path=f"{BASE_DIR}/rows",
        )
        self.parser.description = "Get the count of rows in a table"
        self.parser.add_argument("server")
        self.parser.add_argument("table")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
            (BOFArgumentEncoding.STR, _def(a.table)),
        ]


class SqlCheckRpcBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-checkrpc",
            base_binary_name="checkrpc",
            base_binary_path=f"{BASE_DIR}/checkrpc",
        )
        self.parser.description = "Enumerate RPC status of linked servers"
        self.parser.add_argument("server")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
        ]


class SqlQueryBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-query",
            base_binary_name="query",
            base_binary_path=f"{BASE_DIR}/query",
        )
        self.parser.description = "Execute a custom SQL query"
        self.parser.add_argument("server")
        self.parser.add_argument("query")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def rewrite_arguments(self, arguments: List[str]) -> List[str]:
        try:
            idx = 1
            if len(arguments) > idx and len(arguments[idx]) >= 2:
                q = arguments[idx]
                if (q[0] == q[-1]) and q[0] in ('"', "'"):
                    arguments[idx] = q[1:-1]
        except Exception:
            pass
        return arguments

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
            (BOFArgumentEncoding.STR, _def(a.query)),
        ]


class SqlSearchBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-search",
            base_binary_name="search",
            base_binary_path=f"{BASE_DIR}/search",
        )
        self.parser.description = "Search a table for a column name"
        self.parser.add_argument("server")
        self.parser.add_argument("keyword")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
            (BOFArgumentEncoding.STR, _def(a.keyword)),
        ]


class SqlSmbBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-smb",
            base_binary_name="smb",
            base_binary_path=f"{BASE_DIR}/smb",
        )
        self.parser.description = "Coerce NetNTLM auth via xp_dirtree"
        self.parser.add_argument("server")
        self.parser.add_argument("listener")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
            (BOFArgumentEncoding.STR, _def(a.listener)),
        ]


class _SqlToggleBase(BaseBOFTask):
    def __init__(self, cmd: str, module: str, value: str):
        super().__init__(
            cmd,
            base_binary_name="togglemodule",
            base_binary_path=f"{BASE_DIR}/togglemodule",
        )
        self._module = module
        self._value = value
        self.parser.add_argument("server")
        if module == "rpc":
            self.parser.add_argument("link")
            self.parser.add_argument("database", nargs="?", default="")
            self.parser.add_argument("impersonate", nargs="?", default="")
        else:
            self.parser.add_argument("database", nargs="?", default="")
            self.parser.add_argument("link", nargs="?", default="")
            self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        if self._module == "rpc":
            database = getattr(a, "database", "")
            link = getattr(a, "link", "")
            impersonate = getattr(a, "impersonate", "")
        else:
            database = getattr(a, "database", "")
            link = getattr(a, "link", "")
            impersonate = getattr(a, "impersonate", "")
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(database)),
            (BOFArgumentEncoding.STR, _def(link)),
            (BOFArgumentEncoding.STR, _def(impersonate)),
            (BOFArgumentEncoding.STR, self._module),
            (BOFArgumentEncoding.STR, self._value),
        ]


class SqlEnableRpcBOF(_SqlToggleBase):
    def __init__(self):
        super().__init__("sql-enablerpc", module="rpc", value="TRUE")
        self.parser.description = "Enable RPC and RPC Out on linked server"


class SqlDisableRpcBOF(_SqlToggleBase):
    def __init__(self):
        super().__init__("sql-disablerpc", module="rpc", value="FALSE")
        self.parser.description = "Disable RPC and RPC Out on linked server"


class SqlEnableClrBOF(_SqlToggleBase):
    def __init__(self):
        super().__init__("sql-enableclr", module="clr enabled", value="1")
        self.parser.description = "Enable CLR integration"


class SqlDisableClrBOF(_SqlToggleBase):
    def __init__(self):
        super().__init__("sql-disableclr", module="clr enabled", value="0")
        self.parser.description = "Disable CLR integration"


class SqlEnableXpBOF(_SqlToggleBase):
    def __init__(self):
        super().__init__("sql-enablexp", module="xp_cmdshell", value="1")
        self.parser.description = "Enable xp_cmdshell"


class SqlDisableXpBOF(_SqlToggleBase):
    def __init__(self):
        super().__init__("sql-disablexp", module="xp_cmdshell", value="0")
        self.parser.description = "Disable xp_cmdshell"


class SqlEnableOleBOF(_SqlToggleBase):
    def __init__(self):
        super().__init__("sql-enableole", module="Ole Automation Procedures", value="1")
        self.parser.description = "Enable OLE Automation Procedures"


class SqlDisableOleBOF(_SqlToggleBase):
    def __init__(self):
        super().__init__("sql-disableole", module="Ole Automation Procedures", value="0")
        self.parser.description = "Disable OLE Automation Procedures"


class SqlOleCmdBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-olecmd",
            base_binary_name="olecmd",
            base_binary_path=f"{BASE_DIR}/olecmd",
        )
        self.parser.description = "Execute a system command using OLE automation procedures"
        self.parser.add_argument("server")
        self.parser.add_argument("command")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
            (BOFArgumentEncoding.STR, _def(a.command)),
        ]


class SqlXpCmdBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-xpcmd",
            base_binary_name="xpcmd",
            base_binary_path=f"{BASE_DIR}/xpcmd",
        )
        self.parser.description = "Execute a system command using xp_cmdshell"
        self.parser.add_argument("server")
        self.parser.add_argument("command")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
            (BOFArgumentEncoding.STR, _def(a.command)),
        ]


class SqlClrBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-clr",
            base_binary_name="clr",
            base_binary_path=f"{BASE_DIR}/clr",
        )
        self.parser.description = "Load and execute .NET assembly in a stored procedure"
        self.parser.add_argument("server")
        self.parser.add_argument("dll_path")
        self.parser.add_argument("function")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def validate_files(self, arguments: List[str]):
        a = self.parser.parse_args(arguments)
        f = self.get_file_by_name(a.dll_path)
        if f is None:
            raise TaskInvalidArgumentsException("DLL file not found in uploaded files (name must match dll_path).")

    def _encode_arguments_bof(self, arguments: List[str]):
        import hashlib
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        dll_file = self.get_file_by_name(a.dll_path)
        if dll_file is None:
            raise TaskInvalidArgumentsException("DLL file not found; upload the file with the same name as dll_path.")
        dll_bytes = dll_file.content
        hash_hex = hashlib.sha512(dll_bytes).hexdigest()
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
            (BOFArgumentEncoding.STR, _def(a.function)),
            (BOFArgumentEncoding.STR, hash_hex),
            (BOFArgumentEncoding.BYTES, dll_bytes),
        ]


class SqlAdsiBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-adsi",
            base_binary_name="adsi",
            base_binary_path=f"{BASE_DIR}/adsi",
        )
        self.parser.description = "Obtain ADSI creds from ADSI linked server"
        self.parser.add_argument("server")
        self.parser.add_argument("adsiserver")
        self.parser.add_argument("port", nargs="?", default="4444")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]):
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
            (BOFArgumentEncoding.STR, _def(a.adsiserver)),
            (BOFArgumentEncoding.STR, _def(a.port)),
        ]


class SqlAgentCmdBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-agentcmd",
            base_binary_name="agentcmd",
            base_binary_path=f"{BASE_DIR}/agentcmd",
        )
        self.parser.description = "Execute a system command using agent jobs"
        self.parser.add_argument("server")
        self.parser.add_argument("command")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]):
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
            (BOFArgumentEncoding.STR, _def(a.command)),
        ]


class SqlAgentStatusBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-agentstatus",
            base_binary_name="agentstatus",
            base_binary_path=f"{BASE_DIR}/agentstatus",
        )
        self.parser.description = "Enumerate SQL agent status and jobs"
        self.parser.add_argument("server")
        self.parser.add_argument("database", nargs="?", default="")
        self.parser.add_argument("link", nargs="?", default="")
        self.parser.add_argument("impersonate", nargs="?", default="")

    def _encode_arguments_bof(self, arguments: List[str]):
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server)),
            (BOFArgumentEncoding.STR, _def(a.database)),
            (BOFArgumentEncoding.STR, _def(a.link)),
            (BOFArgumentEncoding.STR, _def(a.impersonate)),
        ]


class Sql1434UdpBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sql-1434udp",
            base_binary_name="1434udp",
            base_binary_path=f"{BASE_DIR}/1434udp",
        )
        self.parser.description = "Obtain SQL Server connection information from SQL Browser (UDP/1434)"
        self.parser.add_argument("server_ip")

    def _encode_arguments_bof(self, arguments: List[str]):
        arguments = _rewrite_all(arguments)
        a = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, _def(a.server_ip)),
        ]
