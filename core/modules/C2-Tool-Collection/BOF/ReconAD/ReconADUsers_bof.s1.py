from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class ReconADUsersBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("ReconAD-Users", base_binary_name="ReconAD")

        self.parser.description = "Use ADSI to query Active Directory user objects and attributes."
        self.parser.epilog = (
            "Use Active Directory Service Interfaces (ADSI) to query user objects and corresponding attributes.\n"
            "Example usage:\n"
            "  ReconAD-Users *admin* --attributes displayName,sAMAccountName --count 10\n"
            "  ReconAD-Users serveradmin --usegc\n"
        )

        self.parser.add_argument("username", help="The user(s) to search for.")
        self.parser.add_argument("--attributes", default="-all", help="Comma separated LDAP attributes (default all).")
        self.parser.add_argument("--count", default=0, help="Limit the results (default all).", type=int)
        self.parser.add_argument("--usegc", action="store_true", help="Use global catalog.")
        self.parser.add_argument("--server", default="-noserver", help="Domain or server (Domain | Server [:port]).")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        return [
            (BOFArgumentEncoding.WSTR, "users"),
            (BOFArgumentEncoding.WSTR, parser_arguments.username),
            (BOFArgumentEncoding.WSTR, parser_arguments.attributes),
            (BOFArgumentEncoding.INT, parser_arguments.count),
            (BOFArgumentEncoding.INT, parser_arguments.usegc),
            (BOFArgumentEncoding.WSTR, parser_arguments.server),
        ]
