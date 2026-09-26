from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class KerbHashBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("KerbHash")

        self.parser.description = "Hash passwords to kerberos keys."
        self.parser.epilog = (
            "Example usage:\n"
            "  - Hash useraccount password:\n"
            "    KerbHash Welcome123 adminuser domain.local\n"
            "  - Hash computeraccount password\n"
            "    KerbHash Welcome123 SERVER$ domain.local"
        )

        self.parser.add_argument("password", help="The password to hash.")
        self.parser.add_argument("username", help="The username.")
        self.parser.add_argument("domain", help="The domain.")

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        return [
            (BOFArgumentEncoding.WSTR, arguments[0]),
            (BOFArgumentEncoding.WSTR, arguments[1]),
            (BOFArgumentEncoding.WSTR, arguments[2]),
        ]
