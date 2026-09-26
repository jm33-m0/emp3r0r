from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class KlistBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("klist", base_binary_name="Klist")

        self.parser.description = "Interact with cached Kerberos tickets."

        self.parser.epilog = "Example usage:\n" "  - klist\n" "  - klist get target_spn\n" "  - klist purge"

        action_parser = self.parser.add_subparsers(dest="action", help="The action to perform.")

        action_get_parser = action_parser.add_parser("get")
        action_get_parser.add_argument("spn", help="Target SPN.")

        _ = action_parser.add_parser("purge")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        if parser_arguments.action == "purge":
            return [(BOFArgumentEncoding.WSTR, "purge")]

        if parser_arguments.action == "get":
            return [(BOFArgumentEncoding.WSTR, "get"), (BOFArgumentEncoding.WSTR, parser_arguments.spn)]

        return []
