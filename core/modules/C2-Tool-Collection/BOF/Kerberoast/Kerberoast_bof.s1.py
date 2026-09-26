from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class KerberoastBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("Kerberoast")

        _action_choices = ["list", "list-no-aes", "roast", "roast-no-aes"]

        self.parser.description = (
            "Perform Kerberoasting against all (or specified) SPN enabled accounts."
        )

        self.parser.epilog = (
            "List all SPN enabled user/service accounts or request service tickets (TGS-REP) which can be cracked "
            "offline using HashCat.\n\n"
            "WARNING: Listing and roasting tickets without sAMAccountName filter is OPSEC UNSAFE!\n\n"
            "Example usage:\n"
            "  - Kerberoast list\n"
            "  - Kerberoast list DA*\n"
        )

        self.parser.add_argument(
            "action",
            choices=_action_choices,
            help=f"Actions ({', '.join(_action_choices)}).",
            metavar="action",
        )

        self.parser.add_argument(
            "filter",
            help="sAMAccountName filter.",
            nargs="?",
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        if parser_arguments.filter is not None:
            return [
                (BOFArgumentEncoding.WSTR, parser_arguments.action),
                (BOFArgumentEncoding.WSTR, parser_arguments.filter),
            ]

        return [(BOFArgumentEncoding.WSTR, parser_arguments.action)]
