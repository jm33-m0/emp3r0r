from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class LapsdumpBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("Lapsdump")

        self.parser.description = (
            "Dump LAPS passwords from specified computers within Active Directory."
        )

        self.parser.add_argument("hostname")

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        return [(BOFArgumentEncoding.WSTR, parser_arguments.hostname)]
