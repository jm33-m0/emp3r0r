from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class PsmBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("psm", base_binary_name="Psm")

        self.parser.description = "Show detailed information from a specific process id (loaded modules, tcp connections e.g.)."

        self.parser.add_argument("pid", help="The target pid.")

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        return [
            (BOFArgumentEncoding.INT, parser_arguments.pid),
        ]
