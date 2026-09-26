from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class FindProcHandleBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("FindProcHandle", base_binary_name="FindProcHandle")

        self.parser.add_argument("processname", help="The processhandle to search for.")

        self.parser.description = (
            "Find specific process handles."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  - Find handles to the lsass process:\n"
            "    FindProcHandle lsass.exe\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        return [(BOFArgumentEncoding.WSTR, parser_arguments.processname)]


class FindModuleBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("FindModule", base_binary_name="FindModule")

        self.parser.add_argument("modulename", help="The module to search for.")

        self.parser.description = (
            "Find specific loaded modules."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  - Find processes with the clr.dll module loaded:\n"
            "    FindModule clr.dll\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        return [(BOFArgumentEncoding.WSTR, parser_arguments.modulename)]
