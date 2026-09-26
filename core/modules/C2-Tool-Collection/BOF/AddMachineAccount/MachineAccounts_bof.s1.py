from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class AddMachineAccountBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("AddMachineAccount")

        self.parser.description = (
            "Add a computer account to the Active Directory domain."
        )
        self.parser.epilog = "Use Active Directory Service Interfaces (ADSI) to add a computer account to AD."

        self.parser.add_argument("computername", help="Computer name")

        self.parser.add_argument(
            "password",
            help="Password",
            nargs="?",
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        if parser_arguments.password is not None:
            return [
                (BOFArgumentEncoding.WSTR, parser_arguments.computername),
                (BOFArgumentEncoding.WSTR, parser_arguments.password),
            ]

        return [(BOFArgumentEncoding.WSTR, parser_arguments.computername)]


class DelMachineAccountBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("DelMachineAccount")

        self.parser.description = (
            "Remove a computer account from the Active Directory domain."
        )
        self.parser.epilog = "Use Active Directory Service Interfaces (ADSI) to delete a computer account from AD."

        self.parser.add_argument("computername", help="Computer name")

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        return [(BOFArgumentEncoding.WSTR, parser_arguments.computername)]


class GetMachineAccountQuota(BaseBOFTask):
    def __init__(self):
        super().__init__("GetMachineAccountQuota")

        self.parser.description = (
            "Read the MachineAccountQuota value from the Active Directory domain."
        )

        self.parser.epilog = "Use Active Directory Service Interfaces (ADSI) to read the ms-DS-MachineAccountQuota value from AD."
