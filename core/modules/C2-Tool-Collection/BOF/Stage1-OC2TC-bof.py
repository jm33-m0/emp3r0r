#!/usr/bin/python3
"""

Stage1-BOF.py

This script provides a supporting wrapper for the Stage1 C2 Server for easy BOF usage.
It can give context about;
- location and parameters of the BOF,
- help and description texts,
- desired GUI (file)inputs / elements,
- parameter splitting, validation, processing and defaults,
- automated execution of a series of commands.

Usage: clone the entire repo to the `stage1c2server/shared/bofs/` folder.
The additional commands are automatically loaded and ready for action.

Development: The integration of this bof.py script is facilitated by overloading from a base BOFModuleClass.
All BOF / BOT related code of Stage1 C2 server is open source and database credentials/access is available, allowing for very powerful modules.

Stage1 C2 is part of our commercial Outflank Security Tooling (OST) product. For more information:
Outflank Security Tooling
https://outflank.nl/services/outflank-security-tooling/

"""

import sys, inspect

sys.path.append("../..")
sys.path.append("/code/shared/bofs/")
sys.path.append("/shared/bofs/")
from boflibrary import *

CURRENT_PATH = os.path.abspath(os.path.dirname(__file__))


def bof_path64(name, arch):  # arch is either 64 or 32
    return "{}/{}.o".format(name, name) if arch == 64 else ""


def bof_path(name, arch):  # arch is either 64 or 32
    return "{}/{}.x{}.o".format(name, name, 64 if arch == 64 else 86)


class OTCBOFBaseClass(
    BOFModuleClass
):  # ExampleLibBaseClass is the commandline command name
    def __init__(self):
        super().__init__(
            CURRENT_PATH,
            bof_path(self.__class__.__name__, 64),
            bof_path(self.__class__.__name__, 32),
        )


class OTCBOF64BaseClass(
    BOFModuleClass
):  # ExampleLibBaseClass is the commandline command name
    def __init__(self):
        super().__init__(CURRENT_PATH, bof_path64(self.__class__.__name__, 64), "")


################################################


class AddMachineAccount(BOFModuleClass):
    """Outflank C2 Tool Collection AddMachineAccount BOF Module"""

    def __init__(self):
        super().__init__(
            CURRENT_PATH,
            "AddMachineAccount/AddMachineAccount.x64.o",
            "AddMachineAccount/AddMachineAccount.x86.o",
        )
        self.args = "ZZ"  # required, optional

    def description(self):  # Short
        return "Add a computer account to the Active Directory domain."

    def help(self):  # Long
        return (
            "Synopsis: AddMachineAccount [Computername] [Password <Optional>]\n\n"
            + "Use Active Directory Service Interfaces (ADSI) to add a computer account to AD."
        )

    def split_arguments(self, arguments):
        return arguments.strip().split(None, 1)  # Only split on the first space

    def validate_arguments(self, argumentList):
        if not argumentList or len(argumentList) == 0:
            raise ValueError("[!] Error: Please specify a computeraccount name.")
        return argumentList


class DelMachineAccount(BOFModuleClass):
    """Outflank C2 Tool Collection DelMachineAccount BOF Module"""

    def __init__(self):
        super().__init__(
            CURRENT_PATH,
            "AddMachineAccount/DelMachineAccount.x64.o",
            "AddMachineAccount/DelMachineAccount.x86.o",
        )
        self.args = "Z"  # required

    def description(self):  # Short
        return "Remove a computer account from the Active Directory domain."

    def help(self):  # Long
        return (
            "Synopsis: DelMachineAccount [Computername]\n\n"
            + "Use Active Directory Service Interfaces (ADSI) to delete a computer account from AD."
        )

    def validate_arguments(self, argumentList):
        if not argumentList or len(argumentList) == 0:
            raise ValueError("[!] Error: Please specify a computeraccount name.")
        return argumentList


class GetMachineAccountQuota(BOFModuleClass):
    """Outflank C2 Tool Collection GetMachineAccountQuota BOF Module"""

    def __init__(self):
        super().__init__(
            CURRENT_PATH,
            "AddMachineAccount/GetMachineAccountQuota.x64.o",
            "AddMachineAccount/GetMachineAccountQuota.x86.o",
        )

    def description(self):  # Short
        return "Read the MachineAccountQuota value from the Active Directory domain."

    def help(self):  # Long
        return (
            "Synopsis: GetMachineAccountQuota\n\n"
            + "Use Active Directory Service Interfaces (ADSI) to read the ms-DS-MachineAccountQuota value from AD."
        )


class CVE202226923(BOFModuleClass):
    """Outflank C2 Tool Collection CVE-20222-6923 BOF Module"""

    def __init__(self):
        super().__init__(
            CURRENT_PATH,
            "CVE-2022-26923/CVE-2022-26923.x64.o",
            "CVE-2022-26923/CVE-2022-26923.x86.o",
        )
        self.args = "ZZ"

    def description(self):  # Short
        return "Active Directory Domain Privilege Escalation exploit."

    def help(self):  # Long
        return (
            "Synopsis: CVE-2022-26923 [Computername] [Password <Optional>]\n"
            + "Use Active Directory Service Interfaces (ADSI) to add a computer account with dNSHostName attribute set to the DC fqdn."
        )

    def validate_arguments(self, argumentList):
        if not argumentList or len(argumentList) == 0:
            raise ValueError("[!] Error: Specify a computeraccount name!")
        return argumentList


class Askcreds(OTCBOFBaseClass):
    """Outflank C2 Tool Collection Askcreds BOF Module"""

    def __init__(self):
        super().__init__()
        self.args = "Z"  # optional

    def description(self):  # Short
        return "Collect passwords using CredUIPromptForWindowsCredentialsName."

    def help(self):  # Long
        return (
            "Synopsis: Askcreds [optional reason]\n"
            + "Collect passwords by simply asking."
        )

    def split_arguments(self, arguments):
        return [
            arguments
        ]  # All further text (including spaces) is seen as one argument


class Domaininfo(OTCBOFBaseClass):
    """Outflank C2 Tool Collection Domaininfo BOF Module"""

    def description(self):  # Short
        return "Using Active Directory Domain Services to enumerate domain information."

    def help(self):  # Long
        return (
            "Using Active Directory Domain Services to enumerate domain information.\n\n"
            + "Synopsis: Domaininfo"
        )


class Kerberoast(OTCBOFBaseClass):
    """Outflank C2 Tool Collection Kerberoast BOF Module"""

    def __init__(self):
        super().__init__()
        self.args = "ZZ"

    def description(self):  # Short
        return "Perform Kerberoasting against all (or specified) SPN enabled accounts."

    def help(self):  # Long
        return (
            "List all SPN enabled user/service accounts or request service tickets (TGS-REP) which can be cracked offline using HashCat.\n\n"
            + "Synopsis: Kerberoast [list, list-no-aes, roast or roast-no-aes] [account <optional sAMAccountName filter (default all)>]\n\n"
        )

    def split_arguments(self, arguments):
        return arguments.strip().split(None, 1)  # Only split on the first space

    def validate_arguments(self, argumentList):
        if (
            not argumentList
            or len(argumentList) == 0
            or argumentList[0] not in ["list", "list-no-aes", "roast", "roast-no-aes"]
        ):
            raise ValueError(
                "[!] Error: Please specify an action (list, list-no-aes, roast or roast-no-aes)."
            )
        return argumentList


class Lapsdump(OTCBOFBaseClass):
    """Outflank C2 Tool Collection Lapsdump BOF Module"""

    def __init__(self):
        super().__init__()
        self.args = "Z"

    def description(self):  # Short
        return "Dump LAPS passwords from specified computers within Active Directory."

    def help(self):  # Long
        return (
            "Synopsis: Lapsdump [target]\n\n"
            + "Use Active Directory Service Interfaces (ADSI) to extract LAPS passwords from AD."
        )

    def validate_arguments(self, argumentList):
        if not argumentList or len(argumentList) == 0:
            raise ValueError("[!] Error: Please specify a Target: IP or Hostname.")
        return argumentList


class PetitPotam(OTCBOF64BaseClass):
    """Outflank C2 Tool Collection PetitPotam BOF Module"""

    def __init__(self):
        super().__init__()
        self.args = "ZZ"

    def description(self):  # Short
        return "Coerce Windows hosts to authenticate to other machines via MS-EFSRPC."

    def help(self):  # Long
        return (
            "Synopsis: PetitPotam <capture server ip or hostname> <target server ip or hostname>\n"
            + "Bof implementation of the PetitPotam exploit."
        )

    def validate_arguments(self, argumentList):
        if not argumentList or len(argumentList) < 1:
            raise ValueError("[!] Error: Please specify a capture server!")
        if len(argumentList) == 1:
            raise ValueError("[!] Error: Please specify a target server!")
        return argumentList


class Psc(OTCBOFBaseClass):
    """Outflank C2 Tool Collection Psc BOF Module"""

    def description(self):  # Short
        return "Show detailed information from processes with established TCP and RDP connections."

    def help(self):  # Long
        return (
            "Synopsis: psc\n\n"
            + "Shows a detailed list of all processes with established TCP and RDP connections."
        )


class Psw(OTCBOFBaseClass):
    """Outflank C2 Tool Collection Psw BOF Module"""

    def description(self):  # Short
        return "Show Window titles from processes with active Windows."

    def help(self):  # Long
        return (
            "Synopsis: Psw\n\n"
            + "Show Window titles from processes with active Windows."
        )


# Psx not included because Stage1 supports it natively


class Smbinfo(OTCBOFBaseClass):
    """Outflank C2 Tool Collection Smbinfo BOF Module"""

    def __init__(self):
        super().__init__()
        self.args = "Z"

    def description(self):  # Short
        return "Gather remote system version info."

    def help(self):  # Long
        return (
            "Synopsis: Smbinfo [target]\n\n"
            + "Use NetWkstaGetInfo API to gather remote system version info."
        )

    def validate_arguments(self, argumentList):
        if not argumentList or len(argumentList) == 0:
            raise ValueError("[!] Error: Specify an ip or hostname!")
        return argumentList


class SprayAD(OTCBOFBaseClass):
    """Outflank C2 Tool Collection SprayAD BOF Module"""

    def __init__(self):
        super().__init__()
        self.args = "ZZZ"

    def description(self):  # Short
        return "Perform a Kerberos or ldap password spraying attack against Active Directory."

    def help(self):  # Long
        return (
            "Test all enabled Active Directory useraccounts for valid passwords.\n\n"
            + "Synopsis: SprayAD [password] [filter <optional> <example: admin*>] [ldap <optional>]"
        )

    def validate_arguments(self, argumentList):
        if not argumentList or len(argumentList) == 0:
            raise ValueError("[!] Error: Please specify a password to test!")
        if len(argumentList) == 1:
            argumentList.append("*")
        return argumentList


class StartWebClient(OTCBOFBaseClass):
    """Outflank C2 Tool Collection StartWebClient BOF Module"""

    def description(self):  # Short
        return "Starting WebClient Service Programmatically."

    def help(self):  # Long
        return (
            "Synopsis: StartWebClient\n\n"
            + "Starting WebClient Service Programmatically"
        )


class Winver(OTCBOFBaseClass):
    """Outflank C2 Tool Collection Winver BOF Module"""

    def description(self):  # Short
        return "Display the version of Windows that is running, the build number and patch release (Update Build Revision)."

    def help(self):  # Long
        return "Synopsis: Winver\n\n" + "Display Windows version info."


# Main entry point of the file
if __name__ == "__main__":
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if (
            inspect.isclass(obj)
            and issubclass(obj, BOFModuleClass)
            and name != "BOFModuleClass"
            and name.find("BaseClass") == -1
        ):
            try:
                instance_of_obj = obj()
                instance_of_obj.test()
            except Exception as error:
                print(
                    "[!] Error during test {}: {}".format(
                        type(error).__name__, name, str(error)
                    )
                )
