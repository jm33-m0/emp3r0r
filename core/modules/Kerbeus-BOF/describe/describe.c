#include "_include/asn_decode.c"
#include "_include/crypt_b64.c"

void DisplayTicket( KRB_CRED cred, int indentLevel ) {
    DateTime starttime = cred.enc_part.ticket_info[0].starttime;
    DateTime endtime = cred.enc_part.ticket_info[0].endtime;
    DateTime renew_till = cred.enc_part.ticket_info[0].renew_till;
    uint flags = cred.enc_part.ticket_info[0].flags;

    if (cred.enc_part.ticket_info[0].sname.name_count == 1)
        PRINT_OUT("  ServiceName              :  %s\n", cred.enc_part.ticket_info[0].sname.name_string[0]);
    else if (cred.enc_part.ticket_info[0].sname.name_count > 1)
        PRINT_OUT("  ServiceName              :  %s/%s\n", cred.enc_part.ticket_info[0].sname.name_string[0], cred.enc_part.ticket_info[0].sname.name_string[1]);

    PRINT_OUT("  ServiceRealm             :  %s\n", cred.enc_part.ticket_info[0].srealm);

    if (cred.enc_part.ticket_info[0].pname.name_count == 1)
        PRINT_OUT("  UserName                 :  %s\n", cred.enc_part.ticket_info[0].pname.name_string[0]);
    else if (cred.enc_part.ticket_info[0].pname.name_count > 1)
        PRINT_OUT("  UserName                 :  %s@%s\n", cred.enc_part.ticket_info[0].pname.name_string[0], cred.enc_part.ticket_info[0].pname.name_string[1]);

    PRINT_OUT("  UserRealm                :  %s\n", cred.enc_part.ticket_info[0].prealm);
    PRINT_OUT("  StartTime (UTC)          :  %02d.%02d.%04d %d:%d:%d\n", starttime.day, starttime.month, starttime.year, starttime.hour, starttime.minute, starttime.second);
    PRINT_OUT("  EndTime (UTC)            :  %02d.%02d.%04d %d:%d:%d\n", endtime.day, endtime.month, endtime.year, endtime.hour, endtime.minute, endtime.second);
    PRINT_OUT("  RenewTill (UTC)          :  %02d.%02d.%04d %d:%d:%d\n", renew_till.day, renew_till.month, renew_till.year, renew_till.hour, renew_till.minute, renew_till.second);

    PRINT_OUT("  Flags                    :  ");
    if (flags & reserved)		PRINT_OUT("reserved ");
    if (flags & forwardable)	PRINT_OUT("forwardable ");
    if (flags & forwarded)		PRINT_OUT("forwarded ");
    if (flags & proxiable)		PRINT_OUT("proxiable ");
    if (flags & proxy)			PRINT_OUT("proxy ");
    if (flags & may_postdate)	PRINT_OUT("may_postdate ");
    if (flags & postdated)		PRINT_OUT("postdated ");
    if (flags & invalid)		PRINT_OUT("invalid ");
    if (flags & renewable)		PRINT_OUT("renewable ");
    if (flags & initial)		PRINT_OUT("initial ");
    if (flags & pre_authent)	PRINT_OUT("pre_authent ");
    if (flags & hw_authent)		PRINT_OUT("hw_authent ");
    if (flags & ok_as_delegate) PRINT_OUT("ok_as_delegate ");
    if (flags & anonymous)		PRINT_OUT("anonymous ");
    if (flags & enc_pa_rep)		PRINT_OUT("enc_pa_rep ");
    if (flags & reserved1)		PRINT_OUT("reserved1 ");
    PRINT_OUT("\n");

    if (cred.enc_part.ticket_info[0].key.key_type == rc4_hmac)
        PRINT_OUT("  KeyType                  :  rc4_hmac\n");
    else if (cred.enc_part.ticket_info[0].key.key_type == aes128_cts_hmac_sha1)
        PRINT_OUT("  KeyType                  :  aes128_cts_hmac_sha1\n");
    else if (cred.enc_part.ticket_info[0].key.key_type == aes256_cts_hmac_sha1)
        PRINT_OUT("  KeyType                  :  aes256_cts_hmac_sha1\n");
}

void DescribeTicket(byte* ticket_b64) {
    int bytesSize = 0;
    byte* bytes = base64_decode(ticket_b64, &bytesSize);

    KRB_CRED kirbi = { 0 };
    AsnElt   asn_KRB_CRED = { 0 };
    if (BytesToAsnDecode3(bytes, bytesSize, false, &asn_KRB_CRED)) return;
    if (AsnGetKrbCred(&(asn_KRB_CRED.sub[0]), &kirbi)) return;
    DisplayTicket(kirbi, 2);
}

void DESCRIBE_RUN( PCHAR Buffer, IN DWORD Length ) {
    PRINT_OUT("[*] Action: Describe ticket\n\n");

    char* ticket = NULL;
    for (int i = 0; i < Length; i++)
        i += GetStrParam(Buffer + i, Length - i, "/ticket:", 8, &ticket );

    if (ticket)
        DescribeTicket(ticket);
    else
        PRINT_OUT("[X] You must supply a /ticket!\n\n");
}

VOID go( IN PCHAR Buffer, IN ULONG Length ) {
    INIT_BOF();

    datap parser;
    BeaconDataParse(&parser, Buffer, Length);
    DWORD PARAM_SIZE = 0;
    PBYTE PARAM = BeaconDataExtract(&parser, &PARAM_SIZE);

    if( LoadFunc() )
        PRINT_OUT("%s\n", "Modules not loaded");
    else
        DESCRIBE_RUN( PARAM, PARAM_SIZE );

    FreeBank();

    END_BOF();
}