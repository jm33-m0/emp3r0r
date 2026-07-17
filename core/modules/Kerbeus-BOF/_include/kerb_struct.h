#pragma once

typedef unsigned int uint;
typedef unsigned char byte;
typedef int bool;
#define true 1
#define false 0

enum KRB_KEY_USAGE {
	KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP = 1,
	KRB_KEY_USAGE_AS_REP_TGS_REP = 2,
	KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY = 3,
	KRB_KEY_USAGE_TGS_REQ_ENC_AUTHOIRZATION_DATA = 4,
	KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR = 7,
	KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8,
	KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR = 11,
	KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART = 13,
	KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART = 14,
	KRB_KEY_USAGE_KRB_NON_KERB_SALT = 16,
	KRB_KEY_USAGE_KRB_NON_KERB_CKSUM_SALT = 17,
	KRB_KEY_USAGE_PA_S4U_X509_USER = 26,
};

enum KERB_CHECKSUM_ALGORITHM {
	KERB_CHECKSUM_NONE = 0,
	KERB_CHECKSUM_RSA_MD4 = 2,
	KERB_CHECKSUM_RSA_MD5 = 7,
	KERB_CHECKSUM_HMAC_SHA1_96_AES128 = 15,
	KERB_CHECKSUM_HMAC_SHA1_96_AES256 = 16,
	KERB_CHECKSUM_DES_MAC = -133,
	KERB_CHECKSUM_HMAC_MD5 = -138,
};

enum KERB_ETYPE {
	des_cbc_crc = 1,
	des_cbc_md4 = 2,
	des_cbc_md5 = 3,
	des3_cbc_md5 = 5,
	des3_cbc_sha1 = 7,
	dsaWithSHA1_CmsOID = 9,
	md5WithRSAEncryption_CmsOID = 10,
	sha1WithRSAEncryption_CmsOID = 11,
	rc2CBC_EnvOID = 12,
	rsaEncryption_EnvOID = 13,
	rsaES_OAEP_ENV_OID = 14,
	des_ede3_cbc_Env_OID = 15,
	des3_cbc_sha1_kd = 16,
	aes128_cts_hmac_sha1 = 17,
	aes256_cts_hmac_sha1 = 18,
	rc4_hmac = 23,
	rc4_hmac_exp = 24,
	subkey_keymaterial = 65,
	old_exp = -135,
};

enum HostAddressType {
	ADDRTYPE_UNIX_NULL = 0,
	ADDRTYPE_UNIX = 1,
	ADDRTYPE_INET = 2,
	ADDRTYPE_IMPLINK = 3,
	ADDRTYPE_PUP = 4,
	ADDRTYPE_CHAOS = 5,
	ADDRTYPE_XNS = 6,
	ADDRTYPE_IPX = 6,
	ADDRTYPE_OSI = 7,
	ADDRTYPE_ECMA = 8,
	ADDRTYPE_DATAKIT = 9,
	ADDRTYPE_CCITT = 10,
	ADDRTYPE_SNA = 11,
	ADDRTYPE_DECNET = 12,
	ADDRTYPE_DLI = 13,
	ADDRTYPE_LAT = 14,
	ADDRTYPE_HYLINK = 15,
	ADDRTYPE_APPLETALK = 16,
	ADDRTYPE_VOICEVIEW = 18,
	ADDRTYPE_FIREFOX = 19,
	ADDRTYPE_NETBIOS = 20,
	ADDRTYPE_BAN = 21,
	ADDRTYPE_ATM = 22,
	ADDRTYPE_INET6 = 24
};

enum KERB_MESSAGE_TYPE {
	KERB_AS_REQ = 10,
	KERB_AS_REP = 11,
	KERB_TGS_REQ = 12,
	KERB_TGS_REP = 13,
	KERB_AP_REQ = 14,
	KERB_AP_REP = 15,
	KERB_TGT_REQ = 16, // KRB-TGT-REQUEST for U2U
	KERB_TGT_REP = 17, // KRB-TGT-REPLY for U2U
	KERB_SAFE = 20,
	KERB_PRIV = 21,
	KERB_CRED = 22,
	KERB_ERROR = 30,
};

enum PADATA_TYPE {
	PADATA_NONE = 0,
	PADATA_TGS_REQ = 1,
	PADATA_AP_REQ = 1,
	PADATA_ENC_TIMESTAMP = 2,
	PADATA_PW_SALT = 3,
	PADATA_ENC_UNIX_TIME = 5,
	PADATA_SANDIA_SECUREID = 6,
	PADATA_SESAME = 7,
	PADATA_OSF_DCE = 8,
	PADATA_CYBERSAFE_SECUREID = 9,
	PADATA_AFS3_SALT = 10,
	PADATA_ETYPE_INFO = 11,
	PADATA_SAM_CHALLENGE = 12,
	PADATA_SAM_RESPONSE = 13,
	PADATA_PK_AS_REQ_19 = 14,
	PADATA_PK_AS_REP_19 = 15,
	PADATA_PK_AS_REQ_WIN = 15,
	PADATA_PK_AS_REQ = 16,
	PADATA_PK_AS_REP = 17,
	PADATA_PA_PK_OCSP_RESPONSE = 18,
	PADATA_ETYPE_INFO2 = 19,
	PADATA_USE_SPECIFIED_KVNO = 20,
	PADATA_SVR_REFERRAL_INFO = 20,
	PADATA_SAM_REDIRECT = 21,
	PADATA_GET_FROM_TYPED_DATA = 22,
	PADATA_SAM_ETYPE_INFO = 23,
	PADATA_SERVER_REFERRAL = 25,
	PADATA_TD_KRB_PRINCIPAL = 102,
	PADATA_PK_TD_TRUSTED_CERTIFIERS = 104,
	PADATA_PK_TD_CERTIFICATE_INDEX = 105,
	PADATA_TD_APP_DEFINED_ERROR = 106,
	PADATA_TD_REQ_NONCE = 107,
	PADATA_TD_REQ_SEQ = 108,
	PADATA_PA_PAC_REQUEST = 128,
	PADATA_S4U2SELF = 129,
	PADATA_PA_S4U_X509_USER = 130,
	PADATA_PA_PAC_OPTIONS = 167,
	PADATA_PK_AS_09_BINDING = 132,
	PADATA_CLIENT_CANONICALIZED = 133,
	PADATA_KEY_LIST_REQ = 161,
	PADATA_KEY_LIST_REP = 162,
};

enum KdcOptions {
	VALIDATE = 0x00000001,
	RENEW = 0x00000002,
	UNUSED29 = 0x00000004,
	ENCTKTINSKEY = 0x00000008,
	RENEWABLEOK = 0x00000010,
	DISABLETRANSITEDCHECK = 0x00000020,
	UNUSED16 = 0x0000FFC0,
	CONSTRAINED_DELEGATION = 0x00020000,
	CANONICALIZE = 0x00010000,
	CNAMEINADDLTKT = 0x00004000,
	OK_AS_DELEGATE = 0x00040000,
	REQUEST_ANONYMOUS = 0x00008000,
	UNUSED12 = 0x00080000,
	OPTHARDWAREAUTH = 0x00100000,
	PREAUTHENT = 0x00200000,
	INITIAL = 0x00400000,
	RENEWABLE = 0x00800000,
	UNUSED7 = 0x01000000,
	POSTDATED = 0x02000000,
	ALLOWPOSTDATE = 0x04000000,
	PROXY = 0x08000000,
	PROXIABLE = 0x10000000,
	FORWARDED = 0x20000000,
	FORWARDABLE = 0x40000000,
	RESERVED = 0x80000000,
};

enum PRINCIPAL_TYPE {
	PRINCIPAL_NT_UNKNOWN = 0,
	PRINCIPAL_NT_PRINCIPAL = 1,
	PRINCIPAL_NT_SRV_INST = 2,
	PRINCIPAL_NT_SRV_HST = 3,
	PRINCIPAL_NT_SRV_XHST = 4,
	PRINCIPAL_NT_UID = 5,
	PRINCIPAL_NT_X500_PRINCIPAL = 6,
	PRINCIPAL_NT_SMTP_NAME = 7,
	PRINCIPAL_NT_ENTERPRISE = 10,
};

enum ASN_TYPES {
	//public const int NULL = 5;
	//public const int OBJECT_IDENTIFIER = 6;
	//public const int Object_Descriptor = 7;
	//public const int EXTERNAL = 8;
	//public const int REAL = 9;
	//public const int ENUMERATED = 10;
	//public const int EMBEDDED_PDV = 11;
	//public const int RELATIVE_OID = 13;
	//public const int SET = 17;
	//public const int VideotexString = 21;
	//public const int GraphicString = 25;
	//public const int VisibleString = 26;
	//public const int CHARACTER_STRING = 29;

	//public const int APPLICATION = 1;
	//public const int  = 2;
	//public const int PRIVATE = 3;

	ASN_UNIVERSAL = 0,
	ASN_BOOLEAN = 1,
	ASN_APPLICATION = 1,
	ASN_CONTEXT = 2,
	ASN_INTEGER = 2,
	ASN_BIT_STRING = 3,
	ASN_OCTET_STRING = 4,
	ASN_UTF8String = 12,
	ASN_SEQUENCE = 16,
	ASN_NumericString = 18,
	ASN_PrintableString = 19,
	ASN_TeletexString = 20,
	ASN_IA5String = 22,
	ASN_UTCTime = 23,
	ASN_GeneralizedTime = 24,
	ASN_GeneralString = 27,
	ASN_UniversalString = 28,
	ASN_BMPString = 30,
	ASN_LIST = 0xa0,
};

enum TICKET_FLAGS {
	reserved = 2147483648,
	forwardable = 0x40000000,
	forwarded = 0x20000000,
	proxiable = 0x10000000,
	proxy = 0x08000000,
	may_postdate = 0x04000000,
	postdated = 0x02000000,
	invalid = 0x01000000,
	renewable = 0x00800000,
	initial = 0x00400000,
	pre_authent = 0x00200000,
	hw_authent = 0x00100000,
	ok_as_delegate = 0x00040000,
	anonymous = 0x00020000,
	//name_canonicalize	= 0x00010000,
	//cname_in_pa_data = 0x00040000,
	enc_pa_rep = 0x00010000,
	reserved1 = 0x00000001,
	empty = 0x00000000,
};

enum PacInfoBufferType {
	Pac_LogonInfo = 1,
	Pac_CredInfo = 2,
	Pac_ServerChecksum = 6,
	Pac_KDCChecksum = 7,
	Pac_ClientName = 0xA,
	Pac_S4U2Proxy = 0xb,
	Pac_UpnDns = 0xc,
	Pac_ClientClaims = 0xd,
	Pac_DeviceInfo = 0xe,
	Pac_DeviceClaims = 0xf,
	Pac_TicketChecksum = 0x10,
	Pac_Attributes = 0x11,
	Pac_Requestor = 0x12,
	Pac_FullPacChecksum = 0x13
};


byte* lookupKadminErrorCode(uint errorCode) {
	if ( errorCode > 7)
		return "unknown";

	byte* KERBEROS_ERROR[8] = {
		"KRB5_KPASSWD_SUCCESS",
		"KRB5_KPASSWD_MALFORMED",
		"KRB5_KPASSWD_HARDERROR",
		"KRB5_KPASSWD_AUTHERROR",
		"KRB5_KPASSWD_SOFTERROR",
		"KRB5_KPASSWD_ACCESSDENIED",
		"KRB5_KPASSWD_BAD_VERSION",
		"KRB5_KPASSWD_INITIAL_FLAG_NEEDED"
	};
	return KERBEROS_ERROR[errorCode];
}
/*
byte* lookupKrbErrorCode(uint errorCode) {
	if ( errorCode > 0x5d)
		return "";

	byte* KERBEROS_ERROR[0x5E] = {
		"KDC_ERR_NONE (0x0) - No error",
		"KDC_ERR_NAME_EXP (0x1) - Client's entry in KDC database has expired",
		"KDC_ERR_SERVICE_EXP (0x2) - Server's entry in KDC database has expired",
		"KDC_ERR_BAD_PVNO (0x3) - Requested Kerberos version number not supported",
		"KDC_ERR_C_OLD_MAST_KVNO (0x4) - Client's key encrypted in old master key",
		"KDC_ERR_S_OLD_MAST_KVNO (0x5) - Server's key encrypted in old master key",
		"KDC_ERR_C_PRINCIPAL_UNKNOWN (0x6) - Client not found in Kerberos database",
		"KDC_ERR_S_PRINCIPAL_UNKNOWN (0x7) - Server not found in Kerberos database",
		"KDC_ERR_PRINCIPAL_NOT_UNIQUE (0x8) - Multiple principal entries in KDC database",
		"KDC_ERR_NULL_KEY (0x9) - The client or server has a null key (master key)",
		"KDC_ERR_CANNOT_POSTDATE (0xA) - Ticket (TGT) not eligible for postdating",
		"KDC_ERR_NEVER_VALID (0xB) - Requested start time is later than end time",
		"KDC_ERR_POLICY (0xC) - Requested start time is later than end time",
		"KDC_ERR_BADOPTION (0xD) - KDC cannot accommodate requested option",
		"KDC_ERR_ETYPE_NOTSUPP (0xE) - KDC has no support for encryption type",
		"KDC_ERR_SUMTYPE_NOSUPP (0xF) - KDC has no support for checksum type",
		"KDC_ERR_PADATA_TYPE_NOSUPP (0x10) - KDC has no support for PADATA type (pre-authentication data)",
		"KDC_ERR_TRTYPE_NO_SUPP (0x11) - KDC has no support for transited type",
		"KDC_ERR_CLIENT_REVOKED (0x12) - Client's credentials have been revoked",
		"KDC_ERR_SERVICE_REVOKED (0x13) -Credentials for server have been revoked",
		"KDC_ERR_TGT_REVOKED (0x14) - TGT has been revoked",
		"KDC_ERR_CLIENT_NOTYET (0x15) - Client not yet valid�try again later",
		"KDC_ERR_SERVICE_NOTYET (0x16) -Server not yet valid�try again later",
		"KDC_ERR_KEY_EXPIRED (0x17) - Password has expired�change password to reset",
		"KDC_ERR_PREAUTH_FAILED (0x18) - Pre-authentication information was invalid",
		"KDC_ERR_PREAUTH_REQUIRED (0x19) - Additional preauthentication required",
		"KDC_ERR_SERVER_NOMATCH (0x1A) - KDC does not know about the requested server",
		"KDC_ERR_MUST_USE_USER2USER (0x1B) - Server principal valid for user2user only",
		"KDC_ERR_PATH_NOT_ACCEPTED (0x1C) - KDC Policy rejects transited path",
		"KDC_ERR_SVC_UNAVAILABLE (0x1D) - KDC is unavailable",
		"KRB_UNKNOWN (0x1E) - Code unknown",
		"KRB_AP_ERR_BAD_INTEGRITY (0x1F) - Integrity check on decrypted field failed",
		"KRB_AP_ERR_TKT_EXPIRED (0x20) - The ticket has expired",
		"KRB_AP_ERR_TKT_NYV (0x21) - The ticket is not yet valid",
		"KRB_AP_ERR_REPEAT (0x22) - The request is a replay",
		"KRB_AP_ERR_NOT_US (0x23) - The ticket is not for us",
		"KRB_AP_ERR_BADMATCH (0x24) -The ticket and authenticator do not match",
		"KRB_AP_ERR_SKEW (0x25) - The clock skew is too great",
		"KRB_AP_ERR_BADADDR (0x26) - Network address in network layer header doesn't match address inside ticket",
		"KRB_AP_ERR_BADVERSION (0x27) - Protocol version numbers don't match (PVNO)",
		"KRB_AP_ERR_MSG_TYPE (0x28) - Message type is unsupported",
		"KRB_AP_ERR_MODIFIED (0x29) - Message stream modified and checksum didn't match",
		"KRB_AP_ERR_BADORDER (0x2A) - Message out of order (possible tampering)",
		"KRB_UNKNOWN (0x2B) - Code unknown",
		"KRB_AP_ERR_BADKEYVER (0x2C) - Specified version of key is not available",
		"KRB_AP_ERR_NOKEY (0x2D) - Service key not available",
		"KRB_AP_ERR_MUT_FAIL (0x2E) - Mutual authentication failed",
		"KRB_AP_ERR_BADDIRECTION (0x2F) - Incorrect message direction",
		"KRB_AP_ERR_METHOD (0x30) - Alternative authentication method required",
		"KRB_AP_ERR_BADSEQ (0x31) - Incorrect sequence number in message",
		"KRB_AP_ERR_INAPP_CKSUM (0x32) - Inappropriate type of checksum in message (checksum may be unsupported)",
		"KRB_AP_PATH_NOT_ACCEPTED (0x33) - Desired path is unreachable",
		"KRB_ERR_RESPONSE_TOO_BIG (0x34) - Too much data",
		"KRB_UNKNOWN (0x15) - Code unknown",
		"KRB_UNKNOWN (0x16) - Code unknown",
		"KRB_UNKNOWN (0x17) - Code unknown",
		"KRB_UNKNOWN (0x18) - Code unknown",
		"KRB_UNKNOWN (0x19) - Code unknown",
		"KRB_UNKNOWN (0x1A) - Code unknown",
		"KRB_UNKNOWN (0x1B) - Code unknown",
		"KRB_ERR_GENERIC (0x3C) - Generic error; the description is in the e-data field",
		"KRB_ERR_FIELD_TOOLONG (0x3D) - Field is too long for this implementation",
		"KDC_ERR_CLIENT_NOT_TRUSTED (0x3E) - The client trust failed or is not implemented",
		"KDC_ERR_KDC_NOT_TRUSTED (0x3F) - The KDC server trust failed or could not be verified",
		"KDC_ERR_INVALID_SIG (0x40) - The signature is invalid",
		"KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED (0x41) - KDC policy has determined the provided Diffie-Hellman key parameters are not acceptable",
		"KDC_ERR_CERTIFICATE_MISMATCH (0x42) - certificate doesn't match client user",
		"KRB_AP_ERR_NO_TGT (0x43) - No TGT was presented or available",
		"KDC_ERR_WRONG_REALM (0x44) -Incorrect domain or principal",
		"KRB_AP_ERR_USER_TO_USER_REQUIRED (0x45) - Ticket must be for USER-TO-USER",
		"KDC_ERR_CANT_VERIFY_CERTIFICATE (0x46)",
		"KDC_ERR_INVALID_CERTIFICATE (0x47)",
		"KDC_ERR_REVOKED_CERTIFICATE (0x48)",
		"KDC_ERR_REVOCATION_STATUS_UNKNOWN (0x49)",
		"KRB_UNKNOWN (0x4A) - Code unknown",
		"KDC_ERR_CLIENT_NAME_MISMATCH (0x4B)",
		"KDC_ERR_KDC_NAME_MISMATCH (0x4C)",
		"KDC_ERR_INCONSISTENT_KEY_PURPOSE (0x4D) - The client certificate does not contain the KeyPurposeId EKU and is required",
		"KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED (0x4E) - The signature algorithm used to sign the CA certificate is not accepted",
		"KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED (0x4F) - The client did not include the required paChecksum parameter",
		"KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED (0x50) - The signature algorithm used to sign the request is not accepted",
		"KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED (0x51) - The KDC does not support public key encryption for PKINIT",
		"KRB_AP_ERR_PRINCIPAL_UNKNOWN (0x52) - A well-known Kerberos principal name is used but not supported",
		"KRB_AP_ERR_REALM_UNKNOWN (0x53) - A well-known Kerberos realm name is used but not supported",
		"KRB_AP_ERR_PRINCIPAL_RESERVED (0x54) - A reserved Kerberos principal name is used but not supported",
		"KRB_UNKNOWN (0x55) - Code unknown",
		"KRB_UNKNOWN (0x56) - Code unknown",
		"KRB_UNKNOWN (0x57) - Code unknown",
		"KRB_UNKNOWN (0x58) - Code unknown",
		"KRB_UNKNOWN (0x59) - Code unknown",
		"KDC_ERR_PREAUTH_EXPIRED (0x5A) - The provided pre-auth data has expired",
		"KDC_ERR_MORE_PREAUTH_DATA_REQUIRED (0x5B) - The KDC found the presented pre-auth data incomplete and requires additional information",
		"KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET (0x5C) - The client sent an authentication set that the KDC was not expecting",
		"KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS (0x5D) - The provided FAST options that were marked as critical are unknown to the KDC and cannot be processed"
	};
	return KERBEROS_ERROR[errorCode];
}
*/

//////////////////////////////

typedef struct AsnElt {
	byte* objBuf;
	int objBufSize;
	int objOff;
	int objLen;
	int valOff;
	int valLen;
	int hasEncodedHeader;

	int tagClass;
	int tagValue;
	struct AsnElt* sub;
	int subCount;
} AsnElt;

typedef struct {
	bool isSet;
	int year;
	int month;
	int day;
	int hour;
	int minute;
	int second;
	int millisecond;
} DateTime;

typedef struct _ADKerbLocal {
	long  ad_type;
	int   ad_data_length;
	byte* ad_data;
	int   LocalData_length;
	byte* LocalData;
} ADKerbLocal;

typedef struct _ADRestrictionEntry {
	long  ad_type;
	int   ad_data_length;
	byte* ad_data;
	long  restriction_type;
	int   restriction_length;
	byte* restriction;
} ADRestrictionEntry;

typedef struct _ADIfRelevant {
	long  ad_type;
	int   ad_data_length;
	byte* ad_data;
	int   ADData_count;
	void** ADData;
} ADIfRelevant;

typedef struct _Checksum {
	int   cksumtype;
	int   checksum_length;
	byte* checksum;
}Checksum;

typedef struct _ETYPE_INFO2_ENTRY {
	int etype;
	char* salt;
} ETYPE_INFO2_ENTRY;

typedef struct _HostAddress {
	long  addr_type;
	char* addr_string;
} HostAddress;

typedef struct _EncryptedData {
	int   etype;
	uint  kvno;
	uint  cipher_size;
	byte* cipher;
} EncryptedData;

typedef struct _PrincipalName {
	long   name_type;
	uint   name_count;
	char** name_string;
} PrincipalName;

typedef struct _Ticket {
	int           tkt_vno;
	char*         realm;
	PrincipalName sname;
	EncryptedData enc_part;
} Ticket;

typedef struct _KDCReqBody {
	uint		  kdc_options;
	PrincipalName cname;
	PrincipalName sname;
	char*         realm;
	uint          till;		// DateTime
	uint          rtime;	// DateTime
	uint          nonce;
	uint		  addresses_count;
	HostAddress*  addresses;
	uint          additional_tickets_count;
	Ticket*       additional_tickets;
	uint          etypes_count;
	int*          etypes;
	EncryptedData enc_authorization_data;
} KDCReqBody;

typedef struct _S4UUserID {
	uint          nonce;
	PrincipalName cname;
	char*         crealm;
	int           options;
}S4UUserID;

typedef struct _KERB_PA_PAC_REQUEST {
	bool include_pac;
} KERB_PA_PAC_REQUEST;

typedef struct _PA_S4U_X509_USER {
	S4UUserID user_id;
	Checksum  cksum;
}PA_S4U_X509_USER;

typedef struct _PA_KEY_LIST_REQ {
	int Enctype;
} PA_KEY_LIST_REQ;

typedef struct _PA_FOR_USER {
	PrincipalName userName;
	char*		  userRealm;
	Checksum	  cksum;
	char*		  auth_package;
} PA_FOR_USER;

typedef struct _PA_PAC_OPTIONS {
	byte kerberosFlags[4];
} PA_PAC_OPTIONS;

typedef struct _PA_DATA {
	uint  type;
	void* value;
} PA_DATA;

typedef struct _LastReq {
	int      lr_type;
	DateTime lr_value;
} LastReq;

typedef struct _EncryptionKey {
	int   key_type;
	uint  key_size;
	byte* key_value;
} EncryptionKey;

typedef struct _EncryptedPAData {
	int			  keytype;
	int           keysize;
	byte*         keyvalue;
	EncryptionKey encryptionKey;
} EncryptedPAData;

typedef struct _EncKDCRepPart {
	EncryptionKey   key;
	LastReq	        lastReq;
	uint		    nonce;
	DateTime	    key_expiration;
	uint		    flags;
	DateTime	    authtime;
	DateTime	    starttime;
	DateTime	    endtime;
	DateTime	    renew_till;
	char*	        realm;
	PrincipalName   sname;
	EncryptedPAData encryptedPaData;
} EncKDCRepPart;

typedef struct _KrbCredInfo {
	EncryptionKey key;
	char*		   prealm;
	PrincipalName pname;
	uint		   flags;
	DateTime	   authtime;
	DateTime	   starttime;
	DateTime	   endtime;
	DateTime	   renew_till;
	char*		   srealm;
	PrincipalName sname;
} KrbCredInfo;

typedef struct _EncKrbCredPart {
	uint ticket_count;
	KrbCredInfo* ticket_info;
} EncKrbCredPart;

typedef struct _KRB_CRED {
	long			pvno;
	long			msg_type;
	uint			ticket_count;
	Ticket*			tickets;
	EncKrbCredPart enc_part;
} KRB_CRED;

typedef struct _Authenticator {
	long          authenticator_vno;
	char*         crealm;
	Checksum      cksum;
	PrincipalName cname;
	long          cusec;
	DateTime      ctime;
	EncryptionKey subkey;
	uint          seq_number;
} Authenticator;

typedef struct _AuthorizationData {
	int   ad_type;
	int   ad_data_length;
	byte* ad_data;
} AuthorizationData;

typedef struct _TransitedEncoding {
	int tr_type;
	int   contents_length;
	byte* contents;
} TransitedEncoding;

typedef struct _EncTicketPart {
	int				   flags;
	EncryptionKey	   key;
	char*			   crealm;
	PrincipalName	   cname;
	TransitedEncoding  transited;
	DateTime		   authtime;
	DateTime		   starttime;
	DateTime		   endtime;
	DateTime		   renew_till;
	HostAddress*	   caddr;
	AuthorizationData* authorization_data;
} EncTicketPart;

typedef struct _EncKrbPrivPart {
	uint  seq_number;
	char* new_password;
	char* host_name;
	char* username;
	char* realm;
} EncKrbPrivPart;

typedef struct _KRB_PRIV {
	long	       pvno;
	long	       msg_type;
	EncryptionKey  ekey;
	EncKrbPrivPart enc_part;
} KRB_PRIV;

/////////////////////////

typedef struct _AS_REQ {
	long	   pvno;
	long	   msg_type;
	uint	   pa_data_count;
	PA_DATA*   pa_data;
	KDCReqBody req_body;
} AS_REQ;

typedef struct _AS_REP {
	long          pvno;
	long          msg_type;
	int           pa_data_count;
	PA_DATA*      pa_data;
	char*         crealm;
	PrincipalName cname;
	Ticket		  ticket;
	EncryptedData enc_part;
} AS_REP;

typedef struct _AP_REQ {
	long          pvno;
	long          msg_type;
	uint          ap_options;
	Ticket		  ticket;
	Authenticator authenticator;
	EncryptionKey key;
	int           keyUsage;
} AP_REQ;

typedef struct _TGS_REP {
	long	      pvno;
	long	      msg_type;
	PA_DATA       padata;
	char*         crealm;
	PrincipalName cname;
	Ticket		  ticket;
	EncryptedData enc_part;
} TGS_REP;

//////////////////////////
