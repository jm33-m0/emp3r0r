package def

import (
	"time"
)

// Emp3r0rAgent agent properties
type Emp3r0rAgent struct {
	Tag            string        `cbor:"1,keyasint"`  // identifier of the agent
	Name           string        `cbor:"2,keyasint"`  // short name of the agent
	ShortID        string        `cbor:"35,keyasint"` // short hash of UUID-UUIDSig for persistence
	Version        string        `cbor:"3,keyasint"`  // agent version
	Transport      string        `cbor:"4,keyasint"`  // transport the agent uses (HTTP2 / CDN / TOR)
	Hostname       string        `cbor:"5,keyasint"`  // Hostname and machine ID
	Hardware       string        `cbor:"6,keyasint"`  // machine details and hypervisor
	Container      string        `cbor:"7,keyasint"`  // container tech (if any)
	Uptime         string        `cbor:"33,keyasint"` // System uptime
	Groups         string        `cbor:"34,keyasint"` // User groups
	CPU            string        `cbor:"8,keyasint"`  // CPU info
	GPU            string        `cbor:"9,keyasint"`  // GPU info
	Mem            string        `cbor:"10,keyasint"` // memory size
	OS             string        `cbor:"11,keyasint"` // OS name and version
	GOOS           string        `cbor:"12,keyasint"` // runtime.GOOS
	Kernel         string        `cbor:"13,keyasint"` // kernel release
	Arch           string        `cbor:"14,keyasint"` // kernel architecture
	From           string        `cbor:"15,keyasint"` // where the agent is coming from, usually a public IP, or 127.0.0.1
	IPs            []string      `cbor:"16,keyasint"` // IPs that are found on target's NICs
	ARP            []string      `cbor:"17,keyasint"` // ARP table
	User           string        `cbor:"18,keyasint"` // user account info
	HasRoot        bool          `cbor:"19,keyasint"` // is agent run as root?
	HasTor         bool          `cbor:"20,keyasint"` // is agent from Tor?
	HasInternet    bool          `cbor:"21,keyasint"` // has internet access?
	NCSIEnabled    bool          `cbor:"22,keyasint"` // NCSI (or similar services) enabled
	Process        *AgentProcess `cbor:"23,keyasint"` // agent's process
	Exes           []string      `cbor:"24,keyasint"` // executables found in agent's $PATH
	CWD            string        `cbor:"25,keyasint"` // current working directory
	Product        any           `cbor:"26,keyasint"` // product info
	UUID           string        `cbor:"27,keyasint"` // agent UUID, specific to the agent binary
	UUIDSig        string        `cbor:"28,keyasint"` // signature of UUID, signed by CA
	PublicKey      string        `cbor:"29,keyasint"` // agent's public key (PEM encoded) for TOFU
	C2Host         string        `cbor:"30,keyasint"` // C2 server's IP or domain name that the agent is connected to
	LastSeen       time.Time     `cbor:"31,keyasint"` // last time the agent was seen
	LastSeenRTT    time.Duration `cbor:"32,keyasint"` // last RTT of the agent
	AgentToken     *AgentToken   `cbor:"36,keyasint"` // current token issued by C2
	MeshRoute      string        `cbor:"37,keyasint"` // p2p routing role or gateway used by this agent
	P2PRelayPort   string        `cbor:"38,keyasint"` // dynamic P2P relay port assigned to this agent
	MeshGossipPort string        `cbor:"39,keyasint"` // dynamic mesh gossip port assigned to this agent
	Files          []string      `cbor:"40,keyasint"` // list of available files/modules in agent storage/MemFS
	GOArch         string        `cbor:"41,keyasint"` // runtime.GOARCH of the agent binary (not the OS kernel arch)
}

// EnrichedPeer holds detailed peer information signed by C2
type EnrichedPeer struct {
	UUID           string   `cbor:"1,keyasint"`
	IPs            []string `cbor:"2,keyasint"`
	From           string   `cbor:"3,keyasint"`
	P2PRelayPort   string   `cbor:"4,keyasint"`
	MeshGossipPort string   `cbor:"5,keyasint"`
	Files          []string `cbor:"6,keyasint"`
	LastSeen       int64    `cbor:"7,keyasint"`
}

// EnrichedPeerList represents the C2 CA-signed list of active peers
type EnrichedPeerList struct {
	Peers     []EnrichedPeer `cbor:"1,keyasint"`
	Signature []byte         `cbor:"2,keyasint"` // CA signature over CBOR of Peers
}

// AgentProcess process info of our agent
type AgentProcess struct {
	PID     int    `cbor:"1,keyasint"` // pid
	PPID    int    `cbor:"2,keyasint"` // parent PID
	Cmdline string `cbor:"3,keyasint"` // process name and command line args
	Parent  string `cbor:"4,keyasint"` // parent process name and cmd line args
}

// MsgTunData data to send in the tunnel, between C&C and agent
// this can also be used for operator to CC communication
type MsgTunData struct {
	JobID            string            `cbor:"1,keyasint"`  // job ID, to retrieve the response, or empty if not a command
	CmdSlice         []string          `cbor:"2,keyasint"`  // command args, [0] is the command, or empty if not a command
	Response         []byte            `cbor:"3,keyasint"`  // response from the agent, or message to operator
	Tag              string            `cbor:"4,keyasint"`  // tag of the agent, or message type if sent to operator
	Time             string            `cbor:"5,keyasint"`  // timestamp
	AgentUUID        string            `cbor:"6,keyasint"`  // agent UUID for robust identification
	AgentUUIDSig     string            `cbor:"7,keyasint"`  // agent UUID signature for verification
	EphemPublicKey   []byte            `cbor:"8,keyasint"`  // ephemeral public key for ECDH key exchange
	PeerList         []string          `cbor:"9,keyasint"`  // pushed by CC to help with discovery
	EnrichedPeerList *EnrichedPeerList `cbor:"10,keyasint"` // C2 CA-signed enriched peer list
}

// TokenEntry is one entry of a !list_tokens response, marshaled as CBOR by
// the agent and decoded by the CC (completion + console rendering).
type TokenEntry struct {
	Key          string `cbor:"1,keyasint"` // SID, or make_token session name when IsSession
	FriendlyName string `cbor:"2,keyasint"` // human-readable identity of the token
	IsSession    bool   `cbor:"3,keyasint"` // true when Key is a make_token logon session
}

// SessionEntry is one entry of a !list_sessions response, marshaled as CBOR
// by the agent and decoded by the CC (completion + console rendering).
type SessionEntry struct {
	Name      string `cbor:"1,keyasint"` // session reference name (usable via the token option)
	User      string `cbor:"2,keyasint"` // account name
	Domain    string `cbor:"3,keyasint"` // domain ("." for local accounts)
	LogonID   uint64 `cbor:"4,keyasint"` // logon session AuthenticationId (LUID)
	CreatedAt string `cbor:"5,keyasint"` // RFC3339 timestamp
}
