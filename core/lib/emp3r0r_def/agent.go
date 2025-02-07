package emp3r0r_def

import (
	"context"

	"github.com/jaypipes/ghw"
	"github.com/posener/h2conn"
)

// Emp3r0rAgent agent properties
type Emp3r0rAgent struct {
	Tag         string           `json:"Tag"`          // identifier of the agent
	Name        string           `json:"Name"`         // short name of the agent
	Version     string           `json:"Version"`      // agent version
	Transport   string           `json:"Transport"`    // transport the agent uses (HTTP2 / CDN / TOR)
	Hostname    string           `json:"Hostname"`     // Hostname and machine ID
	Hardware    string           `json:"Hardware"`     // machine details and hypervisor
	Container   string           `json:"Container"`    // container tech (if any)
	CPU         string           `json:"CPU"`          // CPU info
	GPU         string           `json:"GPU"`          // GPU info
	Mem         string           `json:"Mem"`          // memory size
	OS          string           `json:"OS"`           // OS name and version
	GOOS        string           `json:"GOOS"`         // runtime.GOOS
	Kernel      string           `json:"Kernel"`       // kernel release
	Arch        string           `json:"Arch"`         // kernel architecture
	From        string           `json:"From"`         // where the agent is coming from, usually a public IP, or 127.0.0.1
	IPs         []string         `json:"IPs"`          // IPs that are found on target's NICs
	ARP         []string         `json:"ARP"`          // ARP table
	User        string           `json:"User"`         // user account info
	HasRoot     bool             `json:"HasRoot"`      // is agent run as root?
	HasTor      bool             `json:"HasTor"`       // is agent from Tor?
	HasInternet bool             `json:"HasInternet"`  // has internet access?
	NCSIEnabled bool             `json:"NCSI_Enabled"` // NCSI (or similar services) enabled
	Process     *AgentProcess    `json:"Process"`      // agent's process
	Exes        []string         `json:"Exes"`         // executables found in agent's $PATH
	CWD         string           `json:"CWD"`          // current working directory
	Product     *ghw.ProductInfo `json:"Product"`      // product info
}

// AgentProcess process info of our agent
type AgentProcess struct {
	PID     int    `json:"PID"`     // pid
	PPID    int    `json:"PPID"`    // parent PID
	Cmdline string `json:"Cmdline"` // process name and command line args
	Parent  string `json:"Parent"`  // parent process name and cmd line args
}

// MsgTunData data to send in the tunnel
type MsgTunData struct {
	Payload string `json:"payload"` // payload
	Tag     string `json:"tag"`     // tag of the agent
	Time    string `json:"time"`    // timestamp
}

// H2Conn add context to h2conn.Conn
type H2Conn struct {
	Conn   *h2conn.Conn
	Ctx    context.Context
	Cancel context.CancelFunc
}
