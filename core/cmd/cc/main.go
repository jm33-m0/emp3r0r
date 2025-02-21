//go:build linux
// +build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/tools"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/core"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
)

// Options struct to hold flag values
type Options struct {
	cdnProxy         string
	config           string
	names            string
	apiServer        bool
	sshRelayPort     string
	connectRelayAddr string
	relayedPort      int
	debug            bool
}

func parseFlags() *Options {
	opts := &Options{}
	flag.StringVar(&opts.cdnProxy, "cdn2proxy", "", "Start cdn2proxy server on this port")
	flag.StringVar(&opts.names, "gencert", "", "Generate C2 server cert with these host names")
	flag.BoolVar(&opts.apiServer, "api", false, "Run API server in background, you can send commands to /tmp/emp3r0r.socket")
	flag.StringVar(&opts.sshRelayPort, "relay_server", "", "Act as SSH remote forwarding relay on this port")
	flag.StringVar(&opts.connectRelayAddr, "connect_relay", "", "Connect to SSH remote forwarding relay (host:port)")
	flag.IntVar(&opts.relayedPort, "relayed_port", 0, "Relayed port, use with -connect_relay")
	flag.BoolVar(&opts.debug, "debug", false, "Do not kill tmux session when crashing, so you can see the crash log")
	flag.Parse()
	return opts
}

func init() {
	// set up dirs and default varaibles
	// including config file location
	live.Prompt = cli.Prompt // implement prompt_func
	err := live.InitCC()
	if err != nil {
		log.Fatalf("C2 file paths setup: %v", err)
	}

	// read config file
	err = live.ReadJSONConfig()
	if err != nil {
		logging.Fatalf("Failed to read config: %v", err)
	}

	// set up magic string
	live.InitMagicAgentOneTimeBytes()
}

func main() {
	// Parse command-line flags
	opts := parseFlags()

	// do not kill tmux session when crashing
	if opts.debug {
		live.TmuxPersistence = true
	}

	// abort if CC is already running
	if tools.IsCCRunning() {
		logging.Fatalf("CC is already running")
	}

	// Run as SSH relay client if requested
	if opts.connectRelayAddr != "" {
		if opts.relayedPort == 0 {
			logging.Fatalf("Please specify -relayed_port")
		}
		runSSHRelayClient(opts)
	}

	// Start cdn2proxy server if specified
	if opts.cdnProxy != "" {
		startCDN2Proxy(opts)
	}

	// Run as SSH relay server if specified; otherwise run CLI
	if opts.sshRelayPort != "" {
		runSSHRelayServer(opts)
	} else {
		core.CliMain()
	}
}

// handle SSH relay client logic
func runSSHRelayClient(opts *Options) {
	sshPassword := cli.Prompt("Enter SSH password: ")
	go func(pass string) {
		defer logging.Errorf("session unexpectedly exited, please restart emp3r0r")
		SSHConnections := make(map[string]context.CancelFunc, 10)
		pubkey, sshKeyErr := transport.SSHPublicKey(live.RuntimeConfig.SSHHostKey)
		if sshKeyErr != nil {
			logging.Fatalf("Parsing SSHPublicKey: %v", sshKeyErr)
		}
	ssh_connect:
		ccport, err := strconv.Atoi(live.RuntimeConfig.CCPort)
		if err != nil {
			logging.Fatalf("Invalid CC port: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		sshKeyErr = transport.SSHRemoteFwdClient(opts.connectRelayAddr,
			pass,
			pubkey, // enable host key verification
			ccport, // connect to C2 port
			&SSHConnections, ctx, cancel)
		if sshKeyErr == nil {
			sshKeyErr = fmt.Errorf("session unexpectedly exited")
			logging.Warningf("SSHRemoteFwdClient: %v, retrying", sshKeyErr)
		}
		for ctx.Err() == nil {
			util.TakeABlink()
		}
		goto ssh_connect
	}(sshPassword)
}

// handle SSH relay server logic
func runSSHRelayServer(opts *Options) {
	sshPassword := util.RandMD5String()
	log.Printf("SSH password is %s.\nCopy ~/.emp3r0r to client host, "+
		"then run\nemp3r0r -connect_relay relay_ip:%s\n"+
		"to connect to this relay server. C2 port %s will be relayed to client host.",
		strconv.Quote(sshPassword), opts.sshRelayPort, live.RuntimeConfig.CCPort)
	if err := transport.SSHRemoteFwdServer(opts.sshRelayPort,
		sshPassword,
		live.RuntimeConfig.SSHHostKey); err != nil {
		log.Fatalf("SSHRemoteFwdServer: %v", err)
	}
}

// helper function to start the cdn2proxy server
func startCDN2Proxy(opts *Options) {
	go func() {
		logFile, openErr := os.OpenFile("/tmp/ws.log", os.O_CREATE|os.O_RDWR, 0o600)
		if openErr != nil {
			logging.Fatalf("OpenFile: %v", openErr)
		}
		openErr = cdn2proxy.StartServer(opts.cdnProxy, "127.0.0.1:"+live.RuntimeConfig.CCPort, "ws", logFile)
		if openErr != nil {
			logging.Fatalf("CDN StartServer: %v", openErr)
		}
	}()
}
