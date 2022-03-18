//go:build linux
// +build linux

package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/cc"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
)

func readJSONConfig(filename string) (err error) {
	// read JSON
	jsonData, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	return emp3r0r_data.ReadJSONConfig(jsonData, cc.RuntimeConfig)
}

// cleanup temp files
func cleanup() bool {
	// is cc currently running?
	if tun.IsPortOpen("127.0.0.1", cc.RuntimeConfig.CCPort) {
		return false
	}

	// unlock downloads
	files, err := ioutil.ReadDir(cc.FileGetDir)
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

func main() {

	// cleanup or abort
	if !cleanup() {
		log.Fatal("CC is already running")
	}

	cdnproxy := flag.String("cdn2proxy", "", "Start cdn2proxy server on this port")
	config := flag.String("config", cc.EmpConfigFile, "Use this config file to update hardcoded variables")
	apiserver := flag.Bool("api", false, "Run API server in background, you can send commands to /tmp/emp3r0r.socket")
	flag.Parse()

	// read config file
	err := readJSONConfig(*config)
	if err != nil {
		os.RemoveAll(*config)
		err = cc.PromptForConfig(false)
		if err != nil {
			log.Fatalf("Failed to configure emp3r0r: %v", err)
		}
		cmd := exec.Command("bash", "./emp3r0r")
		err = cmd.Start()
		if err != nil {
			log.Fatalf("Re-run ./emp3r0r: %v", err)
		}
	} else {
		go cc.TLSServer()
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
