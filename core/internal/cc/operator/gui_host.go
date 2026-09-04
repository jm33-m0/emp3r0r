package operator

import (
	"fmt"
	"os"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/tools"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/gui"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// GuiStartOptions is the option bag the cc binary passes to GuiMain. It is an
// alias of the gui package's StartOptions so cmd/cc keeps a single import.
type GuiStartOptions = gui.StartOptions

// guiHost adapts the operator console to the gui.ConsoleHost contract. It owns
// the C2 link (WireGuard tunnel, operator config) and the interactive console;
// lib/gui only presents them in the browser.
type guiHost struct {
	wgDevice *wireguard.WireGuardDevice
}

// Connect brings the C2 link up for the given credentials, mirroring what
// cmd/cc/main.go's connectWg does for the tmux CLI: WireGuard tunnel up,
// operator config downloaded & extracted, config loaded, operator address
// globals set, background jobs started. On error it tears the tunnel down.
func (h *guiHost) Connect(creds gui.Creds) error {
	wgUp := false
	defer func() {
		if !wgUp && h.wgDevice != nil {
			h.wgDevice.Close()
			h.wgDevice = nil
		}
	}()

	// 1. WireGuard tunnel to the C2 server
	wireguard.WgServerIP = creds.ServerWgIP
	wireguard.WgOperatorIP = creds.OperatorWgIP
	if _, err := wireguard.PublicKeyFromPrivate(creds.OperatorWgKey); err != nil {
		return fmt.Errorf("invalid operator WireGuard key: %v", err)
	}
	wgConfig := wireguard.WireGuardConfig{
		PrivateKey: creds.OperatorWgKey,
		IPAddress:  creds.OperatorWgIP + "/24",
		ListenPort: util.RandInt(1024, 65535),
		Peers: []wireguard.PeerConfig{
			{
				PublicKey:  creds.ServerWgKey,
				AllowedIPs: creds.ServerWgIP + "/32",
				Endpoint:   fmt.Sprintf("%s:%d", creds.C2Host, creds.OperatorPort),
			},
		},
	}
	logging.Infof("Connecting to C2 WireGuard server %s:%d ...", creds.C2Host, creds.OperatorPort)
	type wgResult struct {
		dev *wireguard.WireGuardDevice
		err error
	}
	resCh := make(chan wgResult, 1)
	go func() {
		dev, err := wireguard.WireGuardMain(wgConfig)
		resCh <- wgResult{dev: dev, err: err}
	}()
	select {
	case res := <-resCh:
		if res.err != nil {
			return fmt.Errorf("WireGuard: %v", res.err)
		}
		h.wgDevice = res.dev
	case <-time.After(2 * time.Second):
		// The link is up (WireGuardMain blocks while the tunnel lives).
		// Watch for late teardown so we can log when the interface dies.
		go func() {
			res := <-resCh
			if res.err != nil {
				logging.Errorf("WireGuard interface error: %v", res.err)
			} else {
				logging.Warningf("WireGuard interface closed")
			}
		}()
	}
	wgUp = true
	logging.Successf("WireGuard link is up (%s -> %s)", creds.OperatorWgIP, creds.ServerWgIP)

	// 2. download and extract config files (retries internally)
	url := fmt.Sprintf("http://%s:%d/%s",
		wireguard.WgServerIP, wireguard.WgFileServerPort, "emp3r0r_operator_config.tar.gz")
	logging.Infof("Downloading operator config from %s", url)
	if err := live.DownloadExtractConfig(url, ftp.DownloadFile); err != nil {
		return fmt.Errorf("config download: %w", err)
	}

	// 3. load the operator config (certs, C2 endpoints, modules)
	if err := config.LoadConfig(); err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	OperatorPort = creds.OperatorPort + 1 // operator mTLS service sits next to the WG port
	ServerIP = creds.C2Host
	ServerKey = creds.ServerWgKey
	logging.Infof("Operator address: %s (mTLS)", OperatorAddrForGUI())

	// 4. operator background jobs (agent refresher, message tunnel)
	backgroundJobs()
	return nil
}

// OperatorAddrForGUI reports the operator mTLS address (WireGuard IP + port).
func OperatorAddrForGUI() string {
	ip := wireguard.WgServerIP
	if ip == "" {
		ip = "?"
	}
	return fmt.Sprintf("%s:%d", ip, OperatorPort)
}

// Disconnect tears the WireGuard tunnel down (GUI shutdown).
func (h *guiHost) Disconnect() {
	if h.wgDevice != nil {
		logging.Debugf("Closing WireGuard device")
		h.wgDevice.Close()
		h.wgDevice = nil
	}
}

// ConfigureConsole runs the one-time operator console setup.
func (h *guiHost) ConfigureConsole() {
	setupOperatorConsole()
}

// RunConsole blocks while the interactive operator console runs on the pty
// the GUI attached to fd 0/1/2.
func (h *guiHost) RunConsole() error {
	return EMP3R0R_CONSOLE.Start()
}

// SelectAgent targets an agent by tag (same as the console `target` command).
func (h *guiHost) SelectAgent(tag string) bool {
	return setActiveTarget(tag)
}

// Agents snapshots the live agent registry (a sync.Map) into GUI wire DTOs,
// reusing the same mapper as the agent-table refresh path.
func (h *guiHost) Agents() []gui.Agent {
	var agents []*def.Emp3r0rAgent
	live.AgentList.Range(func(_, value any) bool {
		a, ok := value.(*def.Emp3r0rAgent)
		if ok && a != nil {
			agents = append(agents, a)
		}
		return true
	})
	return guiAgentViews(agents)
}

// GuiMain is the operator console entry for the browser GUI
// (emp3r0r client --gui): preflight checks, then lib/gui takes over and
// presents this operator console in the browser. It blocks until the GUI
// daemon exits.
func GuiMain(opts gui.StartOptions) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("GuiMain panicked: %v", r)
		}
	}()

	// the GUI process is still a full cc operator: keep the same preflight
	// checks the CLI client does
	gui.EnsureStdio() // never let a socket land on fd 0/1/2

	// A GUI daemon from a previous run may still be alive (closing the tab or
	// the terminal never kills it). If so, hand the operator its URL back —
	// same live session, no second daemon, no connection command re-entered.
	if gui.ReattachIfRunning() {
		os.Exit(0)
	}

	if err := live.CopyStubs(); err != nil {
		logging.Fatalf("Failed to copy stubs: %v", err)
	}
	if tools.IsCCRunning() {
		logging.Fatalf("CC is already running")
	}

	GuiMode = true
	defer func() { GuiMode = false }()

	gui.Run(&guiHost{}, opts)
}
