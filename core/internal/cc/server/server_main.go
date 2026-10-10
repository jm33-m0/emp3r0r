package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/relay"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func ServerMain(wg_port int, hosts string, numOperators int, operatorsSet bool, addOperators int) {
	// Publish the configured idle timeout to the atomic mirror that agent
	// tunnels and agent-lock expiry read, so config updates and readers never
	// race on the shared RuntimeConfig field.
	setOperatorIdleTimeout(live.RuntimeConfig.OperatorIdleTimeout)

	// Initialize agent database for persistent tracking
	dbPath := filepath.Join(live.EmpWorkSpace, "agents.db")
	if err := agents.InitAgentDB(dbPath); err != nil {
		logging.Errorf("Failed to initialize agent database: %v", err)
		return
	}

	// Register log handler to broadcast important logs to operators
	logging.SetBroadcastHandler(func(level, msg string) {
		_ = operatorBroadcastPrintf(level, "%s", msg)
	})

	if active, purged, err := agents.ReconcileSessionsOnStartup(); err != nil {
		logging.Errorf("Failed to reconcile persisted sessions: %v", err)
		return
	} else {
		logging.Infof("Session restore: active=%d purged_stale=%d", active, purged)
	}
	defer agents.CloseAgentDB()

	// start all services
	network.EmpKCPCtx, network.EmpKCPCancel = context.WithCancel(context.Background())
	go KCPC2ListenAndServe(network.EmpKCPCtx, network.EmpKCPCancel)
	// Bring the userspace WireGuard stack up first so the operator-facing
	// listeners can be bound on it.
	wg(wg_port, numOperators, addOperators, operatorsSet)
	go tarConfig(hosts)
	time.Sleep(3 * time.Second)
	go StartC2AgentTLSServer()
	go StartC2HTTPServer()

	// Highlight the key ports for easy identification
	logging.Successf("\n🎯 ════════════════════ C2 SERVER PORTS ═══════════════════════════")
	logging.Successf("   📡 C2 Agent Port (TLS):  %s", live.RuntimeConfig.CCH2Port)
	logging.Successf("   📡 C2 Agent Port (HTTP): %s", live.RuntimeConfig.CCHTTPPort)
	logging.Successf("   🔄 KCP C2 Port (UDP):    %s", live.RuntimeConfig.P2PRelayPort)
	logging.Successf("   🌐 Operator Port (mTLS): %d", wg_port+1)
	logging.Successf("   🔧 WireGuard Port:       %d", wg_port)
	logging.Successf("══════════════════════════════════════════════════════════════════\n")

	StartOperatorMTLSServer(wg_port + 1)
}

type SavedWgConfig struct {
	ServerIP         string           `json:"server_ip"`
	ServerPrivateKey string           `json:"server_private_key"`
	Subnet           string           `json:"subnet"`
	Operators        []OperatorConfig `json:"operators"`
}

// generateOperators creates count new operators on subnet, numbering their
// display names from startIndex so appended operators keep a stable name.
func generateOperators(subnet string, startIndex, count int) ([]OperatorConfig, error) {
	operators := make([]OperatorConfig, count)
	for i := range count {
		priv, err := wireguard.GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("generate operator private key: %w", err)
		}
		pub, err := wireguard.PublicKeyFromPrivate(priv)
		if err != nil {
			return nil, fmt.Errorf("derive operator public key: %w", err)
		}
		ip, err := netutil.GenerateRandomIPInSubnet24(subnet)
		if err != nil {
			return nil, fmt.Errorf("allocate operator IP: %w", err)
		}
		operators[i] = OperatorConfig{
			Name:       fmt.Sprintf("operator-%d", startIndex+i+1),
			PrivateKey: priv,
			PublicKey:  pub,
			IP:         ip,
		}
	}
	return operators, nil
}

// writeWgConfig persists the WireGuard config with owner-only permissions.
func writeWgConfig(path string, config SavedWgConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal wireguard config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("save wireguard config: %w", err)
	}
	return nil
}

// loadOrProvisionWg returns the WireGuard config, creating it on the first run
// and preserving existing operator identities on every later run. Existing
// identities are never regenerated: --operators is refused once the file exists
// (remove it manually to start over), and --add-operator appends new operators.
func loadOrProvisionWg(configFile string, numOperators, addOperators int, operatorsSet bool) (SavedWgConfig, error) {
	if !util.IsFileExist(configFile) {
		count := max(numOperators, 1)
		if addOperators > 0 {
			count = addOperators
		}
		serverPriv, err := wireguard.GeneratePrivateKey()
		if err != nil {
			return SavedWgConfig{}, fmt.Errorf("generate server private key: %w", err)
		}
		subnet := netutil.GenerateRandomPrivateSubnet24()
		serverIP, err := netutil.GenerateRandomIPInSubnet24(subnet)
		if err != nil {
			return SavedWgConfig{}, fmt.Errorf("allocate server IP: %w", err)
		}
		operators, err := generateOperators(subnet, 0, count)
		if err != nil {
			return SavedWgConfig{}, err
		}
		config := SavedWgConfig{
			ServerIP:         serverIP,
			ServerPrivateKey: serverPriv,
			Subnet:           subnet,
			Operators:        operators,
		}
		if err := writeWgConfig(configFile, config); err != nil {
			return SavedWgConfig{}, err
		}
		logging.Successf("Created WireGuard config with %d operator(s): %s", count, configFile)
		return config, nil
	}

	logging.Infof("Loading WireGuard config from %s", configFile)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return SavedWgConfig{}, fmt.Errorf("read wireguard config: %w", err)
	}
	var config SavedWgConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return SavedWgConfig{}, fmt.Errorf("parse wireguard config: %w", err)
	}
	if config.ServerIP == "" || config.ServerPrivateKey == "" || len(config.Operators) == 0 {
		return SavedWgConfig{}, fmt.Errorf("wireguard config %s is incomplete; remove it and restart to regenerate", configFile)
	}

	switch {
	case addOperators > 0:
		added, err := generateOperators(config.Subnet, len(config.Operators), addOperators)
		if err != nil {
			return SavedWgConfig{}, fmt.Errorf("add operators: %w", err)
		}
		config.Operators = append(config.Operators, added...)
		if err := writeWgConfig(configFile, config); err != nil {
			return SavedWgConfig{}, err
		}
		logging.Successf("Added %d operator(s); %d total", addOperators, len(config.Operators))
	case operatorsSet:
		return SavedWgConfig{}, fmt.Errorf(
			"wireguard config %s already holds %d operator(s); refusing --operators. "+
				"Remove the file to regenerate from scratch, or use --add-operator to add more",
			configFile, len(config.Operators),
		)
	default:
		logging.Infof("Keeping %d existing operator config(s)", len(config.Operators))
	}
	return config, nil
}

func wg(wg_port, numOperators, addOperators int, operatorsSet bool) {
	configFile := filepath.Join(live.EmpWorkSpace, "wg_config.json")
	config, err := loadOrProvisionWg(configFile, numOperators, addOperators, operatorsSet)
	if err != nil {
		logging.Fatalf("%v", err)
	}

	server_pubkey, err := wireguard.PublicKeyFromPrivate(config.ServerPrivateKey)
	if err != nil {
		logging.Fatalf("Failed to derive server public key: %v", err)
	}
	wireguard.WgServerIP = config.ServerIP
	operators := config.Operators

	peers := make([]wireguard.PeerConfig, len(operators))
	for i, op := range operators {
		peers[i] = wireguard.PeerConfig{
			PublicKey:  op.PublicKey,
			AllowedIPs: op.IP + "/32",
		}
		// Publish the first operator's IP as the single-operator default used by
		// callers that still assume one operator (C2 cert SANs and the
		// standalone-operator tunnel path). Every operator still gets its own
		// peer entry below.
		if i == 0 {
			wireguard.WgOperatorIP = op.IP
		}
	}

	// Publish the provisioned identities so the operator mTLS and HTTP handlers
	// can map a peer's WireGuard IP to its stable operator identity.
	registerOperators(operators)

	wgConfig := wireguard.WireGuardConfig{
		IPAddress:     wireguard.WgServerIP + "/24",
		InterfaceName: "emp_server",
		ListenPort:    wg_port,
		PrivateKey:    config.ServerPrivateKey,
		Peers:         peers,
	}
	wgServer, err := wireguard.CreateWireGuardDevice(wgConfig)
	if err != nil {
		logging.Fatalf("Failed to start WireGuard server: %v", err)
	}
	wireguard.WgServer = wgServer
	go wgServer.Wait()

	// Create server config table
	headers := []string{"Parameter", "Value"}
	rows := [][]string{
		{"C2 Server IP (WG)", wireguard.WgServerIP},
		{"C2 Server Port", strconv.Itoa(wg_port)},
		{"C2 Public Key", server_pubkey},
	}

	// Build the server table
	serverTableStr := cli.BuildTable(headers, rows)

	// Create operator config table
	opHeaders := []string{"Operator", "IP Address", "Private Key", "Public Key"}
	opRows := make([][]string, len(operators))

	for i, op := range operators {
		opRows[i] = []string{
			op.Name,
			op.IP,
			op.PrivateKey,
			op.PublicKey,
		}
	}

	// Build the operators table
	operatorsTableStr := cli.BuildTable(opHeaders, opRows)

	// Print the tables with titles
	logging.Successf("\n══════════════════ WireGuard Server Configuration ════════════════════════════\n\n%s\n", serverTableStr)
	logging.Successf("\n══════════════════ Provisioned Access Keys (Redundancy) ════════════════════════════\n\n%s\n", operatorsTableStr)

	// Generate and display client connection commands
	generateConnectionCommands(wg_port, server_pubkey, operators)

	logging.Warningf("WireGuard gives every operator IP-level access to the C2's tunnel subnet.")
	logging.Warningf("Firewall the WireGuard UDP port (%d) and the operator mTLS port (%d) so only"+
		" intended operators can reach them, and never expose the WG subnet to an untrusted network.",
		wg_port, wg_port+1)
}

func tarConfig(hosts string) {
	err := config.GenC2Certs(hosts)
	if err != nil {
		logging.Fatalf("Failed to generate C2 certs: %v", err)
	}
	// create temp dir
	tempDir, err := os.MkdirTemp("", "emp3r0r_config_")
	if err != nil {
		logging.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// create .emp3r0r in temp dir
	tempEmpDir := filepath.Join(tempDir, filepath.Base(live.EmpWorkSpace))
	err = os.MkdirAll(tempEmpDir, 0o700)
	if err != nil {
		logging.Fatalf("Failed to create temp .emp3r0r dir: %v", err)
	}

	// copy necessary files to temp dir
	//
	// Only what an operator needs: the operator CA (to verify the C2's server
	// certificate), the shared operator client cert/key, and the runtime
	// config. The agent CA/server keys and the full wg_config.json (which holds
	// every operator's WireGuard private key) must never leave the C2.
	filesToCopy := []string{
		"emp3r0r.json",
		filepath.Base(transport.OperatorCaCrtFile),
		filepath.Base(transport.OperatorClientCrtFile),
		filepath.Base(transport.OperatorClientKeyFile),
	}

	for _, file := range filesToCopy {
		src := filepath.Join(live.EmpWorkSpace, file)
		if !util.IsFileExist(src) {
			continue
		}
		copyErr := util.Copy(src, tempEmpDir) // util.Copy handles dir dst
		if copyErr != nil {
			logging.Warningf("Failed to copy %s to temp dir: %v", src, copyErr)
		}
	}

	// tar the temp dir
	cwd, err := os.Getwd()
	if err != nil {
		logging.Warningf("Failed to get current directory: %v", err)
	}
	err = os.Chdir(tempDir)
	if err != nil {
		logging.Fatalf("Failed to change directory to temp dir: %v", err)
	}
	defer os.Chdir(cwd)

	err = util.TarArchive(filepath.Base(live.EmpWorkSpace), live.EmpConfigTar)
	if err != nil {
		logging.Errorf("Failed to tar config files: %v", err)
	}
	err = relay.WgFileServer(live.EmpConfigTar)
	if err != nil {
		logging.Errorf("Failed to start file server to serve config tarball: %v", err)
	}
}

// generateConnectionCommands generates and displays client connection commands
func generateConnectionCommands(wg_port int, server_pubkey string, operators []OperatorConfig) {
	headers := []string{"Operator", "Connection Command"}
	rows := make([][]string, len(operators))

	for i, op := range operators {
		// Generate command for each operator
		cmd := generateClientCommand(wg_port, server_pubkey, op)
		rows[i] = []string{
			op.Name,
			cmd,
		}
	}

	// Build the commands table
	commandsTableStr := cli.BuildTable(headers, rows)

	// Print the commands table
	logging.Successf("\n══════════════════ Client Connection Commands ════════════════════════════\n\n%s\n", commandsTableStr)
	logging.Successf("📝 Usage Instructions:")
	logging.Successf("   • Replace '<C2_PUBLIC_IP>' with the actual public IP address of this C2 server")
	logging.Successf("   • For LOCAL connections, use: 127.0.0.1")
	logging.Successf("   • Each operator needs their corresponding private key from the table above")

	// Generate example commands for local and remote usage
	if len(operators) > 0 {
		op := operators[0]
		localCmd := fmt.Sprintf("emp3r0r client --c2-host 127.0.0.1 --operator-port %d --server-wg-key '%s' --server-wg-ip '%s' --operator-wg-ip '%s' --operator-wg-key '%s'",
			wg_port, server_pubkey, wireguard.WgServerIP, op.IP, op.PrivateKey)
		remoteCmd := fmt.Sprintf("emp3r0r client --operator-port %d --server-wg-key '%s' --server-wg-ip '%s' --operator-wg-ip '%s' --operator-wg-key '%s' --c2-host <YOUR_PUBLIC_IP>",
			wg_port, server_pubkey, wireguard.WgServerIP, op.IP, op.PrivateKey)

		logging.Successf("\n💡 Example Commands (for Operator 1):")
		logging.Successf("   Local:  %s", localCmd)
		logging.Successf("   Remote: %s", remoteCmd)
	}
}

// generateClientCommand generates a client connection command for a specific operator
func generateClientCommand(wg_port int, server_pubkey string, op OperatorConfig) string {
	return fmt.Sprintf("emp3r0r client --operator-port %d --server-wg-key '%s' --server-wg-ip '%s' --operator-wg-ip '%s' --operator-wg-key '%s' --c2-host <C2_PUBLIC_IP>",
		wg_port, server_pubkey, wireguard.WgServerIP, op.IP, op.PrivateKey)
}
