package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/arc/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/relay"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func ServerMain(wg_port int, hosts string, numOperators int) {
	// start all services
	go KCPC2ListenAndServe()
	go tarConfig(hosts)
	wg(wg_port, numOperators)
	time.Sleep(3 * time.Second)
	go StartC2AgentTLSServer()

	// Highlight the key ports for easy identification
	logging.Successf("\n🎯 ════════════════════ C2 SERVER PORTS ═══════════════════════════")
	logging.Successf("   📡 C2 Agent Port (TLS):  %s", live.RuntimeConfig.CCPort)
	logging.Successf("   🔄 KCP C2 Port (UDP):    %s", live.RuntimeConfig.KCPServerPort)
	logging.Successf("   🌐 Operator Port (mTLS): %d", wg_port+1)
	logging.Successf("   🔧 WireGuard Port:       %d", wg_port)
	logging.Successf("══════════════════════════════════════════════════════════════════\n")

	StartOperatorMTLSServer(wg_port + 1)
}

type OperatorConfig struct {
	PrivateKey string
	PublicKey  string
	IP         string
}

type SavedWgConfig struct {
	ServerIP         string           `json:"server_ip"`
	ServerPrivateKey string           `json:"server_private_key"`
	Subnet           string           `json:"subnet"`
	Operators        []OperatorConfig `json:"operators"`
}

func wg(wg_port int, numOperators int) {
	var (
		server_privkey string
		server_pubkey  string
		subnet         string
		operators      []OperatorConfig
		err            error
	)

	configFile := filepath.Join(live.EmpWorkSpace, "wg_config.json")
	if util.IsFileExist(configFile) {
		logging.Infof("Loading WireGuard config from %s", configFile)
		data, err := os.ReadFile(configFile)
		if err != nil {
			logging.Fatalf("Failed to read WireGuard config: %v", err)
		}
		var config SavedWgConfig
		err = json.Unmarshal(data, &config)
		if err != nil {
			logging.Fatalf("Failed to parse WireGuard config: %v", err)
		}
		netutil.WgServerIP = config.ServerIP
		server_privkey = config.ServerPrivateKey
		subnet = config.Subnet
		operators = config.Operators

		server_pubkey, err = netutil.PublicKeyFromPrivate(server_privkey)
		if err != nil {
			logging.Fatalf("Failed to generate server public key: %v", err)
		}
	} else {
		server_privkey, err = netutil.GeneratePrivateKey()
		if err != nil {
			logging.Fatalf("Failed to generate server private key: %v", err)
		}
		server_pubkey, err = netutil.PublicKeyFromPrivate(server_privkey)
		if err != nil {
			logging.Fatalf("Failed to generate server public key: %v", err)
		}

		// network address
		subnet = netutil.GenerateRandomPrivateSubnet24()
		netutil.WgServerIP, _ = netutil.GenerateRandomIPInSubnet24(subnet)

		// Generate operator configs
		operators = make([]OperatorConfig, numOperators)

		for i := range numOperators {
			operator_privkey, err := netutil.GeneratePrivateKey()
			if err != nil {
				logging.Fatalf("Failed to generate operator private key: %v", err)
			}
			operator_pubkey, err := netutil.PublicKeyFromPrivate(operator_privkey)
			if err != nil {
				logging.Fatalf("Failed to generate operator public key: %v", err)
			}
			operatorIP, _ := netutil.GenerateRandomIPInSubnet24(subnet)

			// Save for the first operator (backward compatibility)
			if i == 0 {
				netutil.WgOperatorIP = operatorIP
			}

			operators[i] = OperatorConfig{
				PrivateKey: operator_privkey,
				PublicKey:  operator_pubkey,
				IP:         operatorIP,
			}
		}

		// Save config
		config := SavedWgConfig{
			ServerIP:         netutil.WgServerIP,
			ServerPrivateKey: server_privkey,
			Subnet:           subnet,
			Operators:        operators,
		}
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			logging.Fatalf("Failed to marshal WireGuard config: %v", err)
		}
		err = os.WriteFile(configFile, data, 0600)
		if err != nil {
			logging.Fatalf("Failed to save WireGuard config: %v", err)
		}
	}

	peers := make([]netutil.PeerConfig, len(operators))
	for i, op := range operators {
		peers[i] = netutil.PeerConfig{
			PublicKey:  op.PublicKey,
			AllowedIPs: op.IP + "/32",
		}
		// Save for the first operator (backward compatibility)
		if i == 0 {
			netutil.WgOperatorIP = op.IP
		}
	}

	wgConfig := netutil.WireGuardConfig{
		IPAddress:     netutil.WgServerIP + "/24",
		InterfaceName: "emp_server",
		ListenPort:    wg_port,
		PrivateKey:    server_privkey,
		Peers:         peers,
	}
	go func() {
		netutil.WgServer, err = netutil.WireGuardMain(wgConfig)
		if err != nil {
			logging.Fatalf("Failed to start WireGuard server: %v", err)
		}
	}()

	// Create server config table
	headers := []string{"Parameter", "Value"}
	rows := [][]string{
		{"C2 Server IP (WG)", netutil.WgServerIP},
		{"C2 Server Port", strconv.Itoa(wg_port)},
		{"C2 Public Key", server_pubkey},
	}

	// Build the server table
	serverTableStr := cli.BuildTable(headers, rows)

	// Create operator config table
	opHeaders := []string{"Operator ID", "IP Address", "Private Key", "Public Key"}
	opRows := make([][]string, numOperators)

	for i, op := range operators {
		opRows[i] = []string{
			strconv.Itoa(i + 1),
			op.IP,
			op.PrivateKey,
			op.PublicKey,
		}
	}

	// Build the operators table
	operatorsTableStr := cli.BuildTable(opHeaders, opRows)

	// Print the tables with titles
	logging.Successf("\n══════════════════ WireGuard Server Configuration ════════════════════════════\n\n%s\n", serverTableStr)
	logging.Successf("\n══════════════════ WireGuard Operator Configurations ════════════════════════════\n\n%s\n", operatorsTableStr)

	// Generate and display client connection commands
	generateConnectionCommands(wg_port, server_pubkey, operators)
}

func tarConfig(hosts string) {
	err := config.GenC2Certs(hosts)
	if err != nil {
		logging.Fatalf("Failed to generate C2 certs: %v", err)
	}
	err = os.Chdir(live.EmpWorkSpace)
	if err != nil {
		logging.Fatalf("Failed to change directory: %v", err)
	}
	// tar all config files
	filter := func(path string) bool {
		return strings.HasSuffix(path, ".log") || strings.HasPrefix(path, "stub") || strings.HasSuffix(path, ".history")
	}
	os.Chdir(filepath.Dir(live.EmpWorkSpace))
	defer os.Chdir(live.EmpWorkSpace)

	err = arc.ArchiveWithFilter(filepath.Base(live.EmpWorkSpace), live.EmpConfigTar, arc.CompressionMap["xz"], arc.ArchivalMap["tar"], filter)
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
	headers := []string{"Operator ID", "Connection Command"}
	rows := make([][]string, len(operators))

	for i, op := range operators {
		// Generate command for each operator
		cmd := generateClientCommand(wg_port, server_pubkey, op)
		rows[i] = []string{
			strconv.Itoa(i + 1),
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
		localCmd := fmt.Sprintf("emp3r0r client --c2-host 127.0.0.1 --c2-port %d --server-wg-key '%s' --server-wg-ip '%s' --operator-wg-ip '%s'",
			wg_port, server_pubkey, netutil.WgServerIP, op.IP)
		remoteCmd := fmt.Sprintf("emp3r0r client --c2-host <YOUR_PUBLIC_IP> --c2-port %d --server-wg-key '%s' --server-wg-ip '%s' --operator-wg-ip '%s'",
			wg_port, server_pubkey, netutil.WgServerIP, op.IP)

		logging.Successf("\n💡 Example Commands (for Operator 1):")
		logging.Successf("   Local:  %s", localCmd)
		logging.Successf("   Remote: %s", remoteCmd)
	}
}

// generateClientCommand generates a client connection command for a specific operator
func generateClientCommand(wg_port int, server_pubkey string, op OperatorConfig) string {
	return fmt.Sprintf("emp3r0r client --c2-port %d --server-wg-key '%s' --server-wg-ip '%s' --operator-wg-ip '%s' --c2-host <C2_PUBLIC_IP>",
		wg_port, server_pubkey, netutil.WgServerIP, op.IP)
}
