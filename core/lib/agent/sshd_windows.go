package agent

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/gliderlabs/ssh"
)

// SSHD start a ssh server to provide shell access for clients
// the server binds local interface only
func crossPlatformSSHD(shell, port string, args []string) (err error) {
	if strings.HasSuffix(shell, "bash") {
		shell = "cmd.exe"
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

		// console configs
		ptyReq, winCh, isPTY := s.Pty()
		if isPTY {
			log.Printf("Got an SSH PTY request: %s", ptyReq.Term)
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		} else {
			log.Print("Got an SSH request")
		}
		go func() {
			for win := range winCh {
				setWinsize(win.Width, win.Height)
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

func setWinsize(w, h int) {
	// kernel32_dll := windows.NewLazySystemDLL("kernel32.dll")
	// set_console_buffer_size := kernel32_dll.NewProc("SetConsoleScreenBufferSize")
	//
	// // screen buffer size
	// var coord windows.Coord
	// coord.X = int16(w)
	// coord.Y = int16(h)
	//
}
