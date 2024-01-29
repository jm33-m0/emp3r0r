//go:build linux
// +build linux

package cc


import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

const (
	SocketName = "/tmp/emp3r0r.socket"

	// for stupid goconst
	LOG  = "log"
	JSON = "JSON"
	CMD  = "cmd"
)

var APIConn net.Conn

// APIResponse what the frontend sees, in JSON
type APIResponse struct {
	Cmd     string // user cmd
	MsgType string // log/json/cmd, tells frontend where to put it
	MsgData []byte // data payload, can be a JSON string or ordinary string
	Alert   bool   // whether to alert the frontend user
}

func APIMain() {
	log.Printf("%s", color.CyanString("Starting emp3r0r API server"))
	APIListen()
}

// listen on a unix socket
// users can send commands to this socket as if they were
// using a console
func APIListen() {
	// if socket file exists
	if util.IsExist(SocketName) {
		err := os.Remove(SocketName)
		if err != nil {
			CliPrintError("Failed to delete socket: %v", err)
			return
		}
	}

	l, err := net.Listen("unix", SocketName)
	if err != nil {
		CliPrintError("listen error: %v", err)
		return
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			CliPrintError("emp3r0r API: accept error: %v", err)
			return
		}
		APIConn = conn
		IsAPIEnabled = APIConn != nil // update IsAPIEnabled status
		log.Printf("%s: %s", color.BlueString("emp3r0r got an API connection"), conn.RemoteAddr().String())
		processAPIReq(conn)
	}
}

// handle connections to our socket: echo whatever we get
func processAPIReq(c net.Conn) {
	for {
		buf := make([]byte, 512)
		nr, err := c.Read(buf)
		if err != nil {
			return
		}

		data := buf[0:nr]

		// deal with the command
		cmd := string(data)
		cmd = strings.TrimSpace(cmd)
		err = CmdHandler(cmd)
		CliPrintInfo("emp3r0r received %s", strconv.Quote(cmd))
		if err != nil {
			CliPrintError("Command failed: %v", err)
		}
	}
}
