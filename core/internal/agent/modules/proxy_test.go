package modules

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestSocks5ProxyLifecycle(t *testing.T) {
	// Setup RuntimeConfig
	port := fmt.Sprintf("%d", util.RandInt(50000, 60000))
	common.RuntimeConfig = &def.Config{
		AgentSocksServerPort:      port,
		ShadowsocksLocalSocksPort: "user",
		Password:                  "password",
		AgentSocksTimeout:         10,
	}

	addr := "127.0.0.1:" + port

	// 1. Start Proxy
	t.Logf("Starting Socks5Proxy on %s", addr)
	err := Socks5Proxy("on", addr)
	if err != nil {
		t.Fatalf("Failed to start Socks5Proxy: %v", err)
	}

	// Verify it's running
	// Allow some time for the goroutine to start
	time.Sleep(200 * time.Millisecond)

	if def.ProxyServer == nil {
		t.Fatal("def.ProxyServer is nil after start")
	}

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial proxy address %s: %v", addr, err)
	}
	conn.Close()
	t.Log("Successfully connected to proxy")

	// 2. Stop Proxy
	t.Logf("Stopping Socks5Proxy on %s", addr)
	err = Socks5Proxy("off", addr)
	if err != nil {
		t.Fatalf("Failed to stop Socks5Proxy: %v", err)
	}

	// Verify it's stopped but Server is NOT nil (Prevent Root Cause)
	if def.ProxyServer == nil {
		t.Fatal("def.ProxyServer should NOT be nil after stop (Root Cause Fix)")
	}

	// Verify listening port is closed
	conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("Proxy address should be unreachable after stop")
	}
	t.Log("Successfully verified proxy is stopped")

	// 3. Restart Proxy
	t.Logf("Restarting Socks5Proxy on %s", addr)
	err = Socks5Proxy("on", addr)
	if err != nil {
		t.Fatalf("Failed to restart Socks5Proxy: %v", err)
	}

	// Verify it's running again
	time.Sleep(200 * time.Millisecond)

	if def.ProxyServer == nil {
		t.Fatal("def.ProxyServer is nil after restart")
	}

	conn, err = net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial proxy address %s after restart: %v", addr, err)
	}
	conn.Close()
	t.Log("Successfully connected to proxy after restart")
}
