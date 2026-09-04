package tun2socks

import (
	"context"
	"io"
	"net"
	"net/netip"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// pivotHandler implements tun.Handler: sing-tun hands every proxied TCP
// connection here, and we re-open the same destination through the C2 SOCKS5
// pivot (the same path a `curl -x socks5h://…` takes), then relay. UDP is not
// proxied (the pivot is CONNECT-only), so UDP flows are closed immediately.
type pivotHandler struct {
	socks *socks.Client
	tag   string
}

func newPivotHandler(socksAddr, tag string) *pivotHandler {
	return &pivotHandler{
		socks: socks.NewClient(N.SystemDialer, M.ParseSocksaddr(socksAddr), socks.Version5, "", ""),
		tag:   tag,
	}
}

// JudgeFlow accepts everything; destination policy is left to sing-tun's
// route table (auto-route + excludes).
func (h *pivotHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) tun.FlowVerdict {
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

// NewDNSPacket is unused: DNS hijacking is disabled (DNSMode disabled).
func (h *pivotHandler) NewDNSPacket([]byte, M.Socksaddr, M.Socksaddr, N.PacketWriter) {}

// NewConnectionEx is called for each proxied TCP connection (net.Conn is the
// gVisor-terminated side facing the operator app).
func (h *pivotHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _ M.Socksaddr, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	go h.relayTCP(ctx, conn, destination)
}

func (h *pivotHandler) relayTCP(ctx context.Context, conn net.Conn, destination M.Socksaddr) {
	defer conn.Close()

	remote, err := h.socks.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		logging.Infof("tun2socks[%s]: SOCKS5 dial %s failed: %v", h.tag, destination, err)
		return
	}
	defer remote.Close()

	logging.Debugf("tun2socks[%s]: proxying %s", h.tag, destination)
	relayDuplex(conn, remote)
}

// NewPacketConnectionEx drops UDP flows: the SOCKS5 pivot only supports
// CONNECT (TCP) for now. The NAT session must be closed here — the caller
// does NOT close it when the handler returns, so leaving it open would keep a
// NAT entry (and its packet channel) alive until the UDP timeout.
func (h *pivotHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	logging.Debugf("tun2socks[%s]: dropping UDP flow (SOCKS5 pivot is CONNECT-only)", h.tag)
	_ = conn.Close()
}

// relayDuplex pipes bytes both ways until one side finishes, then closes both
// so the other direction unblocks and nothing lingers.
func relayDuplex(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}
