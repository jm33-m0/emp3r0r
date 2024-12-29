//go:build linux
// +build linux

package cc

func moduleBring2CC() {
	addr := Options["addr"].Val

	// start a Shadowsocks TCP tunnel that forwards our local socks5 proxy server to the target's AutoProxy port

	CliPrintInfo("agent %s is connecting to %s to proxy it out to C2", CurrentTarget.Tag, addr)
}
