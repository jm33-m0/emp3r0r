package operator

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// Socks5Pivot describes a running C2-side SOCKS5 listener.
type Socks5Pivot struct {
	Port    int    `json:"port"`
	Bind    string `json:"bind"`
	Agent   string `json:"agent"`
	Warning string `json:"warning,omitempty"`
}

// StartSocks5Pivot starts a C2-side SOCKS5 listener that relays through the
// selected agent. A zero port means the default 1080.
func StartSocks5Pivot(port int, bind string) (Socks5Pivot, error) {
	if port == 0 {
		port = 1080
	}
	if port < 0 || port > 65535 {
		return Socks5Pivot{}, fmt.Errorf("port must be between 1 and 65535")
	}
	agent := agents.MustGetActiveAgent()
	if agent == nil {
		return Socks5Pivot{}, fmt.Errorf("no active target; call list_agents and select_agent")
	}
	if err := modules.HostSocks5Relay(agent); err != nil {
		return Socks5Pivot{}, fmt.Errorf("host SOCKS5 relay: %w", err)
	}
	if err := client.StartSocks5Proxy(agent.Tag, port, bind); err != nil {
		return Socks5Pivot{}, fmt.Errorf("start SOCKS5 pivot: %w", err)
	}
	pivot := Socks5Pivot{Port: port, Bind: socks5ProxyHost(), Agent: agent.Tag}
	if bind != "" && bind != "0.0.0.0" {
		pivot.Bind = bind
	}
	if modules.CanRunSocks5BOF(agent) {
		pivot.Warning = fmt.Sprintf("this C agent polls every %ds with a %ds window while the pivot runs and stays unmasked during relays; its profile is restored on stop", def.Socks5PivotPollInterval, def.Socks5PivotPollWindow)
	}
	return pivot, nil
}

// StopSocks5Pivot stops one C2-side SOCKS5 listener.
func StopSocks5Pivot(port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return client.StopSocks5Proxy(port)
}

// Socks5Pivots lists the running C2-side SOCKS5 listeners.
func Socks5Pivots() ([]Socks5Pivot, error) {
	proxies, err := client.ListSocks5Proxies()
	if err != nil {
		return nil, err
	}
	out := make([]Socks5Pivot, 0, len(proxies))
	for _, proxy := range proxies {
		bind := proxy.BindAddr
		if bind == "" || bind == "0.0.0.0" {
			bind = socks5ProxyHost()
		}
		out = append(out, Socks5Pivot{
			Port:  proxy.Port,
			Bind:  bind,
			Agent: proxy.AgentTag,
		})
	}
	return out, nil
}

// ForgetAgent removes one agent record from the C2 database.
func ForgetAgent(identifier string) (string, error) {
	uuid := strings.TrimSpace(identifier)
	if uuid == "" {
		return "", fmt.Errorf("agent is required")
	}
	if unquoted, err := strconv.Unquote(uuid); err == nil {
		uuid = unquoted
	}
	if byTag := agents.GetAgentByTag(uuid); byTag != nil && byTag.UUID != "" {
		uuid = byTag.UUID
	}
	body, err := client.SendCBORRequest(transport.OperatorForgetAgent, def.Operation{
		AgentTag: uuid,
		Action:   "forget_agent",
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}
