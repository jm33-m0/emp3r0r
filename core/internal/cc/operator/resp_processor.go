package operator

import (
	"fmt"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

// CommandHandler handles specific command responses from agents
type CommandHandler func(out []byte, target *def.Emp3r0rAgent) string

// CommandHandlers maps command names to their handlers
var CommandHandlers sync.Map // map[string]CommandHandler

func init() {
	CommandHandlers.Store("ps", handlePS)
	CommandHandlers.Store("ls", handleLS)
	CommandHandlers.Store("stat", handleStat)
	CommandHandlers.Store("sysinfo", handleSysInfo)
}

func handleSysInfo(out []byte, target *def.Emp3r0rAgent) string {
	// Call controller for parsing (business logic)
	parsed, err := controllers.ParseSysinfoOutput(out)
	if err != nil {
		logging.Debugf("sysinfo: %v", err)
		logging.Errorf("sysinfo: %v", err)
		return ""
	}

	// UI rendering only
	outTable := cli.BuildTable(parsed.Headers, parsed.Rows)
	cli.AdaptiveTable(outTable)
	return outTable
}

func handlePS(out []byte, target *def.Emp3r0rAgent) string {
	// Call controller for parsing (business logic)
	parsed, err := controllers.ParsePSOutput(out)
	if err != nil {
		logging.Debugf("ps: %v", err)
		logging.Errorf("ps: %v", err)
		return ""
	}

	// UI rendering only
	outTable := cli.BuildTable(parsed.Headers, parsed.Rows)
	cli.AdaptiveTable(outTable)
	return outTable
}

func handleLS(out []byte, target *def.Emp3r0rAgent) string {
	// Call controller for parsing (business logic)
	parsed, err := controllers.ParseLSOutput(out)
	if err != nil {
		logging.Debugf("ls: %v", err)
		logging.Errorf("ls: %v", err)
		return ""
	}

	// UI rendering only
	outTable := cli.BuildTable(parsed.Headers, parsed.Rows)
	cli.AdaptiveTable(outTable)
	return outTable
}

func handleStat(out []byte, target *def.Emp3r0rAgent) string {
	// Call controller for parsing (business logic)
	parsed, err := controllers.ParseStatOutput(out)
	if err != nil {
		logging.Debugf("stat: %v", err)
		logging.Errorf("stat: %v", err)
		return ""
	}

	// UI rendering only
	outTable := cli.BuildTable(parsed.Headers, parsed.Rows)
	cli.AdaptiveTable(outTable)
	return outTable
}

// processAgentData handles data from agent side
// UI layer - calls controller for business logic, renders output
func processAgentData(data *def.MsgTunData) {
	// Call controller for business logic
	resp, err := controllers.ProcessAgentResponse(data)
	if err != nil {
		logging.Errorf("%v", err)
		return
	}

	// Handle different message types (UI rendering)
	switch resp.MessageType {
	case "success":
		logging.Successf("%s", resp.Output)
		select {
		case AgentRefreshCh <- struct{}{}:
		default:
		}
		return
	case "error":
		logging.Errorf("%s", resp.Output)
		select {
		case AgentRefreshCh <- struct{}{}:
		default:
		}
		return
	case "warn":
		logging.Warningf("%s", resp.Output)
		return
	case "info":
		logging.Infof("%s", resp.Output)
		return
	}

	// For command output, check if we should show it
	if !resp.ShouldShow {
		return
	}

	// Handle special command processing
	lookupCmd := strings.TrimPrefix(resp.Command, "!")
	if h, ok := CommandHandlers.Load(lookupCmd); ok {
		handler := h.(CommandHandler)
		resp.Output = handler([]byte(resp.Output), resp.Agent)
	}

	// Sanitize command output before rendering (Response field may contain untrusted output)
	// Agent.Name and Command are already sanitized at storage time
	stripped := sanitize.SanitizeText(resp.Output)
	agentOutput := fmt.Sprintf("\n[%s] %s:\n%s\n",
		color.CyanString("%s - %s", resp.Agent.ShortID, resp.Agent.Name),
		color.HiMagentaString("%s", resp.Command),
		color.HiWhiteString(stripped))

	// Add latency info if available
	if resp.TimeSpent > 0 {
		if !resp.IsBuiltin {
			agentOutput = fmt.Sprintf("%s\n%s", agentOutput,
				color.HiCyanString("Latency: %s\n\n", resp.TimeSpent))
		}
	}

	logging.Infof("%s", logging.Raw(agentOutput))
}
