package operator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/carapace-sh/carapace"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

func addModuleCommands(rootCmd *cobra.Command) {
	mods := make([]*def.ModuleConfig, 0)
	def.Modules.Range(func(_, value any) bool {
		if mod, ok := value.(*def.ModuleConfig); ok && mod != nil {
			mods = append(mods, mod)
		}
		return true
	})
	sort.Slice(mods, func(i, j int) bool {
		return mods[i].Name < mods[j].Name
	})

	for _, mod := range mods {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Errorf("Failed to register command for module %s: %v. Rolling back registration.", mod.Name, r)
					def.Modules.Delete(mod.Name)
				}
			}()

			mod := mod
			flagActions := carapace.ActionMap{}
			cmd := &cobra.Command{
				Use:     mod.Name,
				GroupID: "module",
				Short:   mod.Comment,
				Long:    fmt.Sprintf("Run module %s", mod.Name),
				Args:    cobra.NoArgs,
				Run: func(cmd *cobra.Command, _ []string) {
					runModuleByName(cmd, mod.Name)
				},
			}
			cmd.Flags().Bool("force", false, "Force execution without confirmation")

			keys := make([]string, 0, len(mod.Options))
			for key := range mod.Options {
				keys = append(keys, key)
			}
			sort.Strings(keys)

			for _, key := range keys {
				opt := mod.Options[key]
				if opt == nil {
					continue
				}
				help := strings.TrimSpace(opt.Desc)
				if len(opt.Vals) > 0 {
					help = fmt.Sprintf("%s (choices: %s)", help, strings.Join(opt.Vals, ", "))
				}
				if opt.Required {
					help = strings.TrimSpace(help + " [required]")
				}
				cmd.Flags().String(opt.Name, opt.Val, help)
				if len(opt.Vals) > 0 {
					vals := append([]string(nil), opt.Vals...)
					flagActions[opt.Name] = carapace.ActionValues(vals...)
				}
			}
			if len(flagActions) > 0 {
				carapace.Gen(cmd).FlagCompletion(flagActions)
			}

			rootCmd.AddCommand(cmd)
		}()
	}
}

func runModuleByName(cmd *cobra.Command, modName string) {
	modules.SetActiveModule(modName)
	if live.ActiveModule == nil {
		logging.Errorf("No such module: %s", modName)
		return
	}
	mod := live.ActiveModule

	if agents.MustGetActiveAgent() == nil && !mod.IsLocal {
		logging.Errorf("No active agent")
		return
	}
	force, _ := cmd.Flags().GetBool("force")
	if !mod.Fileless && !mod.IsLocal && !force {
		logging.Warningf("Module %s is not fileless and may drop files or modify system configuration.", mod.Name)
		logging.Infof("Run with: %s --force ...", mod.Name)
		return
	}

	runtimeFlags := make(map[string]string)
	for optName, opt := range mod.Options {
		var val string
		var err error
		if cmd.Flags().Lookup(optName) != nil {
			val, err = cmd.Flags().GetString(optName)
			if err != nil {
				logging.Errorf("module %s: read flag %s: %v", mod.Name, optName, err)
				continue
			}
		} else {
			val = opt.Val
		}
		live.SetOption(optName, val)
		runtimeFlags[optName] = val
	}

	ctx := &c2context.C2Context{
		Target:    agents.MustGetActiveAgent(),
		Flags:     runtimeFlags,
		OpSession: client.SessionID,
		OnUIReady: func(data any) error {
			connStr, ok := data.(string)
			if !ok {
				return fmt.Errorf("expected string, got %T", data)
			}
			logging.Successf("Shell ready! Opening tmux...")
			windowName := "shell"
			if ctxTarget := agents.MustGetActiveAgent(); ctxTarget != nil {
				windowName = fmt.Sprintf("shell-%s", ctxTarget.ShortID)
			}
			return cli.TmuxNewWindow(windowName, connStr)
		},
	}
	modules.ModuleRun(ctx)
	if mod.IsLocal {
		logging.Infof("Module %s is local-only; execution remains on C2", mod.Name)
	}
}

func cmdListModules(_ *cobra.Command, _ []string) {
	// table output
	rows := [][]string{}
	def.Modules.Range(func(key, value any) bool {
		mod := value.(*def.ModuleConfig)
		rows = append(rows, []string{mod.Name, mod.Comment})
		return true
	})
	tableStr := cli.BuildTable([]string{"Module", "Description"}, rows)
	cli.AdaptiveTable(tableStr)
	logging.Infof("\n%s", tableStr)
}

func cmdSearchModule(cmd *cobra.Command, args []string) {
	results := modules.ModuleSearch(args[0])
	row := [][]string{}
	for _, mod := range results {
		row = append(row, []string{mod.Name, mod.Comment})
	}
	tableStr := cli.BuildTable([]string{"Module", "Description"}, row)
	cli.AdaptiveTable(tableStr)
	logging.Infof("\n%s", tableStr)
}
