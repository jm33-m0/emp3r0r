package operator

import (
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/spf13/cobra"
)

// CmdLsModules list all available modules
func CmdLsModules(_ *cobra.Command, _ []string) {
	mod_comment_map := make(map[string]string)
	def.ForEachModule(func(mod_name string, mod *def.ModuleConfig) {
		mod_comment_map[mod_name] = mod.Comment
	})
	cli.CliPrettyPrint("Module Name", "Help", &mod_comment_map)
}
