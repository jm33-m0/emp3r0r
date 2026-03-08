package operator

import (
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/spf13/cobra"
)

// CmdLsModules list all available modules
func CmdLsModules(_ *cobra.Command, _ []string) {
	mod_comment_map := make(map[string]string)
	def.Modules.Range(func(key, value any) bool {
		mod_name := key.(string)
		mod := value.(*def.ModuleConfig)
		mod_comment_map[mod_name] = mod.Comment
		return true
	})
	cli.CliPrettyPrint("Module Name", "Help", &mod_comment_map)
}
