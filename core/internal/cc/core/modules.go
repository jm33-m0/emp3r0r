package core

import (
	"github.com/jm33-m0/emp3r0r/core/internal/cli"
	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/spf13/cobra"
)

// ListModules list all available modules
func ListModules(_ *cobra.Command, _ []string) {
	mod_comment_map := make(map[string]string)
	for mod_name, mod := range emp3r0r_def.Modules {
		mod_comment_map[mod_name] = mod.Comment
	}
	cli.CliPrettyPrint("Module Name", "Help", &mod_comment_map)
}
