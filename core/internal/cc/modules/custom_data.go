package modules

import (
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// GetModuleDetails returns module metadata
func GetModuleDetails(modName string) *def.ModuleInfo {
	config, exists := def.Modules[modName]
	if !exists {
		return nil
	}

	return &def.ModuleInfo{
		Name:     config.Name,
		Exec:     config.AgentConfig.Exec,
		Platform: config.Platform,
		Author:   config.Author,
		Date:     config.Date,
		Comment:  config.Comment,
	}
}
