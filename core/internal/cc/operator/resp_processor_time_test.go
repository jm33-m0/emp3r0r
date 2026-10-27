package operator

import (
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestCommandReportsTime(t *testing.T) {
	for _, cmd := range []string{"ls", "!custom_module", def.C2CmdListener, def.C2CmdStealToken, def.C2CmdProxyStart} {
		if !commandReportsTime(cmd) {
			t.Errorf("commandReportsTime(%q) = false, want true", cmd)
		}
	}
	for _, cmd := range []string{def.C2CmdListDir, def.C2CmdStat} {
		if commandReportsTime(cmd) {
			t.Errorf("commandReportsTime(%q) = true, want false", cmd)
		}
	}
}
