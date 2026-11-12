package mcp

import (
	"context"
	"os"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/operator"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// C2Executor dispatches through the same client functions the console uses.
// The C2 still checks operator identity, ownership, and locks.
type C2Executor struct{}

// RunModule dispatches one payload module and returns its job ID.
func (C2Executor) RunModule(_ context.Context, target *def.Emp3r0rAgent, module string, flags map[string]string) (string, error) {
	return modules.DispatchModule(target, module, flags)
}

// BuildLocalModule builds a C2-local module and returns its build log. Local
// modules do not produce an agent job.
func (C2Executor) BuildLocalModule(_ context.Context, module string, flags map[string]string) (string, error) {
	return modules.BuildLocalModule(module, flags)
}

// RunBuiltin sends one built-in agent command line.
func (C2Executor) RunBuiltin(_ context.Context, target *def.Emp3r0rAgent, command string) (string, error) {
	return controllers.ExecuteCommandWithJob(command, "", target.Tag)
}

// UploadFile hosts one local file and asks the target to fetch it. The
// returned job ID tracks the agent's fetch.
func (C2Executor) UploadFile(_ context.Context, target *def.Emp3r0rAgent, src, dst string) (string, error) {
	return ftp.PutFileWithJob(src, dst, target)
}

// DownloadFile pulls one remote path to the operator. The returned path is the
// local file for a single transfer, or the download root for a recursive one.
func (C2Executor) DownloadFile(_ context.Context, target *def.Emp3r0rAgent, path, filter string, recursive bool) (string, error) {
	if err := modules.DownloadGetFile(target, path, filter, recursive); err != nil {
		return "", err
	}
	if live.FileGetDir == "" {
		return "", nil
	}
	if recursive {
		return live.FileGetDir, nil
	}
	_, saveToFile, _, _ := ftp.GenerateGetFilePaths(path)
	if info, err := os.Stat(saveToFile); err == nil && info.Mode().IsRegular() {
		return saveToFile, nil
	}
	return live.FileGetDir, nil
}

// ReloadModules rescans the module directories.
func (C2Executor) ReloadModules(_ context.Context) error {
	modules.InitModules()
	return nil
}

// ResumeOperator clears the server-side operator idle state.
func (C2Executor) ResumeOperator(context.Context) error {
	return client.ResumeOperator()
}

// ForgetAgent removes one agent record from the C2 database.
func (C2Executor) ForgetAgent(_ context.Context, agent string) (string, error) {
	return operator.ForgetAgent(agent)
}

// StartSocks5 starts a C2-side SOCKS5 pivot through the selected agent.
func (C2Executor) StartSocks5(_ context.Context, port int, bind string) (operator.Socks5Pivot, error) {
	return operator.StartSocks5Pivot(port, bind)
}

// StopSocks5 stops one C2-side SOCKS5 pivot.
func (C2Executor) StopSocks5(_ context.Context, port int) error {
	return operator.StopSocks5Pivot(port)
}

// ListSocks5 lists running C2-side SOCKS5 pivots.
func (C2Executor) ListSocks5(context.Context) ([]operator.Socks5Pivot, error) {
	return operator.Socks5Pivots()
}

// StartTun2Socks creates a TUN and routes networks through the SOCKS5 pivot.
func (C2Executor) StartTun2Socks(_ context.Context, opts operator.Tun2SocksOptions) (operator.Tun2SocksState, error) {
	return operator.StartTun2Socks(opts)
}

// StopTun2Socks closes one transparent-proxy instance.
func (C2Executor) StopTun2Socks(_ context.Context, name string) error {
	return operator.StopTun2Socks(name)
}

// Tun2SocksStatus lists running transparent-proxy instances.
func (C2Executor) Tun2SocksStatus(context.Context) []operator.Tun2SocksState {
	return operator.Tun2SocksStatus()
}

// SetDebugLevel changes operator log verbosity.
func (C2Executor) SetDebugLevel(_ context.Context, level int) error {
	logging.SetDebugLevel(level)
	return nil
}
