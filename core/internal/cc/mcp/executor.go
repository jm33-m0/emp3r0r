package mcp

import (
	"context"
	"os"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
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

// RunExec executes one shell command. A C agent runs the exec BOF; a Go agent
// uses the built-in exec command.
func (C2Executor) RunExec(_ context.Context, target *def.Emp3r0rAgent, command string, shell bool) (string, error) {
	if modules.CanRunExecBOF(target) {
		return modules.DispatchExec(target, command, shell)
	}
	return controllers.ExecuteCommandWithJob("exec --cmd "+strconv.Quote(command), "", target.Tag)
}

// RunCommand sends a built-in agent command line.
func (C2Executor) RunCommand(_ context.Context, target *def.Emp3r0rAgent, command string) (string, error) {
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
