package builder

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

const (
	// GoAgentSourceDirName is the editable Go agent source tree mirrored next
	// to c_agent in the operator workspace and installed data directory.
	GoAgentSourceDirName = "go_agent"
	// GoAgentGarbleName is the garble binary shipped beside the Go toolchain.
	GoAgentGarbleName = "garble"
	// GoAgentToolchainDirName is the shipped GOROOT directory.
	GoAgentToolchainDirName = "go"
	// GoAgentBuildScript is the single-payload builder shipped with the source.
	GoAgentBuildScript = "build.py"

	goAgentBuildTimeout = 30 * time.Minute
)

// GoAgentSourceDir resolves the editable Go agent source tree. The workspace
// copy wins so detection-loop edits affect the next build; the read-only
// installed copy is the fallback.
func GoAgentSourceDir() (string, error) {
	candidates := []string{
		filepath.Join(live.EmpWorkSpace, GoAgentSourceDirName),
		filepath.Join(live.EmpDataDir, GoAgentSourceDirName),
	}
	for _, dir := range candidates {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && info.Mode().IsRegular() {
			if info, err := os.Stat(filepath.Join(dir, "cmd", "agent")); err == nil && info.IsDir() {
				if info, err := os.Stat(filepath.Join(dir, GoAgentBuildScript)); err == nil && info.Mode().IsRegular() {
					return dir, nil
				}
			}
		}
	}
	return "", fmt.Errorf("go agent source tree not found under %s or %s", candidates[0], candidates[1])
}

// BuildGoAgentStub compiles the agent from source with the shipped build.py and
// writes the unpatched binary to stubFile. The caller patches the encrypted
// config slot afterwards.
func BuildGoAgentStub(cfg AgentBuildConfig, sourceDir, stubFile string) error {
	if sourceDir == "" || stubFile == "" {
		return fmt.Errorf("Go agent build requires a source directory and output path")
	}
	script := filepath.Join(sourceDir, GoAgentBuildScript)
	if !util.IsExist(script) {
		return fmt.Errorf("Go agent build script is missing: %s", script)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		return fmt.Errorf("python3 is required to build a Go agent: %w", err)
	}
	tmpDir, err := os.MkdirTemp(live.EmpWorkSpace, "go-agent-build-")
	if err != nil {
		return fmt.Errorf("create Go agent build directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	tmpFile := filepath.Join(tmpDir, "agent")
	kind := goAgentPayloadKind(cfg.PayloadType)
	if kind == "" {
		return fmt.Errorf("unsupported Go agent payload type %q", cfg.PayloadType)
	}
	args := []string{
		script, "--build-payload",
		"--payload-kind", kind,
		"--payload-os", PayloadGOOS(cfg.PayloadType),
		"--payload-arch", cfg.Arch,
		"--payload-output", tmpFile,
	}
	if tags := strings.TrimSpace(strings.Join(cfg.BuildTags, " ")); tags != "" {
		args = append(args, "--agent-tags", tags)
	} else {
		args = append(args, "--agent-slim")
	}
	buildCtx, cancel := context.WithTimeout(context.Background(), goAgentBuildTimeout)
	defer cancel()
	cmd := exec.CommandContext(buildCtx, python, args...)
	cmd.Dir = sourceDir
	env := goAgentBuildEnv()
	env = setEnv(env, "EMP3R0R_MAGIC_STRING", def.MagicString)
	cmd.Env = env
	output, runErr := cmd.CombinedOutput()
	if runErr != nil {
		return fmt.Errorf("build Go agent: %w: %s", runErr, clipBuildOutput(output))
	}
	if err := os.Chmod(tmpFile, 0o755); err != nil {
		return fmt.Errorf("chmod built Go agent: %w", err)
	}
	if err := os.Rename(tmpFile, stubFile); err != nil {
		return fmt.Errorf("install built Go agent: %w", err)
	}
	return nil
}

func goAgentPayloadKind(payloadType string) string {
	switch payloadType {
	case PayloadTypeLinuxExecutable, PayloadTypeWindowsExecutable:
		if payloadType == PayloadTypeLinuxExecutable {
			return "cgo"
		}
		return "pure"
	case PayloadTypeLinuxSO, PayloadTypeWindowsDLL:
		return "shared"
	default:
		return ""
	}
}

// minimalBuildEnv keeps provider credentials and unrelated operator state out
// of build.py and the compiler processes. The build gets only the variables it
// needs to locate tools, temporary files, and the shipped toolchain.
func minimalBuildEnv() []string {
	allowed := map[string]bool{
		"PATH": true, "HOME": true, "TMPDIR": true, "TEMP": true, "TMP": true,
		"LANG": true, "LC_ALL": true, "LC_CTYPE": true, "TZ": true,
		"EMP3R0R_GARBLE": true, "EMP3R0R_DISABLE_GARBLE": true,
		"SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
	}
	var env []string
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if ok && allowed[key] {
			env = append(env, kv)
		}
	}
	return env
}

func goAgentBuildEnv() []string {
	env := minimalBuildEnv()
	goRoot := filepath.Join(live.EmpDataDir, GoAgentToolchainDirName)
	cache := filepath.Join(live.EmpWorkSpace, ".go-cache")
	_ = os.MkdirAll(cache, 0o700)
	gopath := filepath.Join(live.EmpWorkSpace, ".go-path")
	_ = os.MkdirAll(gopath, 0o700)
	path := []string{}
	if util.IsExist(filepath.Join(goRoot, "bin", "go")) {
		path = append(path, filepath.Join(goRoot, "bin"))
	}
	if util.IsExist(filepath.Join(live.EmpDataDir, "zig", "zig")) {
		path = append(path, filepath.Join(live.EmpDataDir, "zig"))
	}
	if live.EmpDataDir != "" {
		path = append(path, live.EmpDataDir)
	}
	if old, ok := lookupEnv(env, "PATH"); ok && old != "" {
		path = append(path, old)
	}
	env = setEnv(env, "PATH", strings.Join(path, string(os.PathListSeparator)))
	if util.IsExist(filepath.Join(goRoot, "bin", "go")) {
		env = setEnv(env, "GOROOT", goRoot)
		env = setEnv(env, "EMP3R0R_GOROOT", goRoot)
	}
	env = setEnv(env, "GOTOOLCHAIN", "local")
	env = setEnv(env, "GOPROXY", "off")
	env = setEnv(env, "GOWORK", "off")
	env = setEnv(env, "GOCACHE", cache)
	env = setEnv(env, "GOPATH", gopath)
	if strings.TrimSpace(os.Getenv("EMP3R0R_GARBLE")) == "" {
		if garble := filepath.Join(live.EmpDataDir, GoAgentGarbleName); util.IsExist(garble) {
			env = setEnv(env, "EMP3R0R_GARBLE", garble)
		}
	}
	return env
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			env[i] = key + "=" + value
			return env
		}
	}
	return append(env, key+"="+value)
}

func lookupEnv(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix), true
		}
	}
	return "", false
}

func clipBuildOutput(data []byte) string {
	const max = 8 << 10
	if len(data) > max {
		data = data[len(data)-max:]
	}
	return strings.TrimSpace(string(data))
}
