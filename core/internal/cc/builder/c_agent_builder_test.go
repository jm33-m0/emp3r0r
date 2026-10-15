package builder

import (
	"debug/elf"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestCAgentBuildArgs(t *testing.T) {
	args := cAgentBuildArgs("/src", "/tmp/cfg.c", CAgentProviders{
		Crypto:    "mbedtls",
		Gzip:      "none",
		HTTP:      "libcurl",
		Transport: "http_poll",
		Dynload:   "auto",
		Glibc:     "2.17",
		Libc:      "musl",
	})
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-C /src",
		"agent",
		"CONFIG_SRC=/tmp/cfg.c",
		"CRYPTO=mbedtls",
		"GZIP=none",
		"HTTP=libcurl",
		"TRANSPORT=http_poll",
		"DYNLOAD_MODE=auto",
		"GLIBC_VERSION=2.17",
		"LIBC=musl",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("build args missing %q: %v", want, args)
		}
	}
}

func TestCAgentBuildArgsOmitsEmptyProviders(t *testing.T) {
	args := cAgentBuildArgs("/src", "/cfg", CAgentProviders{})
	joined := strings.Join(args, " ")
	for _, unwanted := range []string{"CRYPTO=", "GZIP=", "HTTP=", "TRANSPORT=", "DYNLOAD_MODE=", "GLIBC_VERSION=", "LIBC="} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("empty provider should be omitted, got %q", joined)
		}
	}
}

func TestValidateCAgentProviders(t *testing.T) {
	if err := validateCAgentProviders(CAgentProviders{}); err != nil {
		t.Fatalf("empty providers should be valid (Makefile defaults): %v", err)
	}
	valid := CAgentProviders{Crypto: "openssl", Gzip: "miniz", HTTP: "libcurl", Transport: "http_poll", Dynload: "auto", Glibc: "2.17", Libc: "glibc"}
	if err := validateCAgentProviders(valid); err != nil {
		t.Fatalf("valid providers rejected: %v", err)
	}
	validMusl := CAgentProviders{Transport: "http_poll", Dynload: "public", Libc: "musl"}
	if err := validateCAgentProviders(validMusl); err != nil {
		t.Fatalf("valid musl providers rejected: %v", err)
	}
	for _, bad := range []CAgentProviders{
		{Crypto: "bogus"},
		{Gzip: "zlib"},
		{HTTP: "raw"},
		{Transport: "h2conn"},
		{Dynload: "magic"},
		{Glibc: "1.0"},
		{Libc: "uclibc"},
		{Libc: "musl", Dynload: "libc_dl"},
		{Libc: "musl", Dynload: "auto"},
	} {
		if err := validateCAgentProviders(bad); err == nil {
			t.Errorf("expected error for %+v", bad)
		}
	}
}

// setupCAgentBuildEnv points the on-demand builder at the checkout's c_agent
// tree and a temp workspace, and skips when the pinned zig toolchain or the
// source is unavailable. The previous globals are restored when the test ends.
func setupCAgentBuildEnv(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig is required to build the C agent")
	}
	coreDir, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve core dir: %v", err)
	}
	if !util.IsFileExist(filepath.Join(coreDir, "c_agent", "Makefile")) {
		t.Skip("core/c_agent source not available")
	}
	tmp := t.TempDir()
	origData, origWS, origCfg, origRT := live.EmpDataDir, live.EmpWorkSpace, live.EmpConfigFile, live.RuntimeConfig
	t.Cleanup(func() {
		live.EmpDataDir, live.EmpWorkSpace, live.EmpConfigFile, live.RuntimeConfig = origData, origWS, origCfg, origRT
	})
	live.EmpDataDir = coreDir
	live.EmpWorkSpace = tmp
	live.EmpConfigFile = filepath.Join(tmp, "emp3r0r.json")
	live.RuntimeConfig = &def.Config{}
}

// TestGenerateCAgentWorkflow exercises the full operator path: shared config
// plumbing, MagicString-encrypted config, on-demand `make`, and the copied
// artifact. It is skipped unless the pinned zig toolchain and the C agent
// source are available, and is otherwise covered end to end by the stager
// suite's TestCAgentEndToEnd.
func TestGenerateCAgentWorkflow(t *testing.T) {
	setupCAgentBuildEnv(t)

	res, err := GenerateCAgentWorkflow(AgentConfig{}, CAgentProviders{Crypto: "openssl", Gzip: "miniz"}, nil)
	if err != nil {
		t.Fatalf("GenerateCAgentWorkflow: %v", err)
	}
	if !util.IsFileExist(res.OutputFile) {
		t.Fatalf("output not produced: %s", res.OutputFile)
	}
	if !strings.HasPrefix(filepath.Base(res.OutputFile), "aquila_linux_") {
		t.Errorf("unexpected output name %q", res.OutputFile)
	}
	if res.AgentUUID == "" || res.ConfigSize == 0 {
		t.Fatalf("incomplete result: %+v", res)
	}
}

// TestGenerateCAgentMuslDynamic pins that a musl build links against musl's
// dynamic loader rather than the static default: dynload needs a loader and a
// /proc/self/maps libc segment to resolve dlopen/dlsym/dlclose.
func TestGenerateCAgentMuslDynamic(t *testing.T) {
	setupCAgentBuildEnv(t)

	res, err := GenerateCAgentWorkflow(AgentConfig{}, CAgentProviders{Libc: "musl", Dynload: "public"}, nil)
	if err != nil {
		t.Fatalf("GenerateCAgentWorkflow(musl): %v", err)
	}
	interp, err := elfInterp(res.OutputFile)
	if err != nil {
		t.Fatalf("read interpreter: %v", err)
	}
	if interp == "" {
		t.Fatal("musl build is static; dynload needs a dynamic loader")
	}
	if !strings.Contains(interp, "ld-musl") {
		t.Fatalf("musl build interpreter = %q, want ld-musl", interp)
	}
}

// elfInterp returns the PT_INTERP program interpreter of an ELF, or "" when
// the binary is static.
func elfInterp(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		buf := make([]byte, p.Filesz)
		if _, err := p.ReadAt(buf, 0); err != nil {
			return "", err
		}
		return strings.TrimRight(string(buf), "\x00"), nil
	}
	return "", nil
}
