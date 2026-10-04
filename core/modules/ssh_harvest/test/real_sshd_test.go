//go:build linux && !android && amd64

// Package sshharvesttest contains the real-sshd end-to-end test for the
// ssh_harvest module. It is opt-in: set EMP3R0R_TEST_REAL_SSHD=1 to run it.
//
// The test downloads and builds a pinned OpenSSH server, starts it on a
// loopback port, runs the real ssh_harvest Starlark module with the shipped
// eBPF uprobe, and drives a real password authentication attempt with
// golang.org/x/crypto/ssh. It asserts the password is captured from the
// authentication register.
//
// Building OpenSSH and libbpf needs a C toolchain, zig, and network access, so
// the test is excluded from a normal `go test ./...` run. Builds are cached
// under EMP3R0R_TEST_OPENSSH_CACHE (default $TMPDIR/emp3r0r-openssh-cache) and
// the libbpf module tree, so repeat runs are fast.
package sshharvesttest

import (
	"debug/elf"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/elfutil"
	"github.com/jm33-m0/emp3r0r/core/lib/memdeps"
	"github.com/jm33-m0/emp3r0r/core/lib/script"
	"golang.org/x/crypto/ssh"
)

const testPassword = "hunter2-real-sshd"

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test file path")
	}
	// core/modules/ssh_harvest/test/real_sshd_test.go -> repo root
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))))
}

func TestRealSSHDAuthCapture(t *testing.T) {
	if os.Getenv("EMP3R0R_TEST_REAL_SSHD") == "" {
		t.Skip("set EMP3R0R_TEST_REAL_SSHD=1 to run the real-sshd e2e test")
	}
	if os.Geteuid() != 0 {
		t.Skip("root is required to run sshd")
	}
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("C compiler not found")
	}

	root := repoRoot(t)
	cache := os.Getenv("EMP3R0R_TEST_OPENSSH_CACHE")
	if cache == "" {
		cache = filepath.Join(os.TempDir(), "emp3r0r-openssh-cache")
	}

	install := buildOpenSSH(t, root, cache)
	// In OpenSSH 9.8+ the per-connection monitor that calls auth_password is
	// sshd-session; sshd-auth is the unprivileged pre-auth child which forwards
	// the password over the monitor socket. Probe sshd-session.
	sshdSession := filepath.Join(install, "libexec", "sshd-session")
	pattern := authPasswordPattern(t, sshdSession)

	probe := filepath.Join(root, "core", "modules", "ssh_harvest", "probe.bpf.o")
	if _, err := os.Stat(probe); err != nil {
		cmd := exec.Command("make", "-C", filepath.Join(root, "core", "modules", "ssh_harvest"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build probe.bpf.o: %v\n%s", err, out)
		}
	}
	star := filepath.Join(root, "core", "modules", "ssh_harvest", "ssh_harvest.star")
	starSrc, err := os.ReadFile(star)
	if err != nil {
		t.Fatalf("read ssh_harvest.star: %v", err)
	}

	libbpf := os.Getenv("EMP3R0R_TEST_LIBBPF")
	if libbpf == "" {
		libbpf = buildLibbpf(t, root)
	}
	libData, err := os.ReadFile(libbpf)
	if err != nil {
		t.Fatalf("read libbpf: %v", err)
	}

	addr, stopSSHD := startSSHD(t, install)
	defer stopSSHD()

	// The module's ebpf_* builtins resolve the libbpf dependency through
	// memdeps; hand them the freshly built object for the duration of the run.
	memdeps.SetResolver(func(string) ([]byte, error) { return libData, nil })
	defer memdeps.SetResolver(nil)

	type runResult struct {
		out string
		err error
	}
	resultCh := make(chan runResult, 1)
	go func() {
		out, err := script.Run(
			starSrc,
			// reg, code-pattern, timeout_s, sshd-session path, pid (-1 = all)
			[]string{"RSI", pattern, "10", sshdSession, "-1"},
			map[string]any{"module_files": []string{probe}},
			0,
		)
		resultCh <- runResult{out, err}
	}()

	// Give CaptureUprobe time to load the object and attach before the
	// authentication attempt reaches auth_password in sshd-session.
	time.Sleep(3 * time.Second)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password(testPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		client.Close()
		t.Fatalf("authentication with a wrong password unexpectedly succeeded")
	}

	res := <-resultCh
	if res.err != nil {
		t.Fatalf("ssh_harvest.star failed: %v\n%s", res.err, res.out)
	}
	t.Logf("module output:\n%s", res.out)
	if !strings.Contains(res.out, testPassword) {
		t.Fatalf("password %q was not captured:\n%s", testPassword, res.out)
	}
}

// buildOpenSSH runs the pinned OpenSSH build script and returns the install
// prefix. The script's stdout/stderr is build noise, not the prefix, so the
// location is derived from the cache directory instead.
func buildOpenSSH(t *testing.T, root, cache string) string {
	t.Helper()
	scriptPath := filepath.Join(root, "core", "modules", "ssh_harvest", "test", "build_openssh.sh")
	cmd := exec.Command("sh", scriptPath, cache)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build OpenSSH: %v\n%s", err, out)
	}
	install := filepath.Join(cache, "install")
	for _, bin := range []string{
		filepath.Join(install, "sbin", "sshd"),
		filepath.Join(install, "libexec", "sshd-session"),
		filepath.Join(install, "libexec", "sshd-auth"),
	} {
		if _, err := os.Stat(bin); err != nil {
			t.Fatalf("OpenSSH build incomplete, %s missing: %v\n%s", bin, err, out)
		}
	}
	return install
}

// buildLibbpf builds the project's libbpf shared object and returns its path.
func buildLibbpf(t *testing.T, root string) string {
	t.Helper()
	dir := filepath.Join(root, "core", "modules", "libbpf")
	cmd := exec.Command("make", "-C", dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build libbpf: %v\n%s", err, out)
	}
	so := filepath.Join(dir, "libbpf.so")
	if _, err := os.Stat(so); err != nil {
		t.Fatalf("libbpf.so missing after build: %v", err)
	}
	return so
}

// authPasswordPattern derives a unique hex byte pattern that starts at the
// first instruction of auth_password, where the second argument (the password)
// is still in RSI. The pattern is taken from the ELF image directly so the
// test does not depend on a compiler generating a fixed prologue.
func authPasswordPattern(t *testing.T, path string) string {
	t.Helper()
	image, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("read %s symbols (was OpenSSH built with --disable-strip?): %v", path, err)
	}
	var value uint64
	found := false
	for _, s := range syms {
		if s.Name == "auth_password" {
			value = s.Value
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("auth_password symbol not found in %s", path)
	}

	// Map the symbol's virtual address to a file offset through its section.
	var fileOff uint64
	mapped := false
	for _, sec := range f.Sections {
		if sec.Type == elf.SHT_NOBITS || sec.Size == 0 {
			continue
		}
		if value >= sec.Addr && value < sec.Addr+sec.Size {
			fileOff = sec.Offset + (value - sec.Addr)
			mapped = true
			break
		}
	}
	if !mapped {
		t.Fatalf("auth_password vaddr %#x is not in any section of %s", value, path)
	}
	if fileOff+64 > uint64(len(image)) {
		t.Fatalf("auth_password at file offset %#x is beyond the image", fileOff)
	}

	// At the function entry RSI holds the password, so the probe must fire on
	// the first byte. Grow the prefix until it is unique in the executable
	// segments; FindCodePattern then maps it back to this exact offset.
	for n := 16; n <= 64; n += 4 {
		pat := image[fileOff : fileOff+uint64(n)]
		off, _, err := elfutil.FindCodePattern(image, pat)
		if err == nil && off == fileOff {
			return hex.EncodeToString(pat)
		}
	}
	t.Fatalf("could not find a unique auth_password entry prefix in %s", path)
	return ""
}

// startSSHD generates host keys, writes a minimal config, starts sshd, and
// waits until it is listening. The returned stop function kills the daemon.
func startSSHD(t *testing.T, install string) (addr string, stop func()) {
	t.Helper()
	dir := t.TempDir()

	keyPaths := make([]string, 0, 2)
	for _, kind := range []string{"ed25519", "rsa"} {
		key := filepath.Join(dir, "ssh_host_"+kind+"_key")
		cmd := exec.Command(filepath.Join(install, "bin", "ssh-keygen"),
			"-q", "-t", kind, "-N", "", "-f", key)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen -t %s: %v\n%s", kind, err, out)
		}
		keyPaths = append(keyPaths, key)
	}

	port := freePort(t)
	conf := filepath.Join(dir, "sshd_config")
	var b strings.Builder
	fmt.Fprintf(&b, "Port %d\n", port)
	b.WriteString("ListenAddress 127.0.0.1\n")
	for _, key := range keyPaths {
		fmt.Fprintf(&b, "HostKey %s\n", key)
	}
	fmt.Fprintf(&b, "PidFile %s\n", filepath.Join(dir, "sshd.pid"))
	b.WriteString("PasswordAuthentication yes\n")
	b.WriteString("KbdInteractiveAuthentication no\n")
	b.WriteString("PermitRootLogin yes\n")
	b.WriteString("PermitEmptyPasswords no\n")
	b.WriteString("AuthorizedKeysFile none\n")
	b.WriteString("StrictModes no\n")
	b.WriteString("UseDNS no\n")
	b.WriteString("GSSAPIAuthentication no\n")
	b.WriteString("LoginGraceTime 15\n")
	b.WriteString("LogLevel VERBOSE\n")
	if err := os.WriteFile(conf, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write sshd config: %v", err)
	}

	logPath := filepath.Join(dir, "sshd.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create sshd log: %v", err)
	}

	cmd := exec.Command(filepath.Join(install, "sbin", "sshd"), "-D", "-e", "-f", conf)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("start sshd: %v", err)
	}

	addr = fmt.Sprintf("127.0.0.1:%d", port)
	stop = func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		logFile.Close()
		if t.Failed() {
			if data, err := os.ReadFile(logPath); err == nil {
				t.Logf("sshd log:\n%s", data)
			}
		}
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return addr, stop
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	t.Fatalf("sshd did not start listening on %s", addr)
	return "", stop
}

// freePort reserves a loopback port by binding and immediately releasing it.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
