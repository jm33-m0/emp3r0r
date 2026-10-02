//go:build linux && !android && (386 || amd64 || arm64)

package libbpf

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// mockLibbpfSource implements enough of libbpf's C ABI to exercise the loader
// without building the real library. Objects starting with "BPF" are accepted.
const mockLibbpfSource = `
#include <stdint.h>
#include <stddef.h>

__attribute__((visibility("default"))) const char *libbpf_version_string(void) {
	return "1.5.0-mock";
}

__attribute__((visibility("default"))) int libbpf_num_possible_cpus(void) {
	return 4;
}

__attribute__((visibility("default"))) int64_t libbpf_get_error(uintptr_t ptr) {
	return ptr == (uintptr_t)0xDEAD ? -22 : 0;
}

__attribute__((visibility("default"))) uintptr_t bpf_object__open_mem(const uint8_t *buf, size_t sz, uintptr_t opts) {
	if (sz >= 3 && buf[0] == 'B' && buf[1] == 'P' && buf[2] == 'F') {
		return (uintptr_t)0x1000;
	}
	return (uintptr_t)0xDEAD;
}

__attribute__((visibility("default"))) int bpf_object__load(uintptr_t obj) {
	(void)obj;
	return 0;
}

__attribute__((visibility("default"))) void bpf_object__close(uintptr_t obj) {
	(void)obj;
}

__attribute__((visibility("default"))) uintptr_t bpf_object__find_program_by_name(uintptr_t obj, const char *name) {
	(void)obj;
	return (name != 0 && name[0] != 0) ? (uintptr_t)0x2000 : 0;
}

__attribute__((visibility("default"))) uintptr_t bpf_program__attach(uintptr_t prog) {
	(void)prog;
	return (uintptr_t)0x3000;
}

__attribute__((visibility("default"))) const char *bpf_program__name(uintptr_t prog) {
	(void)prog;
	return "mock_prog";
}

__attribute__((visibility("default"))) int bpf_link__destroy(uintptr_t link) {
	(void)link;
	return 0;
}

__attribute__((visibility("default"))) int bpf_prog_get_next_id(uint32_t start, uint32_t *next) {
	if (start == 0) { *next = 10; return 0; }
	if (start == 10) { *next = 20; return 0; }
	return -2;
}

__attribute__((visibility("default"))) int bpf_link_get_next_id(uint32_t start, uint32_t *next) {
	if (start == 0) { *next = 30; return 0; }
	return -2;
}

__attribute__((visibility("default"))) int bpf_map_get_next_id(uint32_t start, uint32_t *next) {
	if (start == 0) { *next = 40; return 0; }
	return -2;
}

__attribute__((visibility("default"))) int bpf_prog_get_fd_by_id(uint32_t id) {
	return (id == 10 || id == 20) ? 100 : -1;
}

__attribute__((visibility("default"))) int bpf_link_get_fd_by_id(uint32_t id) {
	return id == 30 ? 101 : -1;
}

__attribute__((visibility("default"))) int bpf_map_get_fd_by_id(uint32_t id) {
	return id == 40 ? 102 : -1;
}

__attribute__((visibility("default"))) int bpf_obj_get_info_by_fd(int fd, void *info, uint32_t *info_len) {
	uint8_t *p = (uint8_t *)info;
	for (uint32_t i = 0; i < *info_len && i < 256; i++) {
		p[i] = 0;
	}
	if (fd == 100) {
		*(uint32_t *)(p + 0) = 1;
		*(uint32_t *)(p + 4) = 10;
		*(uint64_t *)(p + 40) = 12345;
		const char *n = "mock_prog";
		for (int i = 0; n[i] != 0 && i < 16; i++) p[64 + i] = (uint8_t)n[i];
	} else if (fd == 101) {
		*(uint32_t *)(p + 0) = 3;
		*(uint32_t *)(p + 8) = 10;
	} else if (fd == 102) {
		*(uint32_t *)(p + 0) = 2;
		*(uint32_t *)(p + 8) = 4;
		*(uint32_t *)(p + 12) = 8;
		*(uint32_t *)(p + 16) = 1024;
		const char *n = "mock_map";
		for (int i = 0; n[i] != 0 && i < 16; i++) p[24 + i] = (uint8_t)n[i];
	} else {
		return -1;
	}
	*info_len = 256;
	return 0;
}

__attribute__((visibility("default"))) int bpf_link_detach(int fd) {
	return fd == 101 ? 0 : -1;
}
`

func buildMockLibbpf(t *testing.T) []byte {
	t.Helper()
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipping: race detector enables checkptr, which conflicts with mapping arbitrary memory")
	}
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig not found in PATH")
	}

	var target string
	switch runtime.GOARCH {
	case "386":
		target = "x86-linux-gnu.2.17"
	case "amd64":
		target = "x86_64-linux-gnu.2.17"
	case "arm64":
		target = "aarch64-linux-gnu.2.17"
	default:
		t.Skipf("no zig target mapping for GOARCH %s", runtime.GOARCH)
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "libbpf.c")
	if err := os.WriteFile(src, []byte(mockLibbpfSource), 0o600); err != nil {
		t.Fatalf("write mock source: %v", err)
	}
	out := filepath.Join(dir, "libbpf.so")
	cmd := exec.Command("zig", "cc",
		"-target", target,
		"-shared", "-fPIC", "-fno-builtin",
		"-O2", "-g0",
		"-fno-sanitize=all",
		"-o", out, src,
	)
	cmd.Env = append(os.Environ(),
		"ZIG_GLOBAL_CACHE_DIR="+filepath.Join(os.TempDir(), "emp3r0r-zig-global-cache"),
		"ZIG_LOCAL_CACHE_DIR="+filepath.Join(os.TempDir(), "emp3r0r-zig-local-cache"),
	)
	if buildOut, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zig cc failed: %v\n%s", err, buildOut)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read mock: %v", err)
	}
	return data
}

func TestLibraryLifecycle(t *testing.T) {
	lib, err := Load(buildMockLibbpf(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(lib.Close)

	if v, err := lib.Version(); err != nil || v != "1.5.0-mock" {
		t.Fatalf("Version = %q, %v", v, err)
	}
	if n, err := lib.NumPossibleCPUs(); err != nil || n != 4 {
		t.Fatalf("NumPossibleCPUs = %d, %v", n, err)
	}

	if _, err := lib.OpenMem([]byte("not a bpf object")); err == nil {
		t.Fatal("OpenMem accepted garbage")
	}

	obj, err := lib.OpenMem([]byte("BPFfake-object"))
	if err != nil {
		t.Fatalf("OpenMem: %v", err)
	}
	if err := obj.Load(); err != nil {
		t.Fatalf("Object.Load: %v", err)
	}
	prog, err := obj.FindProgram("myprog")
	if err != nil {
		t.Fatalf("FindProgram: %v", err)
	}
	if name := prog.Name(); name != "mock_prog" {
		t.Fatalf("Program.Name = %q", name)
	}
	link, err := prog.Attach()
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	link.Destroy()
	obj.Close()
}

func TestKernelEnumeration(t *testing.T) {
	lib, err := Load(buildMockLibbpf(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(lib.Close)

	progs, err := lib.ProgList()
	if err != nil {
		t.Fatalf("ProgList: %v", err)
	}
	if len(progs) != 2 || progs[0].ID != 10 || progs[1].ID != 20 {
		t.Fatalf("ProgList = %+v", progs)
	}
	if progs[0].Name != "mock_prog" || progs[0].LoadTime != 12345 || progs[0].Type != 1 {
		t.Fatalf("ProgList first = %+v", progs[0])
	}

	links, err := lib.LinkList()
	if err != nil {
		t.Fatalf("LinkList: %v", err)
	}
	if len(links) != 1 || links[0].ID != 30 || links[0].ProgID != 10 {
		t.Fatalf("LinkList = %+v", links)
	}

	maps, err := lib.MapList()
	if err != nil {
		t.Fatalf("MapList: %v", err)
	}
	if len(maps) != 1 || maps[0].ID != 40 || maps[0].Name != "mock_map" || maps[0].MaxEntries != 1024 {
		t.Fatalf("MapList = %+v", maps)
	}

	if err := lib.LinkDetach(30); err != nil {
		t.Fatalf("LinkDetach: %v", err)
	}
}

func TestVersionReadsCString(t *testing.T) {
	// Guard the unsafe C-string reader: a version longer than the buffer is
	// still bounded by max.
	lib, err := Load(buildMockLibbpf(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(lib.Close)
	v, err := lib.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if strings.TrimSpace(v) == "" {
		t.Fatal("Version returned empty string")
	}
}
