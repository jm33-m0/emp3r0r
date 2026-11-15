//go:build linux

package loaderwindows_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSplitCommandLineBounds(t *testing.T) {
	cc := findHostCCompiler()
	if cc == "" {
		t.Skip("no host C compiler available")
	}

	dir := t.TempDir()
	harness := `
#include <assert.h>
#include <wchar.h>

#define STAGER_UNIT_TEST
#include "stager.c"

static void assert_argv_in_bounds(int argc) {
	const wchar_t *buf_start = g_stager_argv_buf;
	const wchar_t *buf_end = g_stager_argv_buf + STAGER_ARGV_CHARS;
	assert(argc >= 0 && argc <= STAGER_MAX_ARGS);
	for (int i = 0; i < argc; i++) {
		assert(g_stager_argv[i] >= buf_start && g_stager_argv[i] < buf_end);
		size_t max_len = (size_t)(buf_end - g_stager_argv[i]);
		assert(wcsnlen(g_stager_argv[i], max_len) < max_len);
	}
}

int main(void) {
	// Token fills STAGER_ARGV_CHARS-1 chars, ends on space, followed by empty quotes and extra token.
	wchar_t exact_fill[64] = L"abcdefg \"\" tail";
	int argc = split_command_line(exact_fill, g_stager_argv, STAGER_MAX_ARGS);
	assert_argv_in_bounds(argc);
	assert(argc == 1);
	assert(wcscmp(g_stager_argv[0], L"abcdefg") == 0);

	// Token fills STAGER_ARGV_CHARS-2 chars leaving one char for an empty trailing token or stopping cleanly.
	wchar_t one_left[64] = L"abcdef \"\" tail";
	argc = split_command_line(one_left, g_stager_argv, STAGER_MAX_ARGS);
	assert_argv_in_bounds(argc);

	// Oversized single token truncates safely inside the buffer.
	wchar_t long_tok[64] = L"abcdefghijkl";
	argc = split_command_line(long_tok, g_stager_argv, STAGER_MAX_ARGS);
	assert_argv_in_bounds(argc);
	assert(argc == 1);
	assert(wcscmp(g_stager_argv[0], L"abcdefg") == 0);

	// Quoted spaces and tabs.
	wchar_t quoted[64] = L"a \"b c\" d";
	argc = split_command_line(quoted, g_stager_argv, STAGER_MAX_ARGS);
	assert_argv_in_bounds(argc);
	assert(argc == 3);
	assert(wcscmp(g_stager_argv[0], L"a") == 0);
	assert(wcscmp(g_stager_argv[1], L"b c") == 0);
	assert(wcscmp(g_stager_argv[2], L"d") == 0);

	// Guard against NULL or zero max args.
	assert(split_command_line(NULL, g_stager_argv, STAGER_MAX_ARGS) == 0);
	assert(split_command_line(quoted, NULL, STAGER_MAX_ARGS) == 0);
	assert(split_command_line(quoted, g_stager_argv, 0) == 0);

	return 0;
}
`
	harnessPath := filepath.Join(dir, "test_split.c")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(dir, "test_split")
	moduleDir, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}

	args := []string{
		"-O1", "-g", "-Wall", "-Wextra", "-Werror",
		"-DSTAGER_ARGV_CHARS=8",
		"-fsanitize=address,undefined",
		"-I", moduleDir,
		harnessPath, "-o", binPath,
	}
	compile := exec.Command(cc, args...)
	out, err := compile.CombinedOutput()
	if err != nil {
		// Retry without sanitizers if sanitizer runtime libraries are absent.
		fallbackArgs := []string{
			"-O1", "-g", "-Wall", "-Wextra",
			"-DSTAGER_ARGV_CHARS=8",
			"-I", moduleDir,
			harnessPath, "-o", binPath,
		}
		compile = exec.Command(cc, fallbackArgs...)
		if out2, err2 := compile.CombinedOutput(); err2 != nil {
			t.Fatalf("compile C test failed: %v\n%s\nfallback:\n%v\n%s", err, out, err2, out2)
		}
	}

	run := exec.Command(binPath)
	if runOut, err := run.CombinedOutput(); err != nil {
		t.Fatalf("stager split_command_line test failed: %v\n%s", err, runOut)
	}
}

func findHostCCompiler() string {
	for _, candidate := range []string{"cc", "gcc", "clang"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	return ""
}
