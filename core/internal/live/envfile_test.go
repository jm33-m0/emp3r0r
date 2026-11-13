package live

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseOperatorEnv(t *testing.T) {
	values, err := ParseOperatorEnv([]byte(`
# comment
export EMP3R0R_DETECTION_PROVIDER=openai-responses
EMP3R0R_DETECTION_MODEL="deepseek-test"
PLAIN=value=with=equals
`))
	if err != nil {
		t.Fatal(err)
	}
	if values["EMP3R0R_DETECTION_PROVIDER"] != "openai-responses" ||
		values["EMP3R0R_DETECTION_MODEL"] != "deepseek-test" ||
		values["PLAIN"] != "value=with=equals" {
		t.Fatalf("values = %+v", values)
	}
	for _, bad := range []string{"NOVALUE", "1BAD=x", "=x"} {
		if _, err := ParseOperatorEnv([]byte(bad)); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

func TestLoadOperatorEnvFileDoesNotOverrideShell(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.env")
	if err := os.WriteFile(path, []byte("EMP3R0R_ENV_TEST_A=file\nEMP3R0R_ENV_TEST_B=file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EMP3R0R_ENV_TEST_A", "shell")
	t.Setenv("EMP3R0R_ENV_TEST_B", "")
	if err := os.Unsetenv("EMP3R0R_ENV_TEST_B"); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadOperatorEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != 1 {
		t.Fatalf("loaded = %d", loaded)
	}
	if got := os.Getenv("EMP3R0R_ENV_TEST_A"); got != "shell" {
		t.Fatalf("shell env overridden: %q", got)
	}
	if got := os.Getenv("EMP3R0R_ENV_TEST_B"); got != "file" {
		t.Fatalf("file env not applied: %q", got)
	}
	t.Cleanup(func() { os.Unsetenv("EMP3R0R_ENV_TEST_B") })
}
