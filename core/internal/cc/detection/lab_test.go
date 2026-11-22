package detection

import "testing"

func TestDefaultSandboxURLForPlatform(t *testing.T) {
	t.Setenv("EMP3R0R_DETECTION_SANDBOX", "")
	if got := DefaultSandboxURLForPlatform("linux"); got != DefaultLinuxSandboxURL {
		t.Fatalf("linux default = %q", got)
	}
	if got := DefaultSandboxURLForPlatform("windows"); got != DefaultSandboxURL {
		t.Fatalf("windows default = %q", got)
	}
	t.Setenv("EMP3R0R_DETECTION_SANDBOX", "http://127.0.0.1:1999")
	if got := DefaultSandboxURLForPlatform("linux"); got != "http://127.0.0.1:1999" {
		t.Fatalf("environment override = %q", got)
	}
}
