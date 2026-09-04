package gui

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestParseLastGuiRun makes sure the log scanner finds the newest running GUI
// daemon's URL + pid (used by ReattachIfRunning).
func TestParseLastGuiRun(t *testing.T) {
	log := "" +
		"2026/09/04 21:17:40 GUI server listening on http://127.0.0.1:38875/?token=aaaa, opening browser\n" +
		"2026/09/04 21:17:40 GUI waiting for operator session (pid 1111)\n" +
		"2026/09/04 21:17:41 console session: EMP3R0R_CONSOLE.Start() invoked\n" +
		"2026/09/05 09:00:00 GUI server listening on http://127.0.0.1:40123/?token=bbbb, opening browser\n" +
		"2026/09/05 09:00:01 GUI waiting for operator session (pid 2222)\n"
	url, pid, ok := parseLastGuiRun(log)
	if !ok || pid != 2222 || url != "http://127.0.0.1:40123/?token=bbbb" {
		t.Fatalf("got url=%q pid=%d ok=%v", url, pid, ok)
	}
}

// TestGuiSavedSessionRoundtrip exercises save -> load -> clear of the session
// credentials file.
func TestGuiSavedSessionRoundtrip(t *testing.T) {
	// point the session file somewhere temporary
	orig := sessionFilePathOverride
	tmp := filepath.Join(t.TempDir(), "gui_session.json")
	sessionFilePathOverride = func() string { return tmp }
	defer func() { sessionFilePathOverride = orig }()

	creds := Creds{
		C2Host:        "10.0.0.1",
		OperatorPort:  13377,
		ServerWgKey:   "SGF2ZSBmdW4gZW1wM3IwciB0b2RheSEhISE=",
		ServerWgIP:    "10.9.9.1",
		OperatorWgIP:  "10.9.9.2",
		OperatorWgKey: "a2VlcCB0aGlzIHNlY3JldCBzYWZlISEhISEh",
	}
	guiSaveSessionCreds(creds)

	got, ok := guiLoadSessionCreds()
	if !ok {
		t.Fatal("expected a saved session")
	}
	if got.C2Host != creds.C2Host || got.ServerWgIP != creds.ServerWgIP {
		t.Fatalf("creds mismatch: %+v", got)
	}
	if st, err := os.Stat(tmp); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("session file perms: mode=%v err=%v", st.Mode().Perm(), err)
	}

	ClearSession()
	if _, ok := guiLoadSessionCreds(); ok {
		t.Fatal("session should be cleared")
	}
	_ = time.Now()
}
