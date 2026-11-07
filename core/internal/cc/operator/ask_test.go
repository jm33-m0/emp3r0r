package operator

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/assistant"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/reeflective/console"
)

func TestAskCommandRegistered(t *testing.T) {
	app := console.New("test-app")
	root := Emp3r0rCommands(app)()
	cmd, _, err := root.Find([]string{"ask"})
	if err != nil {
		t.Fatalf("ask command not found: %v", err)
	}
	if cmd.Name() != "ask" {
		t.Fatalf("found %q instead of ask", cmd.Name())
	}
	for _, flag := range []string{"job", "last", "module", "reset", "model"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("ask --%s is not registered", flag)
		}
	}
}

func TestAskCommandEndToEndAgainstFakeProvider(t *testing.T) {
	var mu sync.Mutex
	var gotPath string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotPath = r.URL.Path
		gotBody = string(body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)
	}))
	defer srv.Close()

	prev := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = prev })
	askSession.Reset()
	t.Cleanup(func() { askSession.Reset() })

	cfg := fmt.Sprintf(`{"base_url":%q,"model":"test-model","api":"chat"}`, srv.URL)
	if err := os.WriteFile(assistant.ConfigPath(), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := askCmd()
	cmd.SetArgs([]string{"--module", "listener", "how do I use this?"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	askWG.Wait()
	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/chat/completions" {
		t.Fatalf("provider path = %q", gotPath)
	}
	if !strings.Contains(gotBody, "test-model") || !strings.Contains(gotBody, "listener") {
		t.Fatalf("provider request did not carry the model and module context: %s", gotBody[:min(len(gotBody), 500)])
	}
}

func TestAskCommandDoesNotBlock(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	var startedOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedOnce.Do(func() { close(started) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)
	}))
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		srv.Close()
		askWG.Wait()
	})

	prev := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = prev })
	askSession.Reset()
	t.Cleanup(func() { askSession.Reset() })

	cfg := fmt.Sprintf(`{"base_url":%q,"model":"test-model","api":"chat"}`, srv.URL)
	if err := os.WriteFile(assistant.ConfigPath(), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := askCmd()
	cmd.SetArgs([]string{"ping"})
	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ask blocked the console")
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("provider request never started")
	}
	releaseOnce.Do(func() { close(release) })
	askWG.Wait()
}

func TestAskIsTheOnlyAssistantCommand(t *testing.T) {
	app := console.New("test-app")
	root := Emp3r0rCommands(app)()
	if cmd, _, err := root.Find([]string{"ask"}); err != nil || cmd.Name() != "ask" {
		t.Fatalf("ask command not registered: %v", err)
	}
	for _, gone := range []string{"plan", "proposal", "do"} {
		if cmd, _, err := root.Find([]string{gone}); err == nil && cmd.Name() == gone {
			t.Errorf("%s should not be registered", gone)
		}
	}
}

func TestStreamPrinterWritesToOutputPane(t *testing.T) {
	var pane bytes.Buffer
	SetOutputPane(&pane)
	t.Cleanup(func() { SetOutputPane(nil) })

	p := &streamPrinter{}
	p.Write("hel")
	p.Write("lo\n")
	p.Flush()
	if got := pane.String(); got != "hello\n" {
		t.Fatalf("pane = %q", got)
	}
	if !p.Printed() {
		t.Fatal("printer reported no output")
	}

	// A complete status line must not run into a stream that is mid-line.
	p.Write("partial")
	p.Flush()
	printAssistantLine("status")
	if got := pane.String(); got != "hello\npartial\nstatus\n" {
		t.Fatalf("pane = %q", got)
	}
}
