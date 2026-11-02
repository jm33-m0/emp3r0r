package modules

import (
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestPrepareModuleParametersUsesPreparedStream(t *testing.T) {
	prev := prepareGetFileStream
	t.Cleanup(func() { prepareGetFileStream = prev })

	called := false
	prepareGetFileStream = func(string, *def.Emp3r0rAgent) (*ftp.GetFileTransfer, error) {
		called = true
		return &ftp.GetFileTransfer{Token: "new-token", Offset: 7}, nil
	}

	// The operator `get` command prepares the stream and passes the token and
	// offset as internal flags; moduleCustom must not register a second stream.
	flags := map[string]string{"path": "/tmp/a.bin", "stream": "prepared", "offset": "3"}
	done, err := prepareModuleParameters(&def.ModuleConfig{Name: ModGetFile}, &def.Emp3r0rAgent{}, flags)
	if err != nil {
		t.Fatalf("prepareModuleParameters: %v", err)
	}
	if done || called {
		t.Fatalf("prepared stream was re-registered (done=%v called=%v)", done, called)
	}
	if flags["stream"] != "prepared" || flags["offset"] != "3" {
		t.Fatalf("prepared flags changed: %v", flags)
	}
}

func TestPrepareModuleParametersRegistersStream(t *testing.T) {
	prev := prepareGetFileStream
	t.Cleanup(func() { prepareGetFileStream = prev })

	prepareGetFileStream = func(string, *def.Emp3r0rAgent) (*ftp.GetFileTransfer, error) {
		return &ftp.GetFileTransfer{Token: "token", Offset: 9}, nil
	}

	flags := map[string]string{"path": "/tmp/a.bin"}
	done, err := prepareModuleParameters(&def.ModuleConfig{Name: ModGetFile}, &def.Emp3r0rAgent{}, flags)
	if err != nil {
		t.Fatalf("prepareModuleParameters: %v", err)
	}
	if done {
		t.Fatal("a live transfer must be dispatched")
	}
	if flags["stream"] != "token" || flags["offset"] != "9" {
		t.Fatalf("stream/offset = %q/%q, want token/9", flags["stream"], flags["offset"])
	}
}
