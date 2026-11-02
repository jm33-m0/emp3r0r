package modules

import (
	"reflect"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestParseGetFileListing(t *testing.T) {
	out := "get_file: 3 file(s) in /var/log\n" +
		"/var/log/a.log\n" +
		" /var/log/b.log \r\n" +
		"get_file: 3 file(s) in /var/log\n" +
		"/var/log/a.log\n" +
		"memfs:///c.log\n"
	got := parseGetFileListing(out)
	want := []string{"/var/log/a.log", "/var/log/b.log", "memfs:///c.log"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseGetFileListing = %v, want %v", got, want)
	}

	if files := parseGetFileListing("get_file: 0 file(s) in /empty\n"); len(files) != 0 {
		t.Fatalf("empty listing parsed as %v", files)
	}
}

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

func TestCanRunGetFileModule(t *testing.T) {
	cases := []struct {
		name   string
		target *def.Emp3r0rAgent
		want   bool
	}{
		{"c agent amd64", &def.Emp3r0rAgent{GOOS: "linux", GOArch: "amd64", AgentImpl: "c"}, true},
		{"c agent x86_64 kernel arch", &def.Emp3r0rAgent{GOOS: "linux", Arch: "x86_64", AgentImpl: "C"}, true},
		{"c agent arm64", &def.Emp3r0rAgent{GOOS: "linux", GOArch: "arm64", AgentImpl: "c"}, false},
		{"go agent amd64", &def.Emp3r0rAgent{GOOS: "linux", GOArch: "amd64", AgentImpl: "go"}, false},
		{"old agent without impl", &def.Emp3r0rAgent{GOOS: "linux", GOArch: "amd64"}, false},
		{"windows c agent", &def.Emp3r0rAgent{GOOS: "windows", GOArch: "amd64", AgentImpl: "c"}, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := canRunGetFileModule(tc.target); got != tc.want {
				t.Fatalf("canRunGetFileModule = %v, want %v", got, tc.want)
			}
		})
	}
}
