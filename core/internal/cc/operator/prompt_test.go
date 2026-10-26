package operator

import (
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

func TestPromptAgentUser(t *testing.T) {
	cases := []struct {
		name  string
		agent *def.Emp3r0rAgent
		want  string
	}{
		{
			name:  "linux user metadata",
			agent: &def.Emp3r0rAgent{User: "alice (/home/alice), uid=1000, gid=1000"},
			want:  "alice",
		},
		{
			name:  "windows domain user",
			agent: &def.Emp3r0rAgent{User: `CORP\alice (C:\Users\alice), uid=1000, gid=1000`},
			want:  `CORP\alice`,
		},
		{
			name:  "fallback to Name",
			agent: &def.Emp3r0rAgent{User: "Not available", Name: "srv/bob"},
			want:  "bob",
		},
		{
			name:  "fallback keeps domain",
			agent: &def.Emp3r0rAgent{User: "", Name: "srv/CORP/bob"},
			want:  "CORP/bob",
		},
		{
			name:  "hostile metadata is sanitized",
			agent: &def.Emp3r0rAgent{User: "\x1b]0;title\x07CORP\\alice\nroot"},
			want:  `CORP\alice`,
		},
		{
			name:  "empty metadata",
			agent: &def.Emp3r0rAgent{},
			want:  promptUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := promptAgentUser(tc.agent)
			if got != tc.want {
				t.Fatalf("promptAgentUser() = %q, want %q", got, tc.want)
			}
			if strings.ContainsAny(got, "\x1b\n\r\x00") {
				t.Fatalf("promptAgentUser() left control characters: %q", got)
			}
		})
	}
}

func TestPromptAgentHost(t *testing.T) {
	cases := []struct {
		name  string
		agent *def.Emp3r0rAgent
		want  string
	}{
		{name: "hostname", agent: &def.Emp3r0rAgent{Hostname: "workstation"}, want: "workstation"},
		{name: "fallback to Name", agent: &def.Emp3r0rAgent{Name: "srv/CORP/alice"}, want: "srv"},
		{name: "hostile hostname", agent: &def.Emp3r0rAgent{Hostname: "\x1b[31mworkstation\x1b[0m\nx"}, want: "workstation x"},
		{name: "empty", agent: &def.Emp3r0rAgent{}, want: promptUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := promptAgentHost(tc.agent)
			if got != tc.want {
				t.Fatalf("promptAgentHost() = %q, want %q", got, tc.want)
			}
			if strings.ContainsAny(got, "\x1b\n\r\x00") {
				t.Fatalf("promptAgentHost() left control characters: %q", got)
			}
		})
	}
}

func TestPromptAgentCWD(t *testing.T) {
	cases := []struct {
		name  string
		agent *def.Emp3r0rAgent
		want  string
	}{
		{name: "unix cwd", agent: &def.Emp3r0rAgent{CWD: "/tmp/work"}, want: "/tmp/work"},
		{name: "windows cwd", agent: &def.Emp3r0rAgent{CWD: `C:\Users\alice`}, want: `C:\Users\alice`},
		{
			name:  "hostile cwd",
			agent: &def.Emp3r0rAgent{CWD: "/tmp/\x1b[31mred\x1b[0m\nmore"},
			want:  "/tmp/red more",
		},
		{name: "empty", agent: &def.Emp3r0rAgent{}, want: promptUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := promptAgentCWD(tc.agent)
			if got != tc.want {
				t.Fatalf("promptAgentCWD() = %q, want %q", got, tc.want)
			}
			if strings.ContainsAny(got, "\x1b\n\r\x00") {
				t.Fatalf("promptAgentCWD() left control characters: %q", got)
			}
		})
	}
}

func TestPromptAgentTag(t *testing.T) {
	if got := promptAgentTag(&def.Emp3r0rAgent{Tag: "deadbeef"}); got != "deadbeef" {
		t.Fatalf("promptAgentTag(valid) = %q", got)
	}
	for _, tag := range []string{"", "DEADBEEF", "not-a-tag", "\x1b[31mdeadbeef"} {
		if got := promptAgentTag(&def.Emp3r0rAgent{Tag: tag}); got != promptUnknown {
			t.Fatalf("promptAgentTag(%q) = %q, want %q", tag, got, promptUnknown)
		}
	}
}

func TestPromptAgentIdentityIsTerminalSafe(t *testing.T) {
	agent := &def.Emp3r0rAgent{
		Tag:      "deadbeef",
		User:     "\x1b]0;title\x07CORP\\alice\nroot",
		Hostname: "\x1b[2Jworkstation",
		CWD:      "/tmp/\x1b[31mred\x07",
	}
	user, host, cwd := promptAgentIdentity(agent)
	for _, value := range []string{user, host, cwd} {
		if strings.ContainsAny(value, "\x1b\n\r\x00") {
			t.Fatalf("identity component contains control characters: %q", value)
		}
	}
	if got := user + "@" + host + ":" + cwd; !strings.Contains(got, "CORP\\alice@workstation:/tmp/red") {
		t.Fatalf("unexpected sanitized identity: %q", got)
	}
}

func TestSetDynamicPromptIncludesTargetIdentity(t *testing.T) {
	previous := live.GetActiveAgent()
	t.Cleanup(func() { live.SetActiveAgent(previous) })

	live.SetActiveAgent(&def.Emp3r0rAgent{
		Tag:       "deadbeef",
		User:      `CORP\alice (C:\Users\alice), uid=1000, gid=1000`,
		Hostname:  "workstation",
		CWD:       "/tmp/\x1b[31mwork\x1b[0m",
		Transport: "HTTP2",
	})

	// Strip our own colour codes so the assertion is about the rendered text,
	// not the prompt styling. Any agent-supplied escape would already have
	// been removed by promptClean.
	rendered := sanitize.SanitizeText(SetDynamicPrompt())
	want := `@deadbeef CORP\alice@workstation:/tmp/work`
	if !strings.Contains(rendered, want) {
		t.Fatalf("SetDynamicPrompt() = %q, want it to contain %q", rendered, want)
	}
	if strings.ContainsRune(rendered, '\x1b') {
		t.Fatalf("prompt retained an agent-supplied escape: %q", rendered)
	}
}
