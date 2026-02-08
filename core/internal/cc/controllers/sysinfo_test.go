package controllers

import (
	"testing"
)

func TestBuildSysinfoCommand(t *testing.T) {
	tests := []struct {
		name     string
		opts     SysinfoOptions
		expected string
	}{
		{
			name:     "full flag only",
			opts:     SysinfoOptions{Full: true},
			expected: "sysinfo --full",
		},
		{
			name:     "cpu flag only",
			opts:     SysinfoOptions{CPU: true},
			expected: "sysinfo --cpu",
		},
		{
			name:     "multiple flags",
			opts:     SysinfoOptions{CPU: true, Mem: true, Net: true},
			expected: "sysinfo --cpu --mem --net",
		},
		{
			name:     "all individual flags",
			opts:     SysinfoOptions{CPU: true, Mem: true, OS: true, Net: true, User: true, Container: true, Uptime: true},
			expected: "sysinfo --cpu --mem --os --net --user --container --uptime",
		},
		{
			name:     "no flags",
			opts:     SysinfoOptions{},
			expected: "sysinfo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildSysinfoCommand(tt.opts)
			if result != tt.expected {
				t.Errorf("BuildSysinfoCommand() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExecuteSysinfoCommand_NilAgent(t *testing.T) {
	opts := SysinfoOptions{Full: true}
	err := ExecuteSysinfoCommand(nil, opts, "test-session")
	if err == nil {
		t.Error("ExecuteSysinfoCommand() with nil agent should return error")
	}
	if err.Error() != "no agent specified" {
		t.Errorf("ExecuteSysinfoCommand() error = %v, want 'no agent specified'", err)
	}
}
