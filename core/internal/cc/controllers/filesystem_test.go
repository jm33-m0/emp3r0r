package controllers

import (
	"testing"
)

func TestBuildLsCommand(t *testing.T) {
	result := BuildLsCommand("/tmp")
	expected := "ls --dst '/tmp'"
	if result != expected {
		t.Errorf("BuildLsCommand() = %v, want %v", result, expected)
	}
}

func TestBuildCatCommand(t *testing.T) {
	result := BuildCatCommand("/etc/passwd")
	expected := "cat --dst '/etc/passwd'"
	if result != expected {
		t.Errorf("BuildCatCommand() = %v, want %v", result, expected)
	}
}

func TestBuildCpCommand(t *testing.T) {
	result := BuildCpCommand("/tmp/src", "/tmp/dst")
	expected := "cp --src '/tmp/src' --dst '/tmp/dst'"
	if result != expected {
		t.Errorf("BuildCpCommand() = %v, want %v", result, expected)
	}
}

func TestBuildRmCommand(t *testing.T) {
	result := BuildRmCommand("/tmp/file")
	expected := "rm --dst '/tmp/file'"
	if result != expected {
		t.Errorf("BuildRmCommand() = %v, want %v", result, expected)
	}
}

func TestBuildMkdirCommand(t *testing.T) {
	result := BuildMkdirCommand("/tmp/newdir")
	expected := "mkdir --dst '/tmp/newdir'"
	if result != expected {
		t.Errorf("BuildMkdirCommand() = %v, want %v", result, expected)
	}
}

func TestBuildMvCommand(t *testing.T) {
	result := BuildMvCommand("/tmp/src", "/tmp/dst")
	expected := "mv --src '/tmp/src' --dst '/tmp/dst'"
	if result != expected {
		t.Errorf("BuildMvCommand() = %v, want %v", result, expected)
	}
}

func TestBuildPwdCommand(t *testing.T) {
	result := BuildPwdCommand()
	expected := "pwd"
	if result != expected {
		t.Errorf("BuildPwdCommand() = %v, want %v", result, expected)
	}
}

func TestBuildCdCommand(t *testing.T) {
	result := BuildCdCommand("/tmp")
	expected := "cd --dst /tmp"
	if result != expected {
		t.Errorf("BuildCdCommand() = %v, want %v", result, expected)
	}
}

func TestBuildPsCommand(t *testing.T) {
	tests := []struct {
		name     string
		pid      int
		user     string
		procName string
		cmdline  string
		expected string
	}{
		{
			name:     "no filters",
			expected: "ps",
		},
		{
			name:     "pid only",
			pid:      1234,
			expected: "ps --pid 1234",
		},
		{
			name:     "user only",
			user:     "root",
			expected: "ps --user root",
		},
		{
			name:     "name only",
			procName: "nginx",
			expected: "ps --name nginx",
		},
		{
			name:     "cmdline only",
			cmdline:  "python",
			expected: "ps --cmdline python",
		},
		{
			name:     "all filters",
			pid:      1234,
			user:     "root",
			procName: "nginx",
			cmdline:  "python",
			expected: "ps --pid 1234 --user root --name nginx --cmdline python",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildPsCommand(tt.pid, tt.user, tt.procName, tt.cmdline)
			if result != tt.expected {
				t.Errorf("BuildPsCommand() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestBuildKillCommand(t *testing.T) {
	tests := []struct {
		name      string
		pids      []int
		expected  string
		expectErr bool
	}{
		{
			name:     "single pid",
			pids:     []int{1234},
			expected: "kill 1234",
		},
		{
			name:     "multiple pids",
			pids:     []int{1234, 5678, 9012},
			expected: "kill 1234 5678 9012",
		},
		{
			name:      "no pids",
			pids:      []int{},
			expectErr: true,
		},
		{
			name:      "invalid pid (zero)",
			pids:      []int{0},
			expectErr: true,
		},
		{
			name:      "invalid pid (negative)",
			pids:      []int{-1},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := BuildKillCommand(tt.pids)
			if tt.expectErr {
				if err == nil {
					t.Errorf("BuildKillCommand() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("BuildKillCommand() unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("BuildKillCommand() = %v, want %v", result, tt.expected)
				}
			}
		})
	}
}

func TestBuildNetHelperCommand(t *testing.T) {
	result := BuildNetHelperCommand()
	expected := "net_helper"
	if result != expected {
		t.Errorf("BuildNetHelperCommand() = %v, want %v", result, expected)
	}
}

func TestBuildSuicideCommand(t *testing.T) {
	result := BuildSuicideCommand()
	expected := "suicide"
	if result != expected {
		t.Errorf("BuildSuicideCommand() = %v, want %v", result, expected)
	}
}

func TestExecuteAgentCommand_NilAgent(t *testing.T) {
	err := ExecuteAgentCommand(nil, "ls", "test-session")
	if err == nil {
		t.Error("ExecuteAgentCommand() with nil agent should return error")
	}
	if err.Error() != "no agent specified" {
		t.Errorf("ExecuteAgentCommand() error = %v, want 'no agent specified'", err)
	}
}
