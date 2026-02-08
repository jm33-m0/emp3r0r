package controllers

import (
	"errors"
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// StartInteractiveShell prepares the environment for an interactive shell session
// and returns the SSH connection string.
// It does NOT open a window - that's the responsibility of the UI layer.
//
// Returns: (connectionString, error)
// Example: "ssh -p 12345 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no 127.0.0.1"
func StartInteractiveShell(ctx *context.C2Context) (string, error) {
	// Validate target exists
	if ctx.Target == nil {
		return "", errors.New("no target agent selected")
	}

	// Extract options from context
	shellOpt, ok := ctx.Flags["shell"]
	if !ok {
		return "", errors.New("option 'shell' not found")
	}

	argsOpt, ok := ctx.Flags["args"]
	if !ok {
		return "", errors.New("option 'args' not found")
	}

	portOpt, ok := ctx.Flags["port"]
	if !ok {
		return "", errors.New("option 'port' not found")
	}

	// Call the module (the "tool") to set up SSH and get connection string
	connStr, err := modules.SSHClient(shellOpt, argsOpt, portOpt)
	if err != nil {
		return "", fmt.Errorf("failed to start SSH client: %w", err)
	}

	return connStr, nil
}

// StartFileManager prepares the environment for an SFTP file manager session
// and returns the SFTP connection string.
//
// Returns: (connectionString, error)
func StartFileManager(ctx *context.C2Context) (string, error) {
	// Validate target exists
	if ctx.Target == nil {
		return "", errors.New("no target agent selected")
	}

	// SFTP uses the default SSHD shell port
	connStr, err := modules.SSHClient("sftp", "", live.RuntimeConfig.SSHDShellPort)
	if err != nil {
		return "", fmt.Errorf("failed to start SFTP client: %w", err)
	}

	return connStr, nil
}
