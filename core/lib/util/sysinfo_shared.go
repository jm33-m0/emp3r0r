package util

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/sysinfo"
)

func GetMemSize() int {
	return sysinfo.GetMemSize()
}

// GetMemAvailable returns available memory in bytes
// It tries to read /proc/meminfo on Linux
func GetMemAvailable() int64 {
	if runtime.GOOS == "linux" {
		f, err := os.Open("/proc/meminfo")
		if err != nil {
			return -1
		}
		defer f.Close()

		s := bufio.NewScanner(f)
		for s.Scan() {
			line := s.Text()
			// Look for MemAvailable
			if strings.HasPrefix(line, "MemAvailable:") {
				parts := strings.Fields(line)
				if len(parts) < 2 {
					return -1
				}
				kb, err := strconv.ParseInt(parts[1], 10, 64)
				if err != nil {
					return -1
				}
				return kb * 1024
			}
		}
	}
	// Fallback or other OS
	return -1
}

func GetGPUInfo() (info string) {
	return sysinfo.GetGPUInfo()
}

func GetCPUInfo() (info string) {
	return sysinfo.GetCPUInfo()
}

func GetUsername() string {
	// user account info
	u, err := user.Current()
	if err != nil {
		logging.Debugf("GetUsername: %v", err)
		return "unknown_user"
	}
	return u.Username
}

// agentIDHexLen is the number of hex characters in a derived agent identifier.
// It is short enough to type and recognise, and wide enough (32 bits) that
// collisions are negligible for the number of agents a C2 tracks at once.
const agentIDHexLen = 8

// GenAgentTag derives the operator-facing agent identifier (the unified "tag"
// and "id") from the agent's UUID alone. Callers on the C2 side must pass the
// cryptographically verified UUID, never agent-reported metadata: the result is
// then a fixed-length lowercase hex string, safe to render on hostile-sensitive
// surfaces such as tmux window names and status lines.
func GenAgentTag(agentUUID string) string {
	if agentUUID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(agentUUID))
	return hex.EncodeToString(sum[:])[:agentIDHexLen]
}

// IsAgentID reports whether s is a well-formed derived agent identifier. The
// identifier is always lowercase hex, so any other byte (tmux format syntax,
// control characters, shell metacharacters) is rejected. Use this as
// defense-in-depth before handing an identifier to a shell-adjacent renderer.
func IsAgentID(s string) bool {
	if len(s) != agentIDHexLen {
		return false
	}
	for i := range s {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// AgentRef formats an agent identity for logs as "<tag> (<uuid>)" so every
// message that names an agent also names the short identifier an operator can
// type (e.g. `target <tag>` or `forget_agent <tag>`). Because the tag is
// derived from the UUID, callers only need the UUID. Anything that does not
// parse as a UUID (for example an already-resolved tag) is returned verbatim
// instead of being hashed into a misleading tag.
func AgentRef(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "<unknown>"
	}
	parsed, err := uuid.Parse(id)
	if err != nil {
		return id
	}
	canonical := parsed.String()
	return GenAgentTag(canonical) + " (" + canonical + ")"
}

// FormatUptime converts seconds to human readable string (d h m s)
func FormatUptime(seconds int64) string {
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	secs := seconds % 60
	return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, secs)
}
