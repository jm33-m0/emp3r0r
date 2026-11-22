package detection

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LabConfig is one sandbox endpoint. The Windows and Linux entries coexist;
// selecting a payload module selects the matching entry.
type LabConfig struct {
	URL                 string `json:"url"`
	GuestSSH            string `json:"guest_ssh,omitempty"`
	GuestSSHKey         string `json:"guest_ssh_key,omitempty"`
	GuestSSHExclude     string `json:"guest_ssh_exclude,omitempty"`
	GuestSSHKnownHosts  string `json:"guest_ssh_known_hosts,omitempty"`
	GuestSSHFingerprint string `json:"guest_ssh_fingerprint,omitempty"`
	GuestSSHInsecure    bool   `json:"guest_ssh_insecure,omitempty"`
}

// LabsConfig keeps both platform labs in one operator-controlled file. A
// missing file or field receives the local default, not a disabled lab.
type LabsConfig struct {
	Windows LabConfig `json:"windows"`
	Linux   LabConfig `json:"linux"`
}

// DefaultLabs returns the two local lab endpoints. Linux uses its SSH tunnel
// port; Windows uses the LitterBox port. EMP3R0R_DETECTION_SANDBOX remains a
// legacy global override.
func DefaultLabs() LabsConfig {
	labs := LabsConfig{
		Windows: LabConfig{URL: DefaultSandboxURL},
		Linux:   LabConfig{URL: DefaultLinuxSandboxURL},
	}
	if value := strings.TrimSpace(os.Getenv("EMP3R0R_DETECTION_SANDBOX")); value != "" {
		labs.Windows.URL = value
		labs.Linux.URL = value
	}
	return labs
}

// LabsPath returns the configured labs file. EMP3R0R_DETECTION_LABS wins;
// otherwise the file lives under the operator detection directory.
func LabsPath(storeRoot string) string {
	if value := strings.TrimSpace(os.Getenv("EMP3R0R_DETECTION_LABS")); value != "" {
		return ExpandHomePath(value)
	}
	if strings.TrimSpace(storeRoot) == "" {
		return ""
	}
	return filepath.Join(storeRoot, "labs.json")
}

// LoadLabs reads both lab entries and fills missing fields from the defaults.
// A missing file is normal; a malformed file is an operator error.
func LoadLabs(storeRoot string) (LabsConfig, error) {
	labs := DefaultLabs()
	path := LabsPath(storeRoot)
	if path == "" {
		return labs, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return labs, nil
		}
		return LabsConfig{}, fmt.Errorf("read labs file %s: %w", path, err)
	}
	var overlay LabsConfig
	if err := json.Unmarshal(data, &overlay); err != nil {
		return LabsConfig{}, fmt.Errorf("decode labs file %s: %w", path, err)
	}
	merge := func(dst *LabConfig, src LabConfig) {
		if strings.TrimSpace(src.URL) != "" {
			dst.URL = strings.TrimSpace(src.URL)
		}
		if src.GuestSSH != "" {
			dst.GuestSSH = src.GuestSSH
		}
		if src.GuestSSHKey != "" {
			dst.GuestSSHKey = src.GuestSSHKey
		}
		if src.GuestSSHExclude != "" {
			dst.GuestSSHExclude = src.GuestSSHExclude
		}
		if src.GuestSSHKnownHosts != "" {
			dst.GuestSSHKnownHosts = src.GuestSSHKnownHosts
		}
		if src.GuestSSHFingerprint != "" {
			dst.GuestSSHFingerprint = src.GuestSSHFingerprint
		}
		if src.GuestSSHInsecure {
			dst.GuestSSHInsecure = true
		}
	}
	merge(&labs.Windows, overlay.Windows)
	merge(&labs.Linux, overlay.Linux)
	return labs, nil
}

func (l LabsConfig) ForPlatform(platform string) LabConfig {
	if strings.EqualFold(strings.TrimSpace(platform), "linux") {
		return l.Linux
	}
	return l.Windows
}

// GuestConfig converts a lab entry into the guest debugger configuration for
// the selected platform. An entry without guest SSH returns nil.
func (l LabConfig) GuestConfig(platform string) (*GuestSSHConfig, error) {
	endpoint := strings.TrimSpace(l.GuestSSH)
	key := strings.TrimSpace(l.GuestSSHKey)
	if endpoint == "" && key == "" {
		return nil, nil
	}
	if endpoint == "" || key == "" {
		return nil, fmt.Errorf("guest SSH requires both guest_ssh and guest_ssh_key in labs.json")
	}
	user, host, port, err := ParseGuestSSHEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	return &GuestSSHConfig{
		Platform: platform, Host: host, Port: port, User: user, KeyPath: ExpandHomePath(key),
		ExcludePath:    strings.TrimSpace(l.GuestSSHExclude),
		KnownHostsPath: ExpandHomePath(l.GuestSSHKnownHosts),
		Fingerprint:    strings.TrimSpace(l.GuestSSHFingerprint),
		Insecure:       l.GuestSSHInsecure,
	}, nil
}
