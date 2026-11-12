package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func forbiddenPath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "mcp.json", "mcp_audit.log", "emp3r0r.log",
		"operator_audit.log", "wg_config.json", "emp3r0r.json",
		"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "authorized_keys",
		"known_hosts", "credentials", "credentials.json", "serviceaccountkey.json",
		"application_default_credentials.json", ".env", ".netrc", ".pgpass",
		".npmrc", ".pypirc", ".git-credentials", ".vault-token",
		"terraform.tfvars", "magic_string", "emp3r0r.history",
		"shadow", "gshadow", "sudoers", "master.passwd":
		return true
	}
	if strings.HasPrefix(base, "stub-") || strings.HasPrefix(base, ".env.") ||
		strings.HasPrefix(base, "id_rsa.") || strings.HasPrefix(base, "id_ed25519.") ||
		strings.HasPrefix(base, "id_ecdsa.") {
		return true
	}
	for _, ext := range []string{
		".key", ".pem", ".crt", ".p12", ".pfx", ".jks", ".keystore",
		".kdbx", ".ovpn", ".tfstate", ".age", ".gpg", ".asc",
		".log", ".history",
	} {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		switch part {
		case ".git", ".ssh", ".gnupg", ".omp", ".aws", ".azure", ".gcp",
			".kube", ".docker", ".password-store", ".module-toolchain":
			return true
		}
	}
	return false
}

// evalExisting resolves symlinks for the longest existing ancestor and
// reattaches the missing suffix.
func evalExisting(path string) (string, error) {
	var missing []string
	current := path
	for {
		if _, err := os.Lstat(current); err == nil {
			real, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", fmt.Errorf("resolve %s: %w", current, err)
			}
			for i := len(missing) - 1; i >= 0; i-- {
				real = filepath.Join(real, missing[i])
			}
			return real, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("cannot resolve %s", path)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}
