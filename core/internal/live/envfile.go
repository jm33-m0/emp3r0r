package live

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxEnvFileBytes = 64 << 10
	maxEnvFileVars  = 128
)

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// LoadOperatorEnv reads <workspace>/operator.env and adds variables that are
// not already present in the process environment. An explicit shell export
// always wins. The file is operator-owned state and should be mode 0600.
func LoadOperatorEnv() (int, error) {
	path := strings.TrimSpace(os.Getenv("EMP3R0R_OPERATOR_ENV"))
	if path == "" {
		path = filepath.Join(EmpWorkSpace, "operator.env")
	}
	return LoadOperatorEnvFile(path)
}

// LoadOperatorEnvFile is LoadOperatorEnv with an explicit path.
func LoadOperatorEnvFile(path string) (int, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("stat operator env: %w", err)
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("operator env %s is not a regular file", path)
	}
	if info.Size() > maxEnvFileBytes {
		return 0, fmt.Errorf("operator env %s exceeds %d bytes", path, maxEnvFileBytes)
	}
	if info.Mode().Perm()&0o077 != 0 {
		// Fix an accidentally world-readable env file instead of refusing to
		// start; the file contains credentials.
		if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
			return 0, fmt.Errorf("operator env %s must be 0600: %w", path, chmodErr)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read operator env: %w", err)
	}
	values, err := ParseOperatorEnv(data)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	loaded := 0
	for key, value := range values {
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return loaded, fmt.Errorf("set %s: %w", key, err)
		}
		loaded++
	}
	return loaded, nil
}

// ParseOperatorEnv parses KEY=VALUE lines. Full-line comments and an optional
// "export " prefix are accepted; values are taken literally, except for a
// matching pair of single or double quotes. Shell expansion is not performed.
func ParseOperatorEnv(data []byte) (map[string]string, error) {
	values := map[string]string{}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for lineNo, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", lineNo+1)
		}
		key = strings.TrimSpace(key)
		if !envKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("line %d: invalid variable name %q", lineNo+1, key)
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			switch {
			case value[0] == '\'' && value[len(value)-1] == '\'':
				value = value[1 : len(value)-1]
			case value[0] == '"' && value[len(value)-1] == '"':
				value = value[1 : len(value)-1]
			}
		}
		if strings.ContainsRune(value, 0) {
			return nil, fmt.Errorf("line %d: NUL byte in value", lineNo+1)
		}
		values[key] = value
		if len(values) > maxEnvFileVars {
			return nil, fmt.Errorf("more than %d variables", maxEnvFileVars)
		}
	}
	return values, nil
}
