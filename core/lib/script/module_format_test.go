package script

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.starlark.net/syntax"
)

// moduleFormatNeedsSprintf reports whether a Starlark "%" format string uses a
// conversion the built-in % operator cannot render. go.starlark.net's string
// interpolation only accepts a bare conversion char (%s, %d, %x, ...), so any
// flag/width/precision (%-20s, %5d, %+x, %.*f) fails at runtime with "unknown
// conversion". Those must go through sprintf, which uses Go fmt.
func moduleFormatNeedsSprintf(format string) bool {
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		if i+1 >= len(format) {
			return true
		}
		switch format[i+1] {
		case 's', 'd', 'i', 'o', 'x', 'X', 'e', 'f', 'g', 'E', 'F', 'G', 'c', '%':
			i++ // consume the conversion char
		default:
			return true // flag/width/precision: % operator rejects it
		}
	}
	return false
}

// TestStarlarkModulesUseSprintfForFormatting scans every shipped script and
// rejects "%" operator interpolations that need sprintf, so the runtime
// "unknown conversion %-" failure cannot come back.
func TestStarlarkModulesUseSprintfForFormatting(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	modulesDir := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filename))), "modules")

	var starFiles int
	err := filepath.Walk(modulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".star") {
			return nil
		}
		starFiles++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		file, err := syntax.Parse(info.Name(), data, 0)
		if err != nil {
			return err
		}
		syntax.Walk(file, func(n syntax.Node) bool {
			bin, ok := n.(*syntax.BinaryExpr)
			if !ok || bin.Op != syntax.PERCENT {
				return true
			}
			lit, ok := bin.X.(*syntax.Literal)
			if !ok || lit.Token != syntax.STRING {
				return true
			}
			format, ok := lit.Value.(string)
			if !ok || !moduleFormatNeedsSprintf(format) {
				return true
			}
			start, _ := bin.Span()
			t.Errorf("%s:%d: use sprintf for %q, the %% operator cannot render flags/width", path, start.Line, format)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", modulesDir, err)
	}
	if starFiles == 0 {
		t.Fatalf("no .star files found under %s", modulesDir)
	}
}
