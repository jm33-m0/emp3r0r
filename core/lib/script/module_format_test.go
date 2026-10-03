package script

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.starlark.net/syntax"
)

// stringLiteral reports whether e is a string literal, possibly parenthesized.
func stringLiteral(e syntax.Expr) bool {
	switch x := e.(type) {
	case *syntax.Literal:
		return x.Token == syntax.STRING
	case *syntax.ParenExpr:
		return stringLiteral(x.X)
	}
	return false
}

// TestStarlarkModulesUseSprintfForFormatting rejects the "%" string operator in
// every shipped script. go.starlark.net's interpolation is a limited duplicate
// of sprintf: it rejects flags/width such as %-20s and aborts the whole script,
// so modules must format with sprintf (Go fmt). Modulo (%) on numbers is not
// flagged.
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
			if !ok || bin.Op != syntax.PERCENT || !stringLiteral(bin.X) {
				return true
			}
			start, _ := bin.Span()
			t.Errorf("%s:%d: use sprintf instead of the %% string operator", path, start.Line)
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
