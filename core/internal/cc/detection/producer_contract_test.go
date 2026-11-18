package detection

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func TestCrystalPackPICOEditRequiresContract(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"README.md", "postex-loader/loader.spec", "postex-loader/src/loader.c"} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		body := "old\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	roots, err := newSourceRoots("loader_windows",
		sourceRoot{Name: "crystal_pack", Dir: dir, Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	e := &evolver{
		cfg:   EvolveConfig{LoopID: "loop", Module: "loader_windows", Iterations: 10},
		db:    db,
		roots: roots,
		logf:  func(logging.Class, string, ...any) {},
	}
	raw, err := json.Marshal(map[string]any{
		"module": "crystal_pack", "file": "postex-loader/src/loader.c",
		"old_string": "old", "new_string": "new",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := e.editSourceTool().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("a PICO edit was accepted before the contract was read")
	}
	if got := result.Flatten(); !strings.Contains(got, "SourceRead module=crystal_pack path=README.md") ||
		!strings.Contains(got, "postex-loader/loader.spec") {
		t.Fatalf("missing prerequisite was not named: %s", got)
	}

	e.producerReads.Store("crystal_pack|readme.md", struct{}{})
	e.producerReads.Store("crystal_pack|postex-loader/loader.spec", struct{}{})
	result, err = e.editSourceTool().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("edit failed after the contract was read: %s", result.Flatten())
	}
}

func TestCrystalPalaceQuery(t *testing.T) {
	for _, query := range []string{
		"Crystal Palace PICO postex loader resource markers",
		"crystal_pack pico resources",
	} {
		if !crystalPalaceQuery(query) {
			t.Fatalf("query %q was not recognised", query)
		}
	}
	for _, query := range []string{"module stomping pe-sieve", "crystal clear EDR"} {
		if crystalPalaceQuery(query) {
			t.Fatalf("query %q was wrongly recognised", query)
		}
	}
}
