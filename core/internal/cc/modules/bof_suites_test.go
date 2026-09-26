package modules

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// modulesRootFromTest resolves the <repo>/core/modules directory relative to
// any test file in this package (core/internal/cc/modules). It lives here,
// without a build constraint, so both the platform-neutral suite tests and the
// Windows-only BOF lifecycle tests can share it.
func modulesRootFromTest(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve caller path")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))), "modules")
}

// readSuiteConfigs loads and indexes one adopted BOF suite's manifest. It
// fails on an empty or duplicate module name so a broken manifest is reported
// before any per-module subtest runs.
func readSuiteConfigs(t *testing.T, modulesRoot, suite string) map[string]*def.ModuleConfig {
	t.Helper()
	configs, err := readModConfigs(filepath.Join(modulesRoot, suite, "config.json"))
	if err != nil {
		t.Fatalf("readModConfigs(%s): %v", suite, err)
	}
	out := make(map[string]*def.ModuleConfig, len(configs))
	for _, c := range configs {
		if c.Name == "" {
			t.Fatalf("%s has a module with an empty name", suite)
		}
		if _, dup := out[c.Name]; dup {
			t.Fatalf("%s declares duplicate module %q", suite, c.Name)
		}
		out[c.Name] = c
	}
	return out
}

// TestAdoptedBOFSuites guards the two imported third-party suites
// (C2-Tool-Collection and SQL-BOF). Manifest parsing, auto-dependency, the
// always-pack rule and required-value handling are covered generically by
// TestLoadAllModulesConfigs, TestInitModulesLoadsRepoModules,
// TestResolveInvocationCOFFArgsAlwaysSatisfied, TestReadModConfigWindowsCOFFAutoDependency
// and TestResolveInvocationMissingRequired. What only these real manifests can
// assert is:
//
//   - every declared flag is documented (no empty description), and
//   - the declaration order and default values match the order and sentinels
//     each BOF actually reads, so an edit cannot silently misalign the wire.
//
// The manifests are parsed once and shared by the subtests.
func TestAdoptedBOFSuites(t *testing.T) {
	modulesRoot := modulesRootFromTest(t)

	suites := make(map[string]map[string]*def.ModuleConfig, 2)
	for _, suite := range []string{"C2-Tool-Collection", "SQL-BOF"} {
		suites[suite] = readSuiteConfigs(t, modulesRoot, suite)
	}

	t.Run("documentation", func(t *testing.T) {
		for suite, configs := range suites {
			for name, config := range configs {
				t.Run(suite+"/"+name, func(t *testing.T) {
					if len(config.Options) == 0 {
						return
					}
					for _, opt := range config.Options {
						if strings.TrimSpace(opt.Desc) == "" {
							t.Errorf("parameter %q has no description", opt.Name)
						}
					}
				})
			}
		}
	})

	t.Run("packing", func(t *testing.T) {
		type arg struct {
			wire string
			val  string
		}
		type tc struct {
			suite, module string
			flags         map[string]string
			want          []arg
		}

		cases := []tc{
			// C2-Tool-Collection: wide strings, ints and the psx short.
			{
				suite: "C2-Tool-Collection", module: "kerbhash",
				flags: map[string]string{"password": "P@ss", "username": "jdoe", "domain": "corp.local"},
				want:  []arg{{"Z", "P@ss"}, {"Z", "jdoe"}, {"Z", "corp.local"}},
			},
			{
				suite: "C2-Tool-Collection", module: "psm",
				flags: map[string]string{"pid": "4242"},
				want:  []arg{{"i", "4242"}},
			},
			{
				suite: "C2-Tool-Collection", module: "psx",
				want: []arg{{"s", "0"}},
			},
			{
				suite: "C2-Tool-Collection", module: "psxx",
				want: []arg{{"s", "1"}},
			},
			{
				suite: "C2-Tool-Collection", module: "reconad",
				flags: map[string]string{"filter": "(&(objectClass=user))"},
				want: []arg{
					{"Z", "custom"},
					{"Z", "(&(objectClass=user))"},
					{"Z", "-all"},
					{"i", "0"},
					{"i", "0"},
					{"Z", "-noserver"},
				},
			},
			{
				suite: "C2-Tool-Collection", module: "reconad-computers",
				flags: map[string]string{"object": "*srv*"},
				want: []arg{
					{"Z", "computers"},
					{"Z", "*srv*"},
					{"Z", "-all"},
					{"i", "0"},
					{"i", "0"},
					{"Z", "-noserver"},
				},
			},
			{
				suite: "C2-Tool-Collection", module: "kerberoast",
				flags: map[string]string{"action": "list"},
				want:  []arg{{"Z", "list"}, {"Z", "*"}},
			},
			// SQL-BOF: narrow strings and the sql-clr binary blob.
			{
				suite: "SQL-BOF", module: "sql-whoami",
				flags: map[string]string{"server": "db01"},
				want:  []arg{{"z", "db01"}, {"z", ""}, {"z", ""}, {"z", ""}},
			},
			{
				suite: "SQL-BOF", module: "sql-columns",
				flags: map[string]string{"server": "db01", "table": "users"},
				want:  []arg{{"z", "db01"}, {"z", ""}, {"z", "users"}, {"z", ""}, {"z", ""}},
			},
			{
				suite: "SQL-BOF", module: "sql-adsi",
				flags: map[string]string{"server": "db01", "adsi_server": "ADSI"},
				want: []arg{
					{"z", "db01"},
					{"z", ""},
					{"z", ""},
					{"z", ""},
					{"z", "ADSI"},
					{"z", "4444"},
				},
			},
			{
				suite: "SQL-BOF", module: "sql-enablerpc",
				flags: map[string]string{"server": "db01"},
				want: []arg{
					{"z", "db01"},
					{"z", ""},
					{"z", ""},
					{"z", ""},
					{"z", "rpc"},
					{"z", "TRUE"},
				},
			},
			{
				suite: "SQL-BOF", module: "sql-disableole",
				flags: map[string]string{"server": "db01"},
				want: []arg{
					{"z", "db01"},
					{"z", ""},
					{"z", ""},
					{"z", ""},
					{"z", "Ole Automation Procedures"},
					{"z", "0"},
				},
			},
			{
				suite: "SQL-BOF", module: "sql-clr",
				flags: map[string]string{
					"server": "db01", "function": "CreateProcess",
					"hash": "ABCD", "dll": "c3FscmVjb24=",
				},
				want: []arg{
					{"z", "db01"},
					{"z", ""},
					{"z", ""},
					{"z", ""},
					{"z", "CreateProcess"},
					{"z", "ABCD"},
					{"b", "c3FscmVjb24="},
				},
			},
			{
				suite: "SQL-BOF", module: "sql-1434udp",
				flags: map[string]string{"server": "10.0.0.5"},
				want:  []arg{{"z", "10.0.0.5"}},
			},
			{
				suite: "SQL-BOF", module: "sql-smb",
				flags: map[string]string{"server": "db01", "listener": `\\10.0.0.9\share`},
				want: []arg{
					{"z", "db01"},
					{"z", ""},
					{"z", ""},
					{"z", ""},
					{"z", `\\10.0.0.9\share`},
				},
			},
		}

		for _, c := range cases {
			t.Run(c.suite+"/"+c.module, func(t *testing.T) {
				config, ok := suites[c.suite][c.module]
				if !ok {
					t.Fatalf("module %q not found in %s", c.module, c.suite)
				}
				invocation, err := resolveInvocation(config, c.flags)
				if err != nil {
					t.Fatalf("resolveInvocation: %v", err)
				}
				if invocation.Coff == nil {
					t.Fatalf("no COFF invocation")
				}
				if len(invocation.Coff.Args) != len(c.want) {
					t.Fatalf("packed %d args, want %d", len(invocation.Coff.Args), len(c.want))
				}
				for i, want := range c.want {
					got := invocation.Coff.Args[i]
					if got.WireType != want.wire {
						t.Errorf("arg %d wire type = %q, want %q", i, got.WireType, want.wire)
					}
					if gotVal := fmt.Sprint(got.Value); gotVal != want.val {
						t.Errorf("arg %d value = %q, want %q", i, gotVal, want.val)
					}
				}
			})
		}
	})

	// Required flags must reject an empty invocation instead of packing an
	// empty string; the mechanism is generic but the manifests could
	// accidentally drop a `required: true`.
	t.Run("required", func(t *testing.T) {
		for _, c := range []struct{ suite, module string }{
			{"C2-Tool-Collection", "kerbhash"},
			{"C2-Tool-Collection", "petitpotam"},
			{"C2-Tool-Collection", "findmodule"},
			{"SQL-BOF", "sql-query"},
			{"SQL-BOF", "sql-1434udp"},
			{"SQL-BOF", "sql-clr"},
		} {
			t.Run(c.suite+"/"+c.module, func(t *testing.T) {
				config, ok := suites[c.suite][c.module]
				if !ok {
					t.Fatalf("module %q not found", c.module)
				}
				if _, err := resolveInvocation(config, map[string]string{}); err == nil {
					t.Fatalf("expected required-argument error, got nil")
				}
			})
		}
	})
}
