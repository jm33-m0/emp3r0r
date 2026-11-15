package operator

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestReadLoopSummaryPrefersSummaryFile(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "loop.md")
	if err := os.WriteFile(reportPath, []byte("# Full\n\n## Outcome\n\nlong\n\n## Cycles\n\n| # |\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "loop-summary.md"), []byte("# Summary\n\nshort\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, source := readLoopSummary(reportPath)
	if got != "# Summary\n\nshort\n" || source != filepath.Join(dir, "loop-summary.md") {
		t.Fatalf("unexpected summary: %q from %q", got, source)
	}
}

func TestReadLoopSummaryFallsBackBeforeCycleTable(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "loop.md")
	body := "# Full\n\n## Outcome\n\nlong\n\n## Cycles\n\n| # |\n"
	if err := os.WriteFile(reportPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, source := readLoopSummary(reportPath)
	if source != reportPath {
		t.Fatalf("fallback source = %q, want %q", source, reportPath)
	}
	if strings.Contains(got, "## Cycles") || !strings.Contains(got, "## Outcome") {
		t.Fatalf("fallback kept the cycle table or lost the outcome:\n%s", got)
	}
}

func TestKnowledgeSyncArgsUsesResolvedCachePath(t *testing.T) {
	oldWorkspace := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = oldWorkspace })

	cmd := KnowledgeSyncCmd()
	if err := cmd.Flags().Set("notebook", "maldev"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("content", "true"); err != nil {
		t.Fatal(err)
	}
	got := knowledgeSyncArgs(cmd)
	want := []string{
		"knowledge-sync",
		"--url", "https://archeotech.r00ted.ch/mcp",
		"--db", filepath.Join(live.EmpWorkSpace, "detection", "knowledge.db"),
		"--notebook", "maldev",
		"--content",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestChooseShellcodeProducerUsesDonutForAuto(t *testing.T) {
	donutDir := t.TempDir()
	producers := map[string]string{
		"crystal_pack": crystalPackFixture(t),
		"donut":        donutDir,
	}
	producer, gotDir, agentType := chooseShellcodeProducer(producers, "auto")
	if producer != "donut" || gotDir != donutDir || agentType != builder.PayloadTypeWindowsExecutable {
		t.Fatalf("auto = %q %q %q, want donut with an EXE", producer, gotDir, agentType)
	}
}

func TestChooseShellcodeProducerUsesCrystalPalaceWhenDonutIsMissing(t *testing.T) {
	dir := crystalPackFixture(t)
	producers := map[string]string{"crystal_pack": dir}
	producer, gotDir, agentType := chooseShellcodeProducer(producers, "auto")
	if producer != "crystal_pack" || gotDir != dir || agentType != builder.PayloadTypeWindowsDLL {
		t.Fatalf("auto = %q %q %q, want crystal_pack with a DLL", producer, gotDir, agentType)
	}
}

func TestChooseShellcodeProducerFallsBackWhenCrystalPalaceIsMissing(t *testing.T) {
	donutDir := t.TempDir()
	producers := map[string]string{"donut": donutDir}
	producer, gotDir, agentType := chooseShellcodeProducer(producers, "auto")
	if producer != "donut" || gotDir != donutDir || agentType != builder.PayloadTypeWindowsExecutable {
		t.Fatalf("auto = %q %q %q, want donut with an EXE", producer, gotDir, agentType)
	}
}

func TestChooseShellcodeProducerHonorsExplicitAgentType(t *testing.T) {
	crystalDir := crystalPackFixture(t)
	donutDir := t.TempDir()
	producers := map[string]string{
		"crystal_pack": crystalDir,
		"donut":        donutDir,
	}
	producer, _, agentType := chooseShellcodeProducer(producers, builder.PayloadTypeWindowsExecutable)
	if producer != "donut" || agentType != builder.PayloadTypeWindowsExecutable {
		t.Fatalf("explicit EXE = %q %q, want donut with an EXE", producer, agentType)
	}
	producer, _, agentType = chooseShellcodeProducer(producers, builder.PayloadTypeWindowsDLL)
	if producer != "crystal_pack" || agentType != builder.PayloadTypeWindowsDLL {
		t.Fatalf("explicit DLL = %q %q, want crystal_pack with a DLL", producer, agentType)
	}
}

func TestChooseShellcodeProducerRejectsNoProducer(t *testing.T) {
	producer, _, _ := chooseShellcodeProducer(nil, "auto")
	if producer != "" {
		t.Fatalf("producer = %q, want none", producer)
	}
}

func crystalPackFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	jar := filepath.Join(dir, "crystalpalace", "crystalpalace.jar")
	if err := os.MkdirAll(filepath.Dir(jar), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jar, []byte("jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := filepath.Join(dir, "postex-loader", "loader.spec")
	if err := os.MkdirAll(filepath.Dir(spec), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spec, []byte("spec"), 0o600); err != nil {
		t.Fatal(err)
	}
	libtcg := filepath.Join(dir, "libtcg.x64.zip")
	if err := os.WriteFile(libtcg, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	java := filepath.Join(dir, "java")
	if err := os.WriteFile(java, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JAVA", java)
	t.Setenv("CC_64", "sh -c")
	t.Setenv("NASM", "/bin/sh")
	return dir
}
