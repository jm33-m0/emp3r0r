package detection

import (
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestParseProducerDirsResolvesBareInstalledName(t *testing.T) {
	dir := t.TempDir()
	previous, hadPrevious := def.Modules.Load("crystal_pack")
	def.Modules.Store("crystal_pack", &def.ModuleConfig{Name: "crystal_pack", Path: dir})
	t.Cleanup(func() {
		if hadPrevious {
			def.Modules.Store("crystal_pack", previous)
			return
		}
		def.Modules.Delete("crystal_pack")
	})

	got, err := ParseProducerDirs([]string{"crystal_pack"})
	if err != nil {
		t.Fatal(err)
	}
	if got["crystal_pack"] != dir {
		t.Fatalf("crystal_pack dir = %q, want %q", got["crystal_pack"], dir)
	}
}

func TestParseProducerDirsRejectsUnknownBareName(t *testing.T) {
	if _, err := ParseProducerDirs([]string{"not_installed"}); err == nil {
		t.Fatal("an unknown bare producer name was accepted")
	}
}

func TestParseProducerDirsKeepsExplicitDir(t *testing.T) {
	got, err := ParseProducerDirs([]string{"donut=/opt/donut"})
	if err != nil {
		t.Fatal(err)
	}
	if got["donut"] != "/opt/donut" {
		t.Fatalf("donut dir = %q, want /opt/donut", got["donut"])
	}
}
