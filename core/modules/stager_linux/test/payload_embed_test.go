//go:build linux

package shellcode_stager

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEmbedPayloadHeader checks the local-payload generator: random key and
// identifiers, the normal .rodata section, and a payload length that matches.
func TestEmbedPayloadHeader(t *testing.T) {
	payload := bytes.Repeat([]byte{0x41, 0x9c, 0x00, 0xff}, 4096)
	dir := t.TempDir()
	payloadPath := filepath.Join(dir, "agent.pic")
	if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	generate := func(name string) string {
		out := filepath.Join(dir, name)
		cmd := exec.Command("python3", filepath.Join("..", "embed_payload.py"), payloadPath, out)
		if got, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("embed_payload.py: %v\n%s", err, got)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(data)
	}

	a := generate("a.h")
	b := generate("b.h")
	if a == b {
		t.Fatal("two builds produced identical headers; randomisation is not working")
	}
	for _, want := range []string{
		"STAGER_LOCAL_PAYLOAD_LEN 16384u",
		`section(".rodata")`,
	} {
		if !strings.Contains(a, want) {
			t.Fatalf("header missing %q:\n%s", want, a)
		}
	}
	if strings.Contains(a, `.rodata.`) {
		t.Fatal("payload uses a distinctive sub-section instead of normal .rodata")
	}
}
