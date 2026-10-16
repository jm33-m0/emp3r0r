package cagent

import (
	"strings"
	"testing"
)

func TestEmbeddedConfigSource(t *testing.T) {
	// Bytes that would break any C string literal: NUL, DEL, high byte,
	// newline, double quote and backslash.
	blob := []byte{0x00, 0x7f, 0xff, 'a', '\n', '"', '\\'}
	src := string(EmbeddedConfigSource(blob, "magic", "1.2.3"))

	for _, want := range []string{
		"#include \"embedded_config.h\"",
		"const uint8_t c2_embedded_config[]",
		"0x00, 0x7f, 0xff, 0x61, 0x0a, 0x22, 0x5c,",
		"const size_t c2_embedded_config_len = 7;",
		"const uint8_t c2_magic_string[]",
		"0x6d, 0x61, 0x67, 0x69, 0x63,",
		"const size_t c2_magic_string_len = 5;",
		"const char c2_build_version[] = \"1.2.3\";",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated source missing %q:\n%s", want, src)
		}
	}
}

func TestEmbeddedConfigSourceEscapesVersion(t *testing.T) {
	src := string(EmbeddedConfigSource(nil, "", "a\"b\\c\n"))
	if !strings.Contains(src, `const char c2_build_version[] = "a\"b\\c\n";`) {
		t.Errorf("version not escaped correctly:\n%s", src)
	}
}

func TestEmbeddedConfigSourceEmpty(t *testing.T) {
	src := string(EmbeddedConfigSource(nil, "", ""))

	if !strings.Contains(src, "const size_t c2_embedded_config_len = 0;") {
		t.Errorf("empty config length wrong:\n%s", src)
	}
	if !strings.Contains(src, "const size_t c2_magic_string_len = 0;") {
		t.Errorf("empty magic length wrong:\n%s", src)
	}
	// An empty initializer ({}) is not valid C99; the generator must emit one
	// zero element while reporting a length of 0.
	if strings.Contains(src, "[] = {\n};") {
		t.Errorf("empty array initializer is not valid C:\n%s", src)
	}
}
