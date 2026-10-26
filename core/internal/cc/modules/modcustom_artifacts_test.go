package modules

import (
	"reflect"
	"testing"
)

func TestGeneratedPayloadLines(t *testing.T) {
	out := []byte("compiling...\n" +
		"[+] generated payload: /tmp/stager.bin (1234 bytes)\r\n" +
		"  [+] generated payload: /tmp/loader.exe (5678 bytes)  \n" +
		"unrelated output\n" +
		"[+] generated payload: \n")

	want := []string{
		"/tmp/stager.bin (1234 bytes)",
		"/tmp/loader.exe (5678 bytes)",
	}
	if got := generatedPayloadLines(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("generatedPayloadLines() = %#v, want %#v", got, want)
	}
	if got := generatedPayloadLines(nil); len(got) != 0 {
		t.Fatalf("generatedPayloadLines(nil) = %#v, want empty", got)
	}
}
