//go:build linux && !android && (386 || amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"testing"
)

// TestUprobeEventSize pins the on-wire layout shared with the BPF program's
// `struct event` (__u32 pid; __u32 uid; __s64 retval; char comm[16];
// char arg[64]). Changing it without changing the C struct silently corrupts
// every captured value.
func TestUprobeEventSize(t *testing.T) {
	if uprobeEventSize != 96 {
		t.Fatalf("uprobeEventSize = %d, want 96", uprobeEventSize)
	}
}

func TestDecodeUprobeEvent(t *testing.T) {
	raw := make([]byte, uprobeEventSize)
	binary.LittleEndian.PutUint32(raw[0:], 4242) // pid
	binary.LittleEndian.PutUint32(raw[4:], 1000) // uid
	binary.LittleEndian.PutUint64(raw[8:], 1)    // retval
	copy(raw[16:32], []byte("sshd"))             // comm
	copy(raw[32:], []byte("hunter2"))            // arg

	ev, err := decodeUprobeEvent(raw)
	if err != nil {
		t.Fatalf("decodeUprobeEvent: %v", err)
	}
	if ev.PID != 4242 || ev.UID != 1000 || ev.Retval != 1 {
		t.Fatalf("decoded %+v", ev)
	}
	if ev.Comm != "sshd" || ev.Arg != "hunter2" {
		t.Fatalf("decoded strings comm=%q arg=%q", ev.Comm, ev.Arg)
	}

	if _, err := decodeUprobeEvent(raw[:uprobeEventSize-1]); err == nil {
		t.Fatal("decodeUprobeEvent accepted a short value")
	}
}

// TestDecodeUprobeEventTruncatesAtNUL guards the C-string semantics: bytes
// after the first NUL are not part of the value.
func TestDecodeUprobeEventTruncatesAtNUL(t *testing.T) {
	raw := make([]byte, uprobeEventSize)
	copy(raw[32:], []byte{'p', 'w', 0, 'x', 'y'})
	ev, err := decodeUprobeEvent(raw)
	if err != nil {
		t.Fatalf("decodeUprobeEvent: %v", err)
	}
	if ev.Arg != "pw" {
		t.Fatalf("Arg = %q, want %q", ev.Arg, "pw")
	}
}

func TestArgRegisterIndex(t *testing.T) {
	want := map[string]int{
		"RAX": 0, "RDI": 1, "RSI": 2, "RDX": 3, "RCX": 4,
		"R8": 5, "R9": 6, "RBP": 7, "RSP": 8,
		"RBX": 9, "R12": 10, "R13": 11, "R14": 12, "R15": 13,
	}
	for name, idx := range want {
		if got := ArgRegisterIndex(name); got != idx {
			t.Errorf("ArgRegisterIndex(%s) = %d, want %d", name, got, idx)
		}
		if got := ArgRegisterIndex(lower(name)); got != idx {
			t.Errorf("ArgRegisterIndex(%s) = %d, want %d (case-insensitive)", lower(name), got, idx)
		}
	}
	if got := ArgRegisterIndex("RIP"); got != -1 {
		t.Errorf("ArgRegisterIndex(RIP) = %d, want -1", got)
	}
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if 'A' <= b[i] && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
