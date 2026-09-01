package controllers

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestParseTokensOutput(t *testing.T) {
	entries := []def.TokenEntry{
		{Key: "S-1-5-21-1-2-3", FriendlyName: "CORP/alice", IsSession: false},
		{Key: "CORP/bob", FriendlyName: "CORP/bob", IsSession: true},
	}
	data, err := cbor.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := ParseTokensOutput(data)
	if err != nil {
		t.Fatalf("ParseTokensOutput: %v", err)
	}
	if len(parsed.Headers) != 3 || len(parsed.Rows) != 2 {
		t.Fatalf("unexpected table: headers=%v rows=%v", parsed.Headers, parsed.Rows)
	}
	if parsed.Rows[0][0] != "S-1-5-21-1-2-3" || parsed.Rows[0][2] != "token" {
		t.Fatalf("row0 = %v", parsed.Rows[0])
	}
	if parsed.Rows[1][0] != "CORP/bob" || parsed.Rows[1][2] != "make_token session" {
		t.Fatalf("row1 = %v", parsed.Rows[1])
	}

	// Empty list is valid (rendered CC-side as "No cached tokens").
	empty, err := cbor.Marshal([]def.TokenEntry{})
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	parsed, err = ParseTokensOutput(empty)
	if err != nil || len(parsed.Rows) != 0 {
		t.Fatalf("empty parse: %v rows=%v", err, parsed.Rows)
	}

	// Garbage input must error, not panic.
	if _, err := ParseTokensOutput([]byte{0xde, 0xad}); err == nil {
		t.Fatalf("expected error for garbage input")
	}
}

func TestParseSessionsOutput(t *testing.T) {
	entries := []def.SessionEntry{
		{Name: "CORP/jdoe", User: "jdoe", Domain: "CORP", LogonID: 0x1a2b3c4d, CreatedAt: "2026-09-01T00:00:00Z"},
		{Name: "localadmin", User: "localadmin", Domain: ".", LogonID: 0x42, CreatedAt: "2026-09-01T00:00:00Z"},
	}
	data, err := cbor.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := ParseSessionsOutput(data)
	if err != nil {
		t.Fatalf("ParseSessionsOutput: %v", err)
	}
	if len(parsed.Rows) != 2 {
		t.Fatalf("unexpected rows: %v", parsed.Rows)
	}
	if parsed.Rows[0][0] != "CORP/jdoe" || parsed.Rows[0][1] != "CORP/jdoe" || parsed.Rows[0][2] != "0x1a2b3c4d" {
		t.Fatalf("row0 = %v", parsed.Rows[0])
	}
	if parsed.Rows[1][1] != "localadmin" {
		t.Fatalf("local session identity = %q, want bare username", parsed.Rows[1][1])
	}
}
