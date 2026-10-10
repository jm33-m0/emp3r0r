package util

import (
	"fmt"
	"strings"
	"testing"
)

func TestGenAgentTagIsDeterministicAndSafe(t *testing.T) {
	const uuid = "8f14e45f-ceea-467f-a8d7-3d1b4f5e2c6a"

	id := GenAgentTag(uuid)
	if id != GenAgentTag(uuid) {
		t.Fatalf("GenAgentTag(%q) is not deterministic", uuid)
	}
	if !IsAgentID(id) {
		t.Fatalf("GenAgentTag(%q) = %q, which is not a valid agent ID", uuid, id)
	}
	if len(id) != agentIDHexLen {
		t.Fatalf("GenAgentTag(%q) has length %d, want %d", uuid, len(id), agentIDHexLen)
	}
	// The identifier must not contain recognizable identity material that could
	// leak through logs, tmux names, or completion output.
	if id == uuid || strings.Contains(id, uuid) || strings.Contains(id, "emp3r0r") {
		t.Fatalf("GenAgentTag(%q) = %q leaks identity material", uuid, id)
	}
}

func TestGenAgentTagDistinctUUIDsDistinctIDs(t *testing.T) {
	seen := make(map[string]string)
	for i := range 256 {
		uuid := fmt.Sprintf("uuid-%03d-abcdef", i)
		id := GenAgentTag(uuid)
		if prev, ok := seen[id]; ok && prev != uuid {
			t.Fatalf("collision: %q and %q both map to %q", prev, uuid, id)
		}
		seen[id] = uuid
	}
}

func TestGenAgentTagEmptyUUID(t *testing.T) {
	if id := GenAgentTag(""); id != "" {
		t.Fatalf("GenAgentTag(\"\") = %q, want empty", id)
	}
}

func TestAgentRefIncludesTagAndUUID(t *testing.T) {
	const uuid = "8f14e45f-ceea-467f-a8d7-3d1b4f5e2c6a"
	ref := AgentRef(uuid)
	tag := GenAgentTag(uuid)
	if !strings.Contains(ref, tag) || !strings.Contains(ref, uuid) {
		t.Fatalf("AgentRef(%q) = %q, want both tag %q and uuid", uuid, ref, tag)
	}

	// A non-UUID identifier (e.g. an already-resolved tag) is returned as-is.
	if ref := AgentRef("deadbeef"); ref != "deadbeef" {
		t.Fatalf("AgentRef(tag) = %q, want the tag verbatim", ref)
	}
	if ref := AgentRef(""); ref != "<unknown>" {
		t.Fatalf("AgentRef(\"\") = %q, want <unknown>", ref)
	}

	// UUID text forms are normalized, so uppercase/braced input yields the
	// same reference and therefore the same derived tag.
	if got, want := AgentRef(strings.ToUpper(uuid)), ref; got != want {
		t.Fatalf("AgentRef(upper) = %q, want %q", got, want)
	}
}

func TestIsAgentIDRejectsHostileInput(t *testing.T) {
	valid := GenAgentTag("some-agent-uuid")
	if !IsAgentID(valid) {
		t.Fatalf("IsAgentID(%q) = false, want true", valid)
	}

	rejected := []string{
		"",
		"unknown",
		valid + "0", // wrong length
		strings.ToUpper(valid),
		valid[:len(valid)-1] + "g",
		"1234567",               // too short
		"1a2b3c4d\n",            // newline
		"1a2b3c4d#(touch /tmp)", // tmux format syntax
		"1a2b3c4d#{window_name}",
		"1a2b3c4d; id",
	}
	for _, s := range rejected {
		if IsAgentID(s) {
			t.Errorf("IsAgentID(%q) = true, want false", s)
		}
	}
}
