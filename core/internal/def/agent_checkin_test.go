package def

import "testing"

func TestCheckinFieldsOmitServerState(t *testing.T) {
	agent := &Emp3r0rAgent{
		Tag:          "tag",
		Name:         "host/user",
		Version:      "v1",
		UUID:         "uuid",
		UUIDSig:      "sig",
		PublicKey:    "pub",
		From:         "203.0.113.7:1234",
		C2Host:       "c2.example:443",
		Owner:        "operator",
		LastSeenRTT:  1,
		AgentToken:   &AgentToken{AgentID: "uuid"},
		MeshRoute:    "direct",
		P2PRelayPort: "1234",
		GOArch:       "amd64",
		P2PTransport: "direct",
	}
	fields := agent.CheckinFields()

	for _, retired := range []uint64{1, 15, 27, 28, 30, 31, 32, 36, 43} {
		if _, ok := fields[retired]; ok {
			t.Errorf("check-in body still carries retired key %d", retired)
		}
	}
	for _, wanted := range []uint64{2, 3, 29, 37, 38, 41, 42} {
		if _, ok := fields[wanted]; !ok {
			t.Errorf("check-in body is missing key %d", wanted)
		}
	}
	// Booleans are meaningful even when false, so they are always sent.
	for _, wanted := range []uint64{19, 20, 21, 22} {
		if _, ok := fields[wanted]; !ok {
			t.Errorf("check-in body is missing boolean key %d", wanted)
		}
	}
}

func TestCheckinFieldsNil(t *testing.T) {
	var agent *Emp3r0rAgent
	if got := agent.CheckinFields(); got != nil {
		t.Fatalf("nil agent CheckinFields = %v, want nil", got)
	}
}
