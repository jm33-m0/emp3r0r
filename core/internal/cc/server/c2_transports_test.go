package server

import (
	"context"
	"testing"
	"time"
)

// TestC2TransportStartersCoverAllModes guards the production startup policy:
// every compiled agent transport must get a listener, independent of the
// channel mode selected for agent builds.
func TestC2TransportStartersCoverAllModes(t *testing.T) {
	starters := c2TransportStarters()
	got := make(map[string]bool, len(starters))
	for _, starter := range starters {
		if starter.name == "" {
			t.Fatal("transport starter has an empty name")
		}
		if starter.start == nil {
			t.Fatalf("transport %q has no start function", starter.name)
		}
		got[starter.name] = true
	}

	for _, want := range []string{"http_poll", "bridge", "tls", "quic"} {
		if !got[want] {
			t.Errorf("C2 transport %q is not started automatically", want)
		}
	}
}

func TestLaunchC2TransportsStartsEveryStarter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan string, 3)
	starters := []c2TransportStarter{
		{name: "one", start: func(context.Context) error { started <- "one"; return nil }},
		{name: "two", start: func(context.Context) error { started <- "two"; return nil }},
		{name: "three", start: func(context.Context) error { started <- "three"; return nil }},
	}

	launchC2Transports(ctx, starters)

	seen := make(map[string]bool, len(starters))
	deadline := time.After(2 * time.Second)
	for len(seen) < len(starters) {
		select {
		case name := <-started:
			seen[name] = true
		case <-deadline:
			t.Fatalf("transports started = %v, want all of %v", seen, starters)
		}
	}
}
