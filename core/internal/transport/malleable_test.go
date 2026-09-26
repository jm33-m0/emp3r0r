package transport

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// TestRandomMalleableHTTPConfigIsComplete checks every generated profile is
// usable as-is by both client and server, for both carrier styles.
func TestRandomMalleableHTTPConfigIsComplete(t *testing.T) {
	paths := map[string]struct{}{}
	for i := 0; i < 200; i++ {
		cfg := RandomMalleableHTTPConfig()

		if cfg.C2Path == "" || cfg.C2Path[0] != '/' {
			t.Fatalf("profile %d: invalid C2Path %q", i, cfg.C2Path)
		}
		if len(cfg.CustomHeaders) == 0 {
			t.Fatalf("profile %d: empty CustomHeaders", i)
		}
		if cfg.CustomHeaders["User-Agent"] == "" || cfg.CustomHeaders["Accept"] == "" {
			t.Fatalf("profile %d: browser headers incomplete: %v", i, cfg.CustomHeaders)
		}
		if cfg.SessionHeader == "" || cfg.SessionValue == "" ||
			cfg.InitHeader == "" || cfg.InitValue == "" ||
			cfg.CloseHeader == "" || cfg.CloseValue == "" {
			t.Fatalf("profile %d: incomplete carrier: %+v", i, cfg)
		}

		if cfg.SessionHeader == "Cookie" {
			if cfg.SessionValue[len(cfg.SessionValue)-2:] != "%s" {
				t.Fatalf("profile %d: cookie session value must templatize the id: %q", i, cfg.SessionValue)
			}
			for _, v := range []string{cfg.InitValue, cfg.CloseValue} {
				if !strings.Contains(v, "=") {
					t.Fatalf("profile %d: cookie init/close value missing '=': %q", i, v)
				}
			}
		} else {
			// Distinct header names are required or the client overwrites one
			// carrier with another and the server cannot resolve the session.
			if strings.EqualFold(cfg.SessionHeader, cfg.InitHeader) ||
				strings.EqualFold(cfg.SessionHeader, cfg.CloseHeader) ||
				strings.EqualFold(cfg.InitHeader, cfg.CloseHeader) {
				t.Fatalf("profile %d: session carrier headers collide: %+v", i, cfg)
			}
			if cfg.SessionValue != "%s" {
				t.Fatalf("profile %d: header session value must be %%s, got %q", i, cfg.SessionValue)
			}
		}

		paths[cfg.C2Path] = struct{}{}
	}

	if len(paths) < 2 {
		t.Fatalf("random profiles did not vary the C2 path: %v", paths)
	}
}

// TestRandomMalleableProfileSessionRoundTrip drives the client request-building
// helpers against the server-side session parsing for a generated profile. This
// is the contract that breaks if a profile is internally inconsistent.
func TestRandomMalleableProfileSessionRoundTrip(t *testing.T) {
	for i := 0; i < 100; i++ {
		cfg := RandomMalleableHTTPConfig()
		sessionID := fmt.Sprintf("sess-%d", i)

		// Client sends the init request exactly like HTTPChannelWrapper.Dial.
		initReq := httptest.NewRequest(http.MethodPost, "/", nil)
		applyMalleableConfig(initReq, &cfg, sessionID)
		setMalleableHeader(initReq.Header, cfg.InitHeader, cfg.InitValue, sessionID)

		rec := httptest.NewRecorder()
		stream, err := HandleHTTPServerSession(rec, initReq, &cfg)
		if err != nil {
			t.Fatalf("profile %d (%s): init rejected: %+v err=%v", i, cfg.SessionHeader, cfg, err)
		}
		if stream == nil {
			t.Fatalf("profile %d: init returned nil stream", i)
		}
		if stream.sessionID != sessionID {
			t.Fatalf("profile %d: init session id = %q, want %q", i, stream.sessionID, sessionID)
		}
		stream.MarkAuthenticated()

		// A later poll carries only the session carrier and must resolve back
		// to the same session.
		pollReq := httptest.NewRequest(http.MethodGet, "/", nil)
		applyMalleableConfig(pollReq, &cfg, sessionID)
		if !IsActiveHTTPServerSession(pollReq, &cfg) {
			t.Fatalf("profile %d (%s): poll did not resolve the init session", i, cfg.SessionHeader)
		}

		otherReq := httptest.NewRequest(http.MethodGet, "/", nil)
		applyMalleableConfig(otherReq, &cfg, sessionID+"-other")
		if IsActiveHTTPServerSession(otherReq, &cfg) {
			t.Fatalf("profile %d: unknown session resolved as active", i)
		}

		_ = stream.Close()
		serverSessions.Delete(sessionID)
	}
}

// TestNormalizeMalleableHTTPConfig pins the merge rule: a complete profile is
// preserved, an incomplete one is replaced.
func TestNormalizeMalleableHTTPConfig(t *testing.T) {
	complete := def.MalleableHTTPConfig{
		C2Path:        "/custom/path",
		SessionHeader: "Cookie",
		SessionValue:  "sid=%s",
		InitHeader:    "Cookie",
		InitValue:     "init=yes",
		CloseHeader:   "Cookie",
		CloseValue:    "close=yes",
		CustomHeaders: map[string]string{"User-Agent": "custom"},
	}
	if got := NormalizeMalleableHTTPConfig(complete); got.C2Path != complete.C2Path || got.SessionValue != complete.SessionValue {
		t.Fatalf("complete profile was modified: %+v", got)
	}

	partial := def.MalleableHTTPConfig{C2Path: "/only/path"}
	got := NormalizeMalleableHTTPConfig(partial)
	if !isCompleteMalleableConfig(got) {
		t.Fatalf("partial profile was not completed: %+v", got)
	}
	if got.C2Path == partial.C2Path {
		t.Fatalf("partial profile kept an inconsistent path: %+v", got)
	}
}
