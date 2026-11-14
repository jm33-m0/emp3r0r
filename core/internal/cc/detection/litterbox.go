// Package detection plans and runs payload detonation tests against a
// LitterBox sandbox, then turns the sandbox output into module source feedback.
//
// The sandbox is an operator-side service. Nothing here runs on a target, and
// every active stage (dynamic analysis, EDR detonation) is opt-in because it
// executes the uploaded payload.
package detection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

const (
	// DefaultSandboxURL is the local LitterBox HTTP API.
	DefaultSandboxURL = "http://127.0.0.1:1337"

	maxSandboxResponse = 64 << 20
	maxUploadBytes     = 100 << 20
	maxErrorExcerpt    = 512
)

// StageKind is one class of sandbox test.
type StageKind string

const (
	StageStatic    StageKind = "static"
	StageDynamic   StageKind = "dynamic"
	StageEDR       StageKind = "edr"
	StageTelemetry StageKind = "telemetry"
)

// Scanner is one configured sandbox analyzer.
type Scanner struct {
	Group   string `json:"group"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Enabled bool   `json:"enabled"`
	Exists  bool   `json:"exists"`
}

// Health is the sandbox capability snapshot used to build a plan.
type Health struct {
	URL          string    `json:"url,omitempty"`
	Available    bool      `json:"available"`
	Status       string    `json:"status,omitempty"`
	Scanners     []Scanner `json:"scanners,omitempty"`
	EDRProfiles  []string  `json:"edr_profiles,omitempty"`
	EDRAgents    []string  `json:"edr_agents,omitempty"`
	Issues       []string  `json:"issues,omitempty"`
	Error        string    `json:"error,omitempty"`
	ProbedAtUnix int64     `json:"probed_at,omitempty"`
}

// Tools returns the available scanner names for one group.
func (h Health) Tools(group string) []string {
	var out []string
	for _, scanner := range h.Scanners {
		if scanner.Group != group || !scanner.Enabled || !scanner.Exists || scanner.Status != "ok" {
			continue
		}
		out = append(out, scanner.Name)
	}
	return out
}

// Upload is one accepted artifact on the sandbox.
type Upload struct {
	MD5          string `json:"md5"`
	SHA256       string `json:"sha256"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	DetectedType string `json:"detected_type,omitempty"`
}

// Risk is the sandbox's aggregate detection assessment.
type Risk struct {
	Score   float64  `json:"risk_score"`
	Level   string   `json:"risk_level"`
	Factors []string `json:"risk_factors,omitempty"`
}

// Client talks to the LitterBox HTTP API.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient validates a sandbox URL. An empty value selects the local sandbox.
func NewClient(baseURL string) (*Client, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = DefaultSandboxURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("sandbox URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("sandbox URL must be http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("sandbox URL has no host")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("sandbox URL must not carry credentials")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return &Client{
		baseURL: parsed.String(),
		http:    &http.Client{Timeout: 15 * time.Minute},
	}, nil
}

// URL returns the normalized sandbox base URL.
func (c *Client) URL() string { return c.baseURL }

// do sends one request and returns a bounded body.
func (c *Client) do(ctx context.Context, method, path, contentType string, body io.Reader) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, 0, fmt.Errorf("sandbox request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("sandbox %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSandboxResponse+1))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read sandbox response: %w", err)
	}
	if len(data) > maxSandboxResponse {
		return nil, resp.StatusCode, fmt.Errorf("sandbox response exceeds %d bytes", maxSandboxResponse)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return data, resp.StatusCode, fmt.Errorf("sandbox %s %s: HTTP %d: %s", method, path, resp.StatusCode, excerpt(data))
	}
	return data, resp.StatusCode, nil
}

func excerpt(data []byte) string {
	text := sanitize.SanitizeOneLine(string(data))
	if len(text) > maxErrorExcerpt {
		text = text[:maxErrorExcerpt]
	}
	return text
}

// Probe reads the sandbox health and EDR profile inventory.
func (c *Client) Probe(ctx context.Context) Health {
	health := Health{URL: c.baseURL, ProbedAtUnix: time.Now().Unix()}
	data, status, err := c.do(ctx, http.MethodGet, "/health", "", nil)
	if err != nil && status != http.StatusServiceUnavailable {
		health.Error = err.Error()
		return health
	}
	var raw struct {
		Scanners struct {
			Rows []Scanner `json:"rows"`
		} `json:"scanners"`
		EDRAgents struct {
			Agents []struct {
				Profile string `json:"profile"`
				Name    string `json:"name"`
				URL     string `json:"url"`
				OK      bool   `json:"ok"`
			} `json:"agents"`
		} `json:"edr_agents"`
		Issues []string `json:"issues"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		health.Error = fmt.Sprintf("decode sandbox health: %v", err)
		return health
	}
	health.Available = true
	health.Scanners = raw.Scanners.Rows
	health.Issues = append(health.Issues, raw.Issues...)
	for _, agent := range raw.EDRAgents.Agents {
		name := agent.Profile
		if name == "" {
			name = agent.Name
		}
		if name != "" {
			health.EDRAgents = append(health.EDRAgents, name)
		}
	}

	profiles, _, err := c.do(ctx, http.MethodGet, "/api/edr/profiles", "", nil)
	if err != nil {
		health.Issues = append(health.Issues, "EDR profiles: "+err.Error())
	} else {
		var rawProfiles struct {
			Profiles []struct {
				Name        string `json:"name"`
				DisplayName string `json:"display_name"`
				Kind        string `json:"kind"`
			} `json:"profiles"`
		}
		if err := json.Unmarshal(profiles, &rawProfiles); err != nil {
			health.Issues = append(health.Issues, "decode EDR profiles: "+err.Error())
		} else {
			for _, profile := range rawProfiles.Profiles {
				if profile.Name != "" {
					health.EDRProfiles = append(health.EDRProfiles, profile.Name)
				}
			}
		}
	}
	if len(health.Tools("static")) == 0 && len(health.Tools("dynamic")) == 0 {
		health.Issues = append(health.Issues, "no sandbox scanners are available")
	}
	health.Status = "ok"
	return health
}

// Upload streams one artifact to the sandbox.
func (c *Client) Upload(ctx context.Context, path string) (Upload, error) {
	file, err := os.Open(path)
	if err != nil {
		return Upload{}, fmt.Errorf("open artifact: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Upload{}, fmt.Errorf("stat artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Upload{}, fmt.Errorf("artifact is not a regular file")
	}
	if info.Size() <= 0 {
		return Upload{}, fmt.Errorf("artifact is empty")
	}
	if info.Size() > maxUploadBytes {
		return Upload{}, fmt.Errorf("artifact exceeds the %d byte sandbox limit", maxUploadBytes)
	}
	name := filepath.Base(path)
	if filepath.Ext(name) == "" {
		name += ".bin"
	}
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		part, partErr := mw.CreateFormFile("file", name)
		if partErr == nil {
			_, partErr = io.Copy(part, file)
		}
		if closeErr := mw.Close(); partErr == nil {
			partErr = closeErr
		}
		pw.CloseWithError(partErr)
	}()
	data, _, err := c.do(ctx, http.MethodPost, "/upload", mw.FormDataContentType(), pr)
	if err != nil {
		pr.CloseWithError(err)
		return Upload{}, err
	}
	var response struct {
		FileInfo struct {
			MD5      string `json:"md5"`
			SHA256   string `json:"sha256"`
			Size     int64  `json:"size"`
			Name     string `json:"original_name"`
			Detected struct {
				Family string `json:"family"`
				Type   string `json:"type"`
			} `json:"detected_type"`
		} `json:"file_info"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return Upload{}, fmt.Errorf("decode sandbox upload: %w", err)
	}
	if response.FileInfo.MD5 == "" {
		return Upload{}, errors.New("sandbox upload returned no MD5")
	}
	upload := Upload{
		MD5:    response.FileInfo.MD5,
		SHA256: response.FileInfo.SHA256,
		Name:   response.FileInfo.Name,
		Size:   response.FileInfo.Size,
	}
	if upload.Name == "" {
		upload.Name = name
	}
	if response.FileInfo.Detected.Family != "" {
		upload.DetectedType = response.FileInfo.Detected.Family
		if response.FileInfo.Detected.Type != "" {
			upload.DetectedType += "/" + response.FileInfo.Detected.Type
		}
	}
	return upload, nil
}

// Analyze runs a passive (static) or active (dynamic) analysis and returns the
// saved result block.
func (c *Client) Analyze(ctx context.Context, md5 string, kind StageKind, wait bool) (json.RawMessage, error) {
	if kind != StageStatic && kind != StageDynamic {
		return nil, fmt.Errorf("unsupported analysis kind %q", kind)
	}
	path := fmt.Sprintf("/analyze/%s/%s?wait=%d", kind, url.PathEscape(md5), boolInt(wait))
	data, _, err := c.do(ctx, http.MethodPost, path, "application/json", nil)
	if err != nil {
		return nil, err
	}
	if kind == StageDynamic {
		// The dynamic endpoint also persists results; read the saved copy so
		// every stage returns the same shape.
		return c.Results(ctx, kind, md5)
	}
	var response struct {
		Status  string          `json:"status"`
		Results json.RawMessage `json:"results"`
		Error   string          `json:"error"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("decode sandbox %s result: %w", kind, err)
	}
	if response.Status != "" && response.Status != "success" {
		if response.Error != "" {
			return nil, fmt.Errorf("sandbox %s: %s", kind, excerpt([]byte(response.Error)))
		}
		return nil, fmt.Errorf("sandbox %s: %s", kind, response.Status)
	}
	if len(response.Results) > 0 {
		return response.Results, nil
	}
	return c.Results(ctx, kind, md5)
}

// Results returns one saved result block.
func (c *Client) Results(ctx context.Context, kind StageKind, md5 string) (json.RawMessage, error) {
	path := fmt.Sprintf("/api/results/%s/%s", kind, url.PathEscape(md5))
	data, _, err := c.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

const maxFetchedEDRProfiles = 32

// SandboxResults is every saved result block for one upload: file info,
// static and dynamic analyzers, BYOVD output, and EDR profiles. The detection
// loop stores all of them with the run.
type SandboxResults struct {
	Info      json.RawMessage
	Static    json.RawMessage
	Dynamic   json.RawMessage
	HolyGrail json.RawMessage
	EDR       map[string]json.RawMessage
	Warnings  []string
}

// Empty reports whether the sandbox produced no saved result block.
func (r SandboxResults) Empty() bool {
	return len(r.Info) == 0 && len(r.Static) == 0 && len(r.Dynamic) == 0 &&
		len(r.HolyGrail) == 0 && len(r.EDR) == 0
}

// FetchResults fetches every saved result block for an upload. The caller may
// pass already-fetched static and dynamic blocks so a run does not request the
// same large result twice. Missing optional blocks are recorded as warnings; a
// single unavailable analyzer must not hide the blocks that did complete.
func (c *Client) FetchResults(ctx context.Context, md5 string, static, dynamic json.RawMessage) SandboxResults {
	out := SandboxResults{EDR: map[string]json.RawMessage{}}
	fetch := func(kind string) json.RawMessage {
		data, status, err := c.do(ctx, http.MethodGet,
			fmt.Sprintf("/api/results/%s/%s", kind, url.PathEscape(md5)), "", nil)
		if err != nil {
			if status != http.StatusNotFound {
				out.Warnings = append(out.Warnings, kind+" results: "+err.Error())
			}
			return nil
		}
		return data
	}
	out.Info = fetch("info")
	out.Static = static
	if len(out.Static) == 0 {
		out.Static = fetch("static")
	}
	out.Dynamic = dynamic
	if len(out.Dynamic) == 0 {
		out.Dynamic = fetch("dynamic")
	}
	out.HolyGrail = fetch("holygrail")

	data, status, err := c.do(ctx, http.MethodGet, "/api/results/edr/"+url.PathEscape(md5), "", nil)
	if err != nil {
		if status != http.StatusNotFound {
			out.Warnings = append(out.Warnings, "EDR index: "+err.Error())
		}
		return out
	}
	var index struct {
		Profiles []string `json:"profiles"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		out.Warnings = append(out.Warnings, "EDR index: "+err.Error())
		return out
	}
	if len(index.Profiles) > maxFetchedEDRProfiles {
		out.Warnings = append(out.Warnings, fmt.Sprintf("EDR profiles truncated from %d to %d", len(index.Profiles), maxFetchedEDRProfiles))
		index.Profiles = index.Profiles[:maxFetchedEDRProfiles]
	}
	for _, profile := range index.Profiles {
		profile = strings.TrimSpace(profile)
		if profile == "" {
			continue
		}
		edr, edrStatus, edrErr := c.do(ctx, http.MethodGet,
			fmt.Sprintf("/api/results/edr/%s/%s", url.PathEscape(profile), url.PathEscape(md5)), "", nil)
		if edrErr != nil {
			if edrStatus != http.StatusNotFound {
				out.Warnings = append(out.Warnings, "EDR "+profile+": "+edrErr.Error())
			}
			continue
		}
		out.EDR[profile] = edr
	}
	return out
}

// Risk returns the aggregate detection assessment.
func (c *Client) Risk(ctx context.Context, md5 string) (Risk, error) {
	data, _, err := c.do(ctx, http.MethodGet, "/api/results/risk/"+url.PathEscape(md5), "", nil)
	if err != nil {
		return Risk{}, err
	}
	var risk Risk
	if err := json.Unmarshal(data, &risk); err != nil {
		return Risk{}, fmt.Errorf("decode risk assessment: %w", err)
	}
	return risk, nil
}

// Info returns the uploaded file metadata, including PE structure when present.
func (c *Client) Info(ctx context.Context, md5 string) (json.RawMessage, error) {
	data, _, err := c.do(ctx, http.MethodGet, "/api/results/info/"+url.PathEscape(md5), "", nil)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

// AnalyzeEDR dispatches the artifact to one EDR profile and waits for the saved
// correlation result.
func (c *Client) AnalyzeEDR(ctx context.Context, profile, md5 string, timeout time.Duration) (json.RawMessage, error) {
	if strings.TrimSpace(profile) == "" {
		return nil, errors.New("EDR profile is required")
	}
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	path := fmt.Sprintf("/analyze/edr/%s/%s", url.PathEscape(profile), url.PathEscape(md5))
	data, _, err := c.do(ctx, http.MethodPost, path, "application/json", nil)
	if err != nil {
		return nil, err
	}
	var phase1 struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(data, &phase1); err != nil {
		return nil, fmt.Errorf("decode EDR dispatch: %w", err)
	}
	if phase1.Status != "" && phase1.Status != "polling_alerts" && phase1.Status != "success" {
		if phase1.Error != "" {
			return nil, fmt.Errorf("EDR dispatch: %s", excerpt([]byte(phase1.Error)))
		}
		return nil, fmt.Errorf("EDR dispatch: %s", phase1.Status)
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		result, err := c.edrResults(ctx, profile, md5)
		if err == nil {
			var status struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(result, &status) == nil && status.Status != "polling_alerts" {
				return result, nil
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			if lastErr == nil {
				lastErr = errors.New("still polling for correlated alerts")
			}
			return nil, fmt.Errorf("EDR results for %s: %w", profile, lastErr)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func (c *Client) edrResults(ctx context.Context, profile, md5 string) (json.RawMessage, error) {
	path := fmt.Sprintf("/api/results/edr/%s/%s", url.PathEscape(profile), url.PathEscape(md5))
	data, _, err := c.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
