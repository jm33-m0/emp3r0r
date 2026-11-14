package detection

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	maxFeedbackFindings = 100
	maxSourceFiles      = 500
	maxSourceFileBytes  = 2 << 20
	maxSourceTotalBytes = 16 << 20
	maxSourceLocations  = 3
	maxGenericNodes     = 20000
	maxGenericFindings  = 200
)

// SourceLocation is one place in the module source a detection maps to.
type SourceLocation struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Excerpt string `json:"excerpt"`
}

// Finding is one detection indicator with the source it maps to.
type Finding struct {
	Stage     StageKind        `json:"stage"`
	Tool      string           `json:"tool"`
	Severity  string           `json:"severity"`
	Rule      string           `json:"rule,omitempty"`
	Indicator string           `json:"indicator"`
	Detail    string           `json:"detail,omitempty"`
	Executes  bool             `json:"executes"`
	Sources   []SourceLocation `json:"sources,omitempty"`
}

// SourceEdit is an actionable pointer for a module source change.
type SourceEdit struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Excerpt string `json:"excerpt"`
	Reason  string `json:"reason"`
	Action  string `json:"action"`
}

// PendingStage records a stage whose result is missing from the feedback.
type PendingStage struct {
	Kind   StageKind `json:"kind"`
	Tool   string    `json:"tool"`
	Status string    `json:"status"`
	Reason string    `json:"reason,omitempty"`
}

// Feedback is the source-edit view of one detection run.
type Feedback struct {
	RunID       string          `json:"run_id"`
	Module      string          `json:"module"`
	ModuleDir   string          `json:"module_dir,omitempty"`
	Artifact    Artifact        `json:"artifact"`
	Score       float64         `json:"score"`
	Level       string          `json:"level,omitempty"`
	RiskFactors []string        `json:"risk_factors,omitempty"`
	Findings    []Finding       `json:"findings"`
	SourceEdits []SourceEdit    `json:"source_edits"`
	Unmatched   int             `json:"unmatched"`
	Pending     []PendingStage  `json:"pending,omitempty"`
	Telemetry   *TelemetryRun   `json:"telemetry,omitempty"`
	Notes       []string        `json:"notes,omitempty"`
	Analysis    json.RawMessage `json:"analysis,omitempty"`
}

// BuildFeedback parses a run's sandbox output and maps every indicator back to
// the module source.
func BuildFeedback(run Run) Feedback {
	fb := Feedback{
		RunID:       run.ID,
		Module:      run.Module,
		ModuleDir:   run.Plan.ModuleDir,
		Artifact:    run.Plan.Artifact,
		Score:       run.Risk.Score,
		Level:       run.Risk.Level,
		RiskFactors: append([]string(nil), run.Risk.Factors...),
		Telemetry:   run.Telemetry,
	}
	if run.Error != "" {
		fb.Notes = append(fb.Notes, "run error: "+run.Error)
	}
	if run.Risk.Level == "" {
		fb.Notes = append(fb.Notes, "the sandbox did not return a risk assessment")
	}
	locator := newLocator(newSourceIndex(run.Plan.ModuleDir))

	if run.Telemetry != nil {
		for _, finding := range run.Telemetry.Findings {
			finding.Stage = StageTelemetry
			finding.Tool = "telemetry"
			finding.Executes = true
			addFinding(&fb, finding, locator.locate)
		}
	}
	for _, stage := range run.Stages {
		switch stage.Status {
		case "skipped", "error":
			reason := stage.Reason
			if stage.Error != "" {
				reason = stage.Error
			}
			fb.Pending = append(fb.Pending, PendingStage{Kind: stage.Kind, Tool: stage.Tool, Status: stage.Status, Reason: reason})
			continue
		case "completed":
		default:
			continue
		}
		switch stage.Kind {
		case StageStatic:
			for _, finding := range parseStatic(stage.Raw) {
				finding.Executes = stage.Executes
				addFinding(&fb, finding, locator.locate)
			}
		case StageDynamic, StageEDR:
			for _, finding := range parseGeneric(stage.Raw, stage.Kind) {
				finding.Tool = stage.Tool
				finding.Executes = true
				addFinding(&fb, finding, locator.locate)
			}
		}
	}
	for _, finding := range parseInfo(run.Info) {
		addFinding(&fb, finding, locator.locate)
	}
	if len(fb.Findings) == 0 {
		fb.Notes = append(fb.Notes, "no indicator was extracted from the completed stages")
	}
	if len(fb.Pending) > 0 {
		fb.Notes = append(fb.Notes, "feedback is partial; pending stages are listed")
	}
	fb.SourceEdits = dedupeEdits(fb.SourceEdits)
	sort.SliceStable(fb.Findings, func(i, j int) bool {
		ri := severityRank(fb.Findings[i].Severity)
		rj := severityRank(fb.Findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return fb.Findings[i].Indicator < fb.Findings[j].Indicator
	})
	return fb
}

func addFinding(fb *Feedback, finding Finding, locate func(string) []SourceLocation) {
	if len(fb.Findings) >= maxFeedbackFindings {
		return
	}
	sanitizeFindingText(&finding)
	finding.Indicator = clipUTF8(finding.Indicator, 300)
	if finding.Indicator == "" {
		return
	}
	for _, existing := range fb.Findings {
		if existing.Indicator == finding.Indicator && existing.Rule == finding.Rule {
			return
		}
	}
	finding.Severity = normalizeSeverity(finding.Severity)
	finding.Sources = locate(finding.Indicator)
	if len(finding.Sources) == 0 {
		fb.Unmatched++
		if len(fb.Notes) < 10 {
			fb.Notes = appendUnique(fb.Notes, fmt.Sprintf("%s: %q has no literal match in the module source", finding.Tool, clip(finding.Indicator, 80)))
		}
	}
	fb.Findings = append(fb.Findings, finding)
	for _, location := range finding.Sources {
		fb.SourceEdits = append(fb.SourceEdits, SourceEdit{
			File:    location.File,
			Line:    location.Line,
			Column:  location.Column,
			Excerpt: location.Excerpt,
			Reason:  fmt.Sprintf("%s %s hit: %s", finding.Tool, finding.Severity, clip(finding.Indicator, 120)),
			Action:  suggestion(finding),
		})
	}
}

func suggestion(finding Finding) string {
	switch finding.Stage {
	case StageStatic:
		switch strings.ToLower(finding.Tool) {
		case "yara":
			return "Remove, reshape, or encrypt the matched literal; confirm the rule no longer matches after a rebuild."
		case "checkplz":
			return "Inspect the flagged offset and remove the signature pattern it keys on."
		default:
			return "The scanner surfaced this literal from the artifact; derive it at runtime or encrypt it."
		}
	case StageDynamic:
		return "A runtime scanner observed this; change the code path so the behavior no longer matches the scanner's heuristic."
	case StageEDR:
		return "The EDR rule fired on this behavior; adjust the sequence, the APIs used, or the parent process to avoid the rule."
	}
	return "Review the mapped source and remove the indicator."
}

func dedupeEdits(edits []SourceEdit) []SourceEdit {
	seen := make(map[string]struct{}, len(edits))
	out := make([]SourceEdit, 0, len(edits))
	for _, edit := range edits {
		key := fmt.Sprintf("%s:%d:%s", edit.File, edit.Line, edit.Reason)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, edit)
	}
	return out
}

// --- static result parsing -------------------------------------------------

// yaraMatch mirrors the YARA JSON output the sandbox saves.
type yaraMatch struct {
	Rule      string         `json:"rule"`
	Namespace string         `json:"namespace"`
	Tags      []string       `json:"tags"`
	Meta      map[string]any `json:"meta"`
	Metadata  map[string]any `json:"metadata"`
	Strings   []any          `json:"strings"`
}

type stringAnalyzerFindings struct {
	SuspiciousStrings   []string `json:"found_suspicious_strings"`
	SuspiciousFunctions []string `json:"found_suspicious_functions"`
	InterestingStrings  []string `json:"found_interesting_strings"`
	Commands            []string `json:"found_commands"`
	Domains             []string `json:"found_domains"`
	IPs                 []string `json:"found_ip"`
	URLs                []string `json:"found_url"`
	Paths               []string `json:"found_path"`
	RegistryKeys        []string `json:"found_registry_keys"`
	DLLs                []string `json:"found_dll"`
	Functions           []string `json:"found_functions"`
	Network             []string `json:"found_network_indicators"`
	FileOperations      []string `json:"found_file_operations"`
	Emails              []string `json:"found_emails"`
	ErrorMessages       []string `json:"found_error_messages"`
}

func parseStatic(raw json.RawMessage) []Finding {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil
	}
	var findings []Finding

	if yaraRaw, ok := top["yara"]; ok {
		var report struct {
			Matches []yaraMatch `json:"matches"`
			Status  string      `json:"status"`
			Errors  any         `json:"errors"`
		}
		if json.Unmarshal(yaraRaw, &report) == nil {
			for _, match := range report.Matches {
				severity, detail := yaraMeta(match)
				if len(match.Strings) == 0 {
					findings = append(findings, Finding{Tool: "yara", Severity: severity, Rule: match.Rule, Indicator: match.Rule, Detail: detail})
					continue
				}
				for _, item := range match.Strings {
					for _, text := range yaraStrings(item) {
						findings = append(findings, Finding{Tool: "yara", Severity: severity, Rule: match.Rule, Indicator: text, Detail: detail})
					}
				}
			}
		}
	}

	if stringsRaw, ok := top["stringnalyzer"]; ok {
		var report struct {
			Findings stringAnalyzerFindings `json:"findings"`
		}
		if json.Unmarshal(stringsRaw, &report) == nil {
			for _, group := range []struct {
				items    []string
				severity string
			}{
				{report.Findings.SuspiciousStrings, "high"},
				{report.Findings.SuspiciousFunctions, "medium"},
				{report.Findings.Commands, "medium"},
				{report.Findings.Network, "medium"},
				{report.Findings.Domains, "low"},
				{report.Findings.URLs, "low"},
				{report.Findings.IPs, "low"},
				{report.Findings.Paths, "low"},
				{report.Findings.RegistryKeys, "medium"},
				{report.Findings.DLLs, "low"},
				{report.Findings.Functions, "low"},
				{report.Findings.FileOperations, "low"},
				{report.Findings.InterestingStrings, "low"},
				{report.Findings.Emails, "low"},
				{report.Findings.ErrorMessages, "low"},
			} {
				for _, item := range group.items {
					findings = append(findings, Finding{Tool: "stringnalyzer", Severity: group.severity, Indicator: item})
				}
			}
		}
	}

	if checkRaw, ok := top["checkplz"]; ok {
		var report struct {
			Findings map[string]any `json:"findings"`
		}
		if json.Unmarshal(checkRaw, &report) == nil {
			for _, key := range []string{"initial_threat", "final_threat_detection"} {
				if value, ok := report.Findings[key]; ok && value != nil {
					findings = append(findings, Finding{
						Tool: "checkplz", Severity: "high", Rule: key,
						Indicator: fmt.Sprintf("%v", value),
					})
				}
			}
		}
	}
	return findings
}

func yaraMeta(match yaraMatch) (string, string) {
	severity := "medium"
	for _, meta := range []map[string]any{match.Meta, match.Metadata} {
		if meta == nil {
			continue
		}
		if value, ok := meta["severity"]; ok {
			severity = normalizeSeverity(fmt.Sprintf("%v", value))
		}
	}
	var details []string
	for _, meta := range []map[string]any{match.Meta, match.Metadata} {
		for _, key := range []string{"description", "author", "reference"} {
			if value, ok := meta[key]; ok {
				details = append(details, fmt.Sprintf("%s=%v", key, value))
			}
		}
	}
	return severity, strings.Join(details, "; ")
}

// yaraStrings extracts the matched text from a YARA string entry.
func yaraStrings(item any) []string {
	entry, ok := item.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	for _, key := range []string{"data", "match", "value"} {
		value, ok := entry[key]
		if !ok {
			continue
		}
		switch v := value.(type) {
		case string:
			out = append(out, decodeMaybeBase64(v))
		case []any:
			for _, element := range v {
				if text, ok := element.(string); ok {
					out = append(out, decodeMaybeBase64(text))
				}
			}
		}
	}
	return out
}

func decodeMaybeBase64(text string) string {
	text = strings.TrimSpace(text)
	if len(text) < 8 || len(text)%4 != 0 {
		return text
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return text
	}
	printable := 0
	for _, r := range string(decoded) {
		if unicode.IsPrint(r) || r == '\n' || r == '\t' || r == '\r' {
			printable++
		}
	}
	if printable < len(decoded)*9/10 {
		return text
	}
	return string(decoded)
}

// parseInfo extracts suspicious imports and entropy flags from the uploaded
// file metadata.
func parseInfo(raw json.RawMessage) []Finding {
	if len(raw) == 0 {
		return nil
	}
	var top map[string]any
	if json.Unmarshal(raw, &top) != nil {
		return nil
	}
	pe, _ := top["pe_info"].(map[string]any)
	if pe == nil {
		return nil
	}
	var findings []Finding
	if imports, ok := pe["suspicious_imports"].([]any); ok {
		for _, entry := range imports {
			imp, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			fn, _ := imp["function"].(string)
			dll, _ := imp["dll"].(string)
			if fn == "" {
				continue
			}
			findings = append(findings, Finding{
				Tool: "pe-info", Severity: "medium", Indicator: fn,
				Detail: "suspicious import from " + dll,
			})
		}
	}
	for _, section := range anySlice(pe["sections"]) {
		sec, ok := section.(map[string]any)
		if !ok {
			continue
		}
		entropy, _ := sec["entropy"].(float64)
		name, _ := sec["name"].(string)
		if entropy > 7.5 && name != "" {
			findings = append(findings, Finding{
				Tool: "pe-info", Severity: "high", Indicator: name,
				Detail: fmt.Sprintf("section entropy %.2f", entropy),
			})
		}
	}
	return findings
}

func anySlice(value any) []any {
	if slice, ok := value.([]any); ok {
		return slice
	}
	return nil
}

// --- dynamic and EDR parsing ----------------------------------------------

var indicatorKeys = map[string]bool{
	"message": true, "description": true, "title": true, "rule": true,
	"rule_name": true, "technique": true, "technique_id": true,
	"detection": true, "indicator": true, "signature": true, "anomaly": true,
	"suspicious": true, "reason": true, "detail": true, "details": true, "notes": true,
}

var collectionKeys = map[string]bool{
	"findings": true, "alerts": true, "events": true, "detections": true,
	"anomalies": true, "suspicious": true, "matches": true, "hits": true,
}

func parseGeneric(raw json.RawMessage, kind StageKind) []Finding {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	collector := &genericCollector{max: maxGenericFindings, seen: map[string]struct{}{}}
	collector.walk(value, "", "", "", 0)
	out := make([]Finding, 0, len(collector.findings))
	for _, finding := range collector.findings {
		finding.Stage = kind
		out = append(out, finding)
	}
	return out
}

type genericCollector struct {
	findings []Finding
	seen     map[string]struct{}
	nodes    int
	max      int
}

func (c *genericCollector) walk(value any, severity, rule, tool string, depth int) {
	if depth > 8 || c.nodes > maxGenericNodes || len(c.findings) >= c.max {
		return
	}
	c.nodes++
	switch v := value.(type) {
	case map[string]any:
		if text, ok := v["severity"].(string); ok {
			severity = normalizeSeverity(text)
		}
		if text, ok := v["level"].(string); ok && text != "" {
			severity = normalizeSeverity(text)
		}
		for _, key := range []string{"rule", "rule_name", "name", "title", "technique"} {
			if text, ok := v[key].(string); ok && text != "" {
				rule = text
				break
			}
		}
		if text, ok := v["tool"].(string); ok && text != "" {
			tool = text
		}
		for key, child := range v {
			if collectionKeys[strings.ToLower(key)] || indicatorKeys[strings.ToLower(key)] {
				c.collectStrings(child, severity, rule, tool, depth+1)
			}
			c.walk(child, severity, rule, tool, depth+1)
		}
	case []any:
		for _, child := range v {
			c.walk(child, severity, rule, tool, depth+1)
		}
	}
}

func (c *genericCollector) collectStrings(value any, severity, rule, tool string, depth int) {
	if depth > 8 || len(c.findings) >= c.max {
		return
	}
	switch v := value.(type) {
	case string:
		c.add(v, severity, rule, tool)
	case []any:
		for _, element := range v {
			if text, ok := element.(string); ok {
				c.add(text, severity, rule, tool)
			}
		}
	case map[string]any:
		for _, key := range []string{"message", "description", "title", "name", "text", "value"} {
			if text, ok := v[key].(string); ok {
				c.add(text, severity, rule, tool)
			}
		}
	}
}

func (c *genericCollector) add(text, severity, rule, tool string) {
	text = strings.TrimSpace(text)
	if len(text) < 4 {
		return
	}
	key := strings.ToLower(text)
	if _, ok := c.seen[key]; ok {
		return
	}
	c.seen[key] = struct{}{}
	c.findings = append(c.findings, Finding{
		Severity: severity, Rule: rule, Indicator: text, Detail: rule, Tool: tool,
	})
}

// --- source index ---------------------------------------------------------

type sourceFile struct {
	rel   string
	lines []string
}

type sourceIndex struct {
	files []sourceFile
}

var sourceExtensions = map[string]bool{
	".c": true, ".h": true, ".s": true, ".sh": true, ".py": true, ".json": true,
	".ld": true, ".mk": true, ".txt": true, ".yml": true, ".yaml": true,
}

func newSourceIndex(dir string) *sourceIndex {
	index := &sourceIndex{}
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return index
	}
	total := 0
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		name := info.Name()
		if info.IsDir() {
			if name == ".git" || name == "__pycache__" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() || !sourceExtensions[strings.ToLower(filepath.Ext(name))] {
			return nil
		}
		if info.Size() > maxSourceFileBytes || len(index.files) >= maxSourceFiles || total > maxSourceTotalBytes {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			rel = name
		}
		total += len(data)
		index.files = append(index.files, sourceFile{
			rel:   filepath.ToSlash(rel),
			lines: strings.Split(string(data), "\n"),
		})
		return nil
	})
	sort.Slice(index.files, func(i, j int) bool { return index.files[i].rel < index.files[j].rel })
	return index
}

// locator bounds how much source text one feedback pass inspects and caches
// repeated indicators, so a large module cannot turn feedback into a scan of
// the whole tree per finding.
type locator struct {
	index  *sourceIndex
	budget int
	cache  map[string][]SourceLocation
}

func newLocator(index *sourceIndex) *locator {
	return &locator{index: index, budget: 500000, cache: map[string][]SourceLocation{}}
}

func (l *locator) locate(indicator string) []SourceLocation {
	if cached, ok := l.cache[indicator]; ok {
		return cached
	}
	locations := l.index.locate(indicator, &l.budget)
	l.cache[indicator] = locations
	return locations
}

func (idx *sourceIndex) locate(indicator string, budget *int) []SourceLocation {
	candidates := sourceCandidates(indicator)
	if len(candidates) == 0 {
		return nil
	}
	out := idx.scan(candidates, budget, false)
	if len(out) == 0 {
		out = idx.scan(candidates, budget, true)
	}
	return out
}

func (idx *sourceIndex) scan(candidates []string, budget *int, fold bool) []SourceLocation {
	var out []SourceLocation
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		// Folded matching is for API names the sandbox lowercases. Short
		// lowercase words would match prose, so only long identifiers qualify.
		if fold && len(candidate) < 8 {
			continue
		}
		needle := candidate
		if fold {
			needle = strings.ToLower(candidate)
		}
		for _, file := range idx.files {
			for lineNo, line := range file.lines {
				(*budget)--
				if *budget <= 0 {
					return out
				}
				haystack := line
				if fold {
					haystack = strings.ToLower(line)
				}
				column := strings.Index(haystack, needle)
				if column < 0 {
					continue
				}
				key := fmt.Sprintf("%s:%d", file.rel, lineNo+1)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, SourceLocation{
					File:    file.rel,
					Line:    lineNo + 1,
					Column:  column + 1,
					Excerpt: clip(strings.TrimSpace(line), 200),
				})
				if len(out) >= maxSourceLocations {
					return out
				}
			}
		}
	}
	return out
}

var identifierLike = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{4,}$`)

// codeShaped reports whether a token is likely to appear in source: it has an
// underscore, a digit, an inner capital, or a path separator.
func codeShaped(token string) bool {
	if strings.ContainsAny(token, "_0123456789./\\:") {
		return true
	}
	for _, r := range token[1:] {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func sourceCandidates(indicator string) []string {
	indicator = strings.TrimSpace(indicator)
	if indicator == "" {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		value = strings.Trim(value, "\"'`,;()[]{}")
		if len(value) < 5 || len(value) > 240 {
			return
		}
		if !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	add(indicator)
	add(decodeMaybeBase64(indicator))
	multiWord := strings.ContainsAny(indicator, " \t")
	for _, token := range strings.FieldsFunc(indicator, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ';' || r == '=' || r == '(' || r == ')' || r == '"' || r == '\''
	}) {
		if !identifierLike.MatchString(token) {
			continue
		}
		// In a sentence, only code-shaped tokens are worth searching for.
		// Plain lowercase words match comments and dilute the feedback.
		if multiWord && !codeShaped(token) {
			continue
		}
		add(token)
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(value))
	case "100":
		return "critical"
	case "80":
		return "high"
	case "50":
		return "medium"
	case "20":
		return "low"
	case "5":
		return "info"
	}
	return "medium"
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	}
	return 5
}

func clip(text string, limit int) string {
	if limit <= 0 || len(text) <= limit {
		return text
	}
	return text[:limit]
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}
