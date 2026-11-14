package detection

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

const (
	// knowledgeSchemaVersion is the FTS cache layout this package writes.
	knowledgeSchemaVersion = 1
	// maxKnowledgeResponse bounds one MCP response.
	maxKnowledgeResponse = 64 << 20
	// maxKnowledgeDocBytes bounds one cached document artifact.
	maxKnowledgeDocBytes = 512 << 10
	// maxKnowledgeQuery bounds a model-issued search query.
	maxKnowledgeQuery = 200
	// maxKnowledgeHits bounds one search result page.
	maxKnowledgeHits = 20
)

var knowledgeDocRef = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

// knowledgeSchema is the offline copy of the reference notebook. The FTS table
// mirrors knowledge_documents by rowid so the loop can search without network.
const knowledgeSchema = `
CREATE TABLE IF NOT EXISTS knowledge_documents (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	doc_ref TEXT NOT NULL UNIQUE,
	notebook TEXT NOT NULL DEFAULT '',
	title TEXT NOT NULL DEFAULT '',
	url TEXT NOT NULL DEFAULT '',
	summary TEXT NOT NULL DEFAULT '',
	content TEXT NOT NULL DEFAULT '',
	updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS knowledge_documents_notebook ON knowledge_documents(notebook);
CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
	title, summary, content, tokenize='unicode61 remove_diacritics 2'
);
CREATE TABLE IF NOT EXISTS knowledge_meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL DEFAULT ''
);
`

// KnowledgeDB is the local reference cache. The detection loop opens it
// read-only; SyncKnowledge owns the write handle.
type KnowledgeDB struct {
	path string
	db   *sql.DB
	ro   *sql.DB
}

// KnowledgeSyncOptions controls one cache refresh from an MCP notebook server.
type KnowledgeSyncOptions struct {
	URL      string
	Notebook string
	Content  bool
	Logf     func(string)
}

// KnowledgeSyncStats reports what one refresh changed.
type KnowledgeSyncStats struct {
	Notebooks int `json:"notebooks"`
	Summaries int `json:"summaries"`
	Contents  int `json:"contents"`
	Skipped   int `json:"skipped"`
}

// KnowledgeHit is one ranked search result.
type KnowledgeHit struct {
	DocRef   string  `json:"document_ref"`
	Notebook string  `json:"notebook"`
	Title    string  `json:"title"`
	URL      string  `json:"url,omitempty"`
	Snippet  string  `json:"snippet"`
	Score    float64 `json:"score,omitempty"`
}

// KnowledgeDoc is one document artifact with byte bounds applied.
type KnowledgeDoc struct {
	DocRef     string `json:"document_ref"`
	Notebook   string `json:"notebook"`
	Title      string `json:"title,omitempty"`
	URL        string `json:"url,omitempty"`
	Artifact   string `json:"artifact"`
	Content    string `json:"content"`
	NextOffset int    `json:"next_offset,omitempty"`
}

// KnowledgePath returns the cache path inside a detection store.
func KnowledgePath(storeRoot string) string {
	return filepath.Join(strings.TrimSpace(storeRoot), "knowledge.db")
}

// OpenKnowledgeDB opens the cache. A read-only open of a missing or empty cache
// returns an error the caller can surface as "run knowledge-sync".
func OpenKnowledgeDB(path string, writable bool) (*KnowledgeDB, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("knowledge database path is required")
	}
	if writable {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create knowledge directory: %w", err)
		}
	}
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath()
	if writable {
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			return nil, fmt.Errorf("open knowledge database: %w", err)
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		for _, pragma := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL", "PRAGMA busy_timeout=5000"} {
			if _, err := db.Exec(pragma); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("configure knowledge database: %w", err)
			}
		}
		if _, err := db.Exec(knowledgeSchema); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("create knowledge schema: %w", err)
		}
		if _, err := db.Exec(`INSERT INTO knowledge_meta(key, value) VALUES('schema_version', ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`, fmt.Sprint(knowledgeSchemaVersion)); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("record knowledge schema: %w", err)
		}
		if err := restrictKnowledgeFiles(path); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("restrict knowledge database: %w", err)
		}
		return &KnowledgeDB{path: path, db: db}, nil
	}
	ro, err := sql.Open("sqlite", dsn+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open knowledge database: %w", err)
	}
	ro.SetMaxOpenConns(1)
	ro.SetMaxIdleConns(1)
	if _, err := ro.Exec("PRAGMA query_only=ON"); err != nil {
		_ = ro.Close()
		return nil, fmt.Errorf("set knowledge query connection read-only: %w", err)
	}
	var name string
	if err := ro.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='knowledge_fts'`).Scan(&name); err != nil {
		_ = ro.Close()
		return nil, fmt.Errorf("knowledge cache is empty; run detect_loop knowledge-sync")
	}
	return &KnowledgeDB{path: path, ro: ro}, nil
}

// Path returns the database path.
func (k *KnowledgeDB) Path() string { return k.path }

// Close releases the handles this instance owns.
func (k *KnowledgeDB) Close() error {
	var errs []error
	if k.db != nil {
		if err := restrictKnowledgeFiles(k.path); err != nil {
			errs = append(errs, err)
		}
		errs = append(errs, k.db.Close())
	}
	if k.ro != nil {
		errs = append(errs, k.ro.Close())
	}
	return errors.Join(errs...)
}

// restrictKnowledgeFiles applies 0600 to the database and SQLite's WAL
// sidecars. WAL and SHM are created after the main file, so each needs its own
// chmod; a permissive umask must not expose cached knowledge.
func restrictKnowledgeFiles(path string) error {
	var errs []error
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(name, 0o600); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Count returns the number of cached documents.
func (k *KnowledgeDB) Count(ctx context.Context) (int, error) {
	conn := k.reader()
	var count int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM knowledge_documents`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (k *KnowledgeDB) reader() *sql.DB {
	if k.ro != nil {
		return k.ro
	}
	return k.db
}

// ---------------------------------------------------------------- MCP client

type mcpClient struct {
	url    string
	http   *http.Client
	nextID int64
}

func newMCPClient(rawURL string) (*mcpClient, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("knowledge server URL is required")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid knowledge server URL %q", rawURL)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("knowledge server URL must use http or https")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("knowledge server URL must not contain credentials")
	}
	origin := strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("knowledge server redirected too many times")
			}
			if req.URL.User != nil {
				return fmt.Errorf("knowledge server redirected to a URL with credentials")
			}
			next := strings.ToLower(req.URL.Scheme) + "://" + strings.ToLower(req.URL.Host)
			if next != origin {
				return fmt.Errorf("knowledge server redirected outside %s", origin)
			}
			return nil
		},
	}
	return &mcpClient{url: rawURL, http: client}, nil
}

func (c *mcpClient) call(ctx context.Context, method string, params any, out any) error {
	c.nextID++
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": c.nextID, "method": method, "params": params,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxKnowledgeResponse))
	if err != nil {
		return fmt.Errorf("read knowledge response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("knowledge server returned %s", resp.Status)
	}
	envelope, err := decodeMCPEnvelope(data)
	if err != nil {
		return err
	}
	if envelope.Error != nil {
		return fmt.Errorf("knowledge server error: %s", envelope.Error.Message)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(envelope.Result, out); err != nil {
		return fmt.Errorf("decode knowledge result: %w", err)
	}
	return nil
}

type mcpEnvelope struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeMCPEnvelope(data []byte) (mcpEnvelope, error) {
	var envelope mcpEnvelope
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &envelope); err == nil {
			return envelope, nil
		}
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64<<10), maxKnowledgeResponse)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		payload, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		payload = strings.TrimSpace(payload)
		if payload == "" || payload == "[DONE]" {
			continue
		}
		if err := json.Unmarshal([]byte(payload), &envelope); err == nil {
			return envelope, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return envelope, fmt.Errorf("read knowledge stream: %w", err)
	}
	return envelope, fmt.Errorf("knowledge server returned no JSON-RPC message")
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpToolResult struct {
	Content []mcpContent `json:"content"`
	IsError bool         `json:"isError"`
}

func (c *mcpClient) tool(ctx context.Context, name string, args any, out any) error {
	var result mcpToolResult
	if err := c.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args}, &result); err != nil {
		return err
	}
	if result.IsError {
		return fmt.Errorf("knowledge tool %s failed", name)
	}
	var text string
	for _, item := range result.Content {
		if item.Type == "text" && strings.TrimSpace(item.Text) != "" {
			text = item.Text
			break
		}
	}
	if text == "" {
		return fmt.Errorf("knowledge tool %s returned no text", name)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal([]byte(text), out); err != nil {
		return fmt.Errorf("decode knowledge tool %s output: %w", name, err)
	}
	return nil
}

type knowledgeBookmark struct {
	URL        string `json:"url"`
	Title      string `json:"title"`
	Filename   string `json:"filename"`
	Notebook   string `json:"notebook"`
	Summarized bool   `json:"summarized"`
	Scraped    bool   `json:"scraped"`
}

type knowledgeCatalog struct {
	Notebooks []string            `json:"notebooks"`
	Bookmarks []knowledgeBookmark `json:"bookmarks"`
}

type knowledgeDocuments struct {
	Documents        []knowledgeDocument `json:"documents"`
	Truncated        bool                `json:"response_truncated"`
	MaxResponseBytes int                 `json:"max_response_bytes"`
}

type knowledgeDocument struct {
	DocumentRef string `json:"document_ref"`
	Artifact    string `json:"artifact"`
	Filename    string `json:"filename"`
	Content     string `json:"content"`
}

// SyncKnowledge refreshes the cache from an MCP notebook server. It is only
// called by the operator command; the detection loop never makes network calls.
func SyncKnowledge(ctx context.Context, db *KnowledgeDB, opts KnowledgeSyncOptions) (KnowledgeSyncStats, error) {
	stats := KnowledgeSyncStats{}
	if db == nil || db.db == nil {
		return stats, fmt.Errorf("knowledge database is not writable")
	}
	defer func() { _ = restrictKnowledgeFiles(db.path) }()
	logf := opts.Logf
	if logf == nil {
		logf = func(string) {}
	}
	client, err := newMCPClient(opts.URL)
	if err != nil {
		return stats, err
	}
	var init any
	if err := client.call(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "emp3r0r-detection", "version": "1"},
	}, &init); err != nil {
		return stats, fmt.Errorf("initialize knowledge server: %w", err)
	}
	var catalog knowledgeCatalog
	if err := client.tool(ctx, "list_bookmarks", map[string]any{}, &catalog); err != nil {
		return stats, err
	}
	stats.Notebooks = len(catalog.Notebooks)
	notebook := strings.ToLower(strings.TrimSpace(opts.Notebook))
	var refs []knowledgeBookmark
	for _, bookmark := range catalog.Bookmarks {
		if notebook != "" && strings.ToLower(bookmark.Notebook) != notebook {
			continue
		}
		if !bookmark.Summarized {
			stats.Skipped++
			continue
		}
		if knowledgeRef(bookmark) == "" {
			stats.Skipped++
			continue
		}
		refs = append(refs, bookmark)
	}
	logf(fmt.Sprintf("knowledge: %d notebooks, %d summarised documents", stats.Notebooks, len(refs)))

	const batch = 20
	byRef := make(map[string]knowledgeBookmark, len(refs))
	refIDs := make([]string, 0, len(refs))
	for _, bookmark := range refs {
		ref := knowledgeRef(bookmark)
		byRef[ref] = bookmark
		refIDs = append(refIDs, ref)
	}
	// fetchPages retrieves an artifact for a set of refs, then retries any
	// missing ref alone so one oversized document cannot hide the rest.
	fetchPages := func(artifact string) (map[string]knowledgeDocument, error) {
		out := make(map[string]knowledgeDocument, len(refIDs))
		for start := 0; start < len(refIDs); start += batch {
			end := start + batch
			if end > len(refIDs) {
				end = len(refIDs)
			}
			var documents knowledgeDocuments
			if err := client.tool(ctx, "get_documents", map[string]any{
				"document_refs": refIDs[start:end], "artifact": artifact,
			}, &documents); err != nil {
				return nil, err
			}
			for _, document := range documents.Documents {
				out[document.DocumentRef] = document
			}
		}
		for _, ref := range refIDs {
			if _, ok := out[ref]; ok {
				continue
			}
			var single knowledgeDocuments
			if err := client.tool(ctx, "get_documents", map[string]any{
				"document_refs": []string{ref}, "artifact": artifact,
			}, &single); err != nil {
				return nil, err
			}
			for _, document := range single.Documents {
				out[document.DocumentRef] = document
			}
		}
		return out, nil
	}
	summaries, err := fetchPages("summary")
	if err != nil {
		return stats, err
	}
	for _, ref := range refIDs {
		document, ok := summaries[ref]
		if !ok {
			stats.Skipped++
			continue
		}
		if err := db.storeDocument(ctx, byRef[ref], document, "summary"); err != nil {
			return stats, err
		}
		stats.Summaries++
	}
	if opts.Content {
		contents, err := fetchPages("content")
		if err != nil {
			return stats, err
		}
		for _, ref := range refIDs {
			document, ok := contents[ref]
			if !ok || strings.TrimSpace(document.Content) == "" {
				stats.Skipped++
				continue
			}
			stored, err := db.updateContent(ctx, ref, document.Content)
			if err != nil {
				return stats, err
			}
			if stored {
				stats.Contents++
			}
		}
	}
	logf(fmt.Sprintf("knowledge: cached %d summaries, %d contents, skipped %d", stats.Summaries, stats.Contents, stats.Skipped))
	return stats, nil
}

func knowledgeRef(bookmark knowledgeBookmark) string {
	notebook := strings.ToLower(strings.TrimSpace(bookmark.Notebook))
	filename := strings.TrimSpace(bookmark.Filename)
	if notebook == "" || filename == "" {
		return ""
	}
	for _, ext := range []string{".llm", ".md", ".txt", ".html", ".htm"} {
		if strings.HasSuffix(strings.ToLower(filename), ext) {
			filename = filename[:len(filename)-len(ext)]
			break
		}
	}
	ref := notebook + "/" + filename
	if !knowledgeDocRef.MatchString(ref) {
		return ""
	}
	return ref
}

func (k *KnowledgeDB) storeDocument(ctx context.Context, bookmark knowledgeBookmark, document knowledgeDocument, artifact string) error {
	ref := knowledgeRef(bookmark)
	if ref == "" {
		ref = strings.TrimSpace(document.DocumentRef)
	}
	if !knowledgeDocRef.MatchString(ref) {
		return fmt.Errorf("invalid knowledge document reference %q", ref)
	}
	summary := ""
	content := ""
	if artifact == "summary" {
		summary = boundsKnowledgeText(document.Content)
	} else {
		content = boundsKnowledgeText(document.Content)
	}
	tx, err := k.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var id int64
	title := sanitizeKnowledgeText(bookmark.Title)
	url := sanitizeKnowledgeText(bookmark.URL)
	if err := tx.QueryRowContext(ctx, `SELECT id FROM knowledge_documents WHERE doc_ref = ?`, ref).Scan(&id); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO knowledge_documents(doc_ref, notebook, title, url, summary, content, updated_at)
			VALUES(?, ?, ?, ?, ?, ?, ?)`,
			ref, strings.ToLower(bookmark.Notebook), title, url, summary, content, time.Now().UTC().Unix())
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		if err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE knowledge_documents
			SET notebook = ?, title = ?, url = ?, summary = CASE WHEN ? <> '' THEN ? ELSE summary END,
			    content = CASE WHEN ? <> '' THEN ? ELSE content END, updated_at = ?
			WHERE id = ?`,
			strings.ToLower(bookmark.Notebook), title, url,
			summary, summary, content, content, time.Now().UTC().Unix(), id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM knowledge_fts WHERE rowid = ?`, id); err != nil {
			return err
		}
	}
	var storedTitle, storedSummary, storedContent string
	if err := tx.QueryRowContext(ctx, `SELECT title, summary, content FROM knowledge_documents WHERE id = ?`, id).
		Scan(&storedTitle, &storedSummary, &storedContent); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO knowledge_fts(rowid, title, summary, content) VALUES(?, ?, ?, ?)`,
		id, storedTitle, storedSummary, storedContent); err != nil {
		return err
	}
	return tx.Commit()
}

func (k *KnowledgeDB) updateContent(ctx context.Context, ref, content string) (bool, error) {
	ref = strings.TrimSpace(ref)
	if !knowledgeDocRef.MatchString(ref) {
		return false, fmt.Errorf("invalid knowledge document reference %q", ref)
	}
	content = boundsKnowledgeText(content)
	if content == "" {
		return false, nil
	}
	tx, err := k.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM knowledge_documents WHERE doc_ref = ?`, ref).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE knowledge_documents SET content = ?, updated_at = ? WHERE id = ?`,
		content, time.Now().UTC().Unix(), id); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM knowledge_fts WHERE rowid = ?`, id); err != nil {
		return false, err
	}
	var title, summary string
	if err := tx.QueryRowContext(ctx, `SELECT title, summary FROM knowledge_documents WHERE id = ?`, id).Scan(&title, &summary); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO knowledge_fts(rowid, title, summary, content) VALUES(?, ?, ?, ?)`,
		id, title, summary, content); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func boundsKnowledgeText(text string) string {
	text = sanitizeKnowledgeText(text)
	if len(text) > maxKnowledgeDocBytes {
		text = clipUTF8(text, maxKnowledgeDocBytes)
	}
	return text
}

// sanitizeKnowledgeText strips terminal escapes and non-printable runes,
// including C1 controls and Unicode format characters such as bidi overrides,
// while keeping the prose and line structure intact.
func sanitizeKnowledgeText(text string) string {
	cleaned := sanitize.SanitizeText(text)
	var b strings.Builder
	b.Grow(len(cleaned))
	for _, r := range cleaned {
		// SanitizeText keeps Unicode spaces, which includes the C1 NEL
		// character (U+0085); terminals still interpret C1 as control codes.
		if r >= 0x80 && r <= 0x9f {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// Search runs an FTS5 query and returns ranked excerpt hits.
func (k *KnowledgeDB) Search(ctx context.Context, query, notebook string, limit int) ([]KnowledgeHit, error) {
	terms := ftsTerms(query)
	if len(terms) == 0 {
		return nil, fmt.Errorf("search query has no searchable terms")
	}
	if limit <= 0 || limit > maxKnowledgeHits {
		limit = 10
	}
	notebook = strings.ToLower(strings.TrimSpace(notebook))
	hits, err := k.searchFTS(ctx, terms, "AND", notebook, limit)
	if err != nil {
		return nil, err
	}
	if len(hits) == 0 && len(terms) > 1 {
		return k.searchFTS(ctx, terms, "OR", notebook, limit)
	}
	return hits, nil
}

func (k *KnowledgeDB) searchFTS(ctx context.Context, terms []string, op, notebook string, limit int) ([]KnowledgeHit, error) {
	quoted := make([]string, 0, len(terms))
	for _, term := range terms {
		quoted = append(quoted, `"`+term+`"`)
	}
	expression := strings.Join(quoted, " "+op+" ")
	sqlText := `SELECT d.doc_ref, d.notebook, d.title, d.url,
		snippet(knowledge_fts, 1, '[', ']', ' … ', 32) AS excerpt,
		bm25(knowledge_fts, 4.0, 1.0, 0.5) AS rank
		FROM knowledge_fts JOIN knowledge_documents d ON d.id = knowledge_fts.rowid
		WHERE knowledge_fts MATCH ?`
	args := []any{expression}
	if notebook != "" {
		sqlText += ` AND d.notebook = ?`
		args = append(args, notebook)
	}
	sqlText += ` ORDER BY rank LIMIT ?`
	args = append(args, limit)
	rows, err := k.reader().QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, fmt.Errorf("search knowledge: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var hits []KnowledgeHit
	for rows.Next() {
		var hit KnowledgeHit
		if err := rows.Scan(&hit.DocRef, &hit.Notebook, &hit.Title, &hit.URL, &hit.Snippet, &hit.Score); err != nil {
			return nil, err
		}
		hit.Title = sanitizeKnowledgeText(hit.Title)
		hit.Snippet = sanitizeKnowledgeText(hit.Snippet)
		hit.Score = -hit.Score // bm25 returns a negative score; positive reads better
		hits = append(hits, hit)
	}
	return hits, rows.Err()
}

// Read returns one cached artifact, bounded by byte offset and limit.
func (k *KnowledgeDB) Read(ctx context.Context, ref, artifact string, offset, limit int) (KnowledgeDoc, error) {
	ref = strings.TrimSpace(ref)
	if !knowledgeDocRef.MatchString(ref) {
		return KnowledgeDoc{}, fmt.Errorf("invalid document reference")
	}
	switch artifact {
	case "", "summary":
		artifact = "summary"
	case "content":
	default:
		return KnowledgeDoc{}, fmt.Errorf("artifact must be summary or content")
	}
	var title, url, notebook, summary, content string
	err := k.reader().QueryRowContext(ctx, `SELECT title, url, notebook, summary, content
		FROM knowledge_documents WHERE doc_ref = ?`, ref).Scan(&title, &url, &notebook, &summary, &content)
	if errors.Is(err, sql.ErrNoRows) {
		return KnowledgeDoc{}, fmt.Errorf("document %q is not cached", ref)
	}
	if err != nil {
		return KnowledgeDoc{}, err
	}
	text := summary
	if artifact == "content" {
		text = content
	}
	if text == "" {
		return KnowledgeDoc{}, fmt.Errorf("document %q has no cached %s; re-run knowledge-sync with --content", ref, artifact)
	}
	if offset < 0 {
		offset = 0
	}
	if offset > len(text) {
		offset = len(text)
	}
	text = text[offset:]
	for !utf8.ValidString(text) && len(text) > 0 {
		text = text[1:]
	}
	if limit <= 0 || limit > maxKnowledgeDocBytes {
		limit = 8 << 10
	}
	next := 0
	if len(text) > limit {
		text = clipUTF8(text, limit)
		next = offset + len(text)
	}
	return KnowledgeDoc{
		DocRef: ref, Notebook: notebook, Title: sanitizeKnowledgeText(title),
		URL: sanitizeKnowledgeText(url), Artifact: artifact,
		Content: sanitizeKnowledgeText(text), NextOffset: next,
	}, nil
}

// ftsTerms normalises a free-text query into quoted FTS tokens.
func ftsTerms(query string) []string {
	query = strings.TrimSpace(query)
	if len(query) > maxKnowledgeQuery {
		query = query[:maxKnowledgeQuery]
	}
	seen := map[string]struct{}{}
	var terms []string
	for _, token := range strings.FieldsFunc(strings.ToLower(query), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_'
	}) {
		if len(token) < 2 || len(token) > 48 {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		terms = append(terms, token)
		if len(terms) >= 12 {
			break
		}
	}
	slices.Sort(terms)
	return terms
}
