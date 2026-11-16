package detection

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func openKnowledgeFixture(t *testing.T) *KnowledgeDB {
	t.Helper()
	db, err := OpenKnowledgeDB(filepath.Join(t.TempDir(), "knowledge.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func addKnowledgeDoc(t *testing.T, db *KnowledgeDB, ref, notebook, title, url, summary, content string) {
	t.Helper()
	res, err := db.db.Exec(`INSERT INTO knowledge_documents(doc_ref, notebook, title, url, summary, content)
		VALUES(?, ?, ?, ?, ?, ?)`, ref, notebook, title, url, summary, content)
	if err != nil {
		t.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`INSERT INTO knowledge_fts(rowid, title, summary, content) VALUES(?, ?, ?, ?)`,
		id, title, summary, content); err != nil {
		t.Fatal(err)
	}
}

func TestKnowledgeReadFallsBackToSummary(t *testing.T) {
	db := openKnowledgeFixture(t)
	addKnowledgeDoc(t, db, "maldev/stomp", "maldev", "Stomping", "https://example/stomp",
		"Module stomping maps payload bytes over a legitimate module.", "")
	doc, err := db.Read(context.Background(), "maldev/stomp", "content", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Fallback || doc.Artifact != "summary" {
		t.Fatalf("document = %+v, want summary fallback", doc)
	}
	if !strings.Contains(doc.Content, "legitimate module") {
		t.Fatalf("fallback content = %q", doc.Content)
	}
}

func TestKnowledgeSearchDeduplicatesURLs(t *testing.T) {
	db := openKnowledgeFixture(t)
	addKnowledgeDoc(t, db, "maldev/stomp", "maldev", "Module stomping", "https://example/stomp/",
		"module stomping with doppelganging", "")
	addKnowledgeDoc(t, db, "redteam/stomp", "redteam", "Module stomping copy", "https://example/stomp",
		"module stomping with doppelganging", "")
	hits, err := db.Search(context.Background(), "module stomping", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %+v, want one URL", hits)
	}
	if hits[0].DocRef != "maldev/stomp" {
		t.Fatalf("kept hit = %+v, want highest-ranked first hit", hits[0])
	}
}

func TestKnowledgeStatsAndList(t *testing.T) {
	db := openKnowledgeFixture(t)
	addKnowledgeDoc(t, db, "maldev/stomp", "maldev", "Module stomping", "https://example/stomp", "summary", "")
	addKnowledgeDoc(t, db, "redteam/apc", "redteam", "APC injection", "https://example/apc", "summary", "content")
	stats, err := db.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Documents != 2 || stats.Summaries != 2 || stats.Contents != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if len(stats.Notebooks) != 2 {
		t.Fatalf("notebooks = %+v", stats.Notebooks)
	}
	docs, err := db.List(context.Background(), "maldev", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 || docs[0].DocRef != "maldev/stomp" || !docs[0].Summary || docs[0].Content {
		t.Fatalf("documents = %+v", docs)
	}
}

func TestAttachKnowledgeRecordsFindingRefsOnce(t *testing.T) {
	db := openKnowledgeFixture(t)
	addKnowledgeDoc(t, db, "maldev/createprocess", "maldev", "CreateProcessW detection",
		"https://example/createprocess", "telemetry child process CreateProcessW behavior", "")
	e := &evolver{
		knowledge: db,
		logf:      func(logging.Class, string, ...any) {},
	}
	feedback := Feedback{Findings: []Finding{{
		Stage: StageTelemetry, Severity: "high", Rule: "telemetry/child-process", Indicator: "CreateProcessW",
	}}}
	var summary cycleSummary
	e.attachKnowledge(context.Background(), &summary, feedback)
	if len(summary.KBRefs) != 1 || !strings.Contains(summary.KBRefs[0], "kb=maldev/createprocess") {
		t.Fatalf("refs = %+v, hits = %+v", summary.KBRefs, summary.Knowledge)
	}
	e.attachKnowledge(context.Background(), &summary, feedback)
	if len(summary.KBRefs) != 1 {
		t.Fatalf("duplicate refs = %+v", summary.KBRefs)
	}
}
