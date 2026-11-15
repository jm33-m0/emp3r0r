//go:build !release

package logging

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/fatih/color"
)

func TestSafeTerminalTextKeepsSGRAndDropsControlSequences(t *testing.T) {
	in := "\x1b[31mred\x1b[0m \x1b]0;title\x07text \x1b[2Jcleared\x1b[1;32mok"
	out := safeTerminalText(in)
	if !strings.Contains(out, "\x1b[31mred\x1b[0m") {
		t.Fatalf("SGR was stripped: %q", out)
	}
	for _, bad := range []string{"\x1b]0;", "title", "\x1b[2J", "\x07"} {
		if strings.Contains(out, bad) {
			t.Fatalf("output still contains %q: %q", bad, out)
		}
	}
	if !strings.Contains(out, "text cleared") || !strings.Contains(out, "\x1b[1;32mok") {
		t.Fatalf("text or style lost: %q", out)
	}
}

func TestClassfSanitizesFormatInjection(t *testing.T) {
	old := logger
	var buf bytes.Buffer
	logger = &Logger{writer: &buf}
	defer func() { logger = old }()

	Classf(ClassLine, "\x1b]0;evil\x07%s", "visible")
	out := buf.String()
	if strings.Contains(out, "\x1b]0;") || strings.Contains(out, "\x07") {
		t.Fatalf("Classf wrote an OSC sequence: %q", out)
	}
	if !strings.Contains(out, "visible") {
		t.Fatalf("Classf lost the message: %q", out)
	}
}

func TestClassModelRendersMarkdown(t *testing.T) {
	old := logger
	var buf bytes.Buffer
	logger = &Logger{writer: &buf}
	defer func() { logger = old }()

	Classf(ClassModel, "## Direction\n\n- self-load\n- section mapping")
	out := buf.String()
	if strings.Contains(out, "## Direction") {
		t.Fatalf("model output was not rendered: %q", out)
	}
	for _, want := range []string{"Direction", "self-load", "section mapping"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered model output lost %q: %q", want, out)
		}
	}
}

func TestCycleTagIsMagentaAndBold(t *testing.T) {
	old := color.NoColor
	color.NoColor = false
	defer func() { color.NoColor = old }()

	tag := ClassCycle.tagColor()
	if tag == nil {
		t.Fatal("cycle has no tag color")
	}
	if got := tag.Sprint("[cycle]"); !strings.Contains(got, "\x1b[95") {
		t.Fatalf("cycle tag is not bright magenta: %q", got)
	}
}

func TestClassfRendersMarkdownForFileAndTerminalWriters(t *testing.T) {
	old := logger
	var file, terminal bytes.Buffer
	logger = &Logger{sinks: []logSink{
		{w: PlainFileWriter(&file), plain: true},
		{w: &terminal},
	}}
	defer func() { logger = old }()

	Classf(ClassModel, "## Heading\n\n- one")
	if strings.Contains(file.String(), "## Heading") {
		t.Fatalf("file writer got raw Markdown: %q", file.String())
	}
	for name, got := range map[string]string{"file": file.String(), "terminal": terminal.String()} {
		if !strings.Contains(got, "Heading") || !strings.Contains(got, "one") {
			t.Fatalf("%s writer lost rendered content: %q", name, got)
		}
	}
}

func TestLoggerWritesToEverySink(t *testing.T) {
	old := logger
	var file, terminal bytes.Buffer
	logger = &Logger{sinks: []logSink{
		{w: PlainFileWriter(&file), plain: true},
		{w: &terminal},
	}}
	defer func() { logger = old }()

	logger.Printf(nil, "line %d\n", 1)
	for name, got := range map[string]string{"file": file.String(), "terminal": terminal.String()} {
		if !strings.Contains(got, "line 1") {
			t.Fatalf("%s sink missed the log line: %q", name, got)
		}
	}
}

func TestClassfToRendersTerminalTagsAndMarkdown(t *testing.T) {
	old := color.NoColor
	color.NoColor = false
	defer func() { color.NoColor = old }()

	var buf bytes.Buffer
	ClassfTo(&buf, ClassCycle, "cycle %d", 3)
	if !strings.Contains(buf.String(), "\x1b[") || !strings.Contains(buf.String(), "[cycle]") || !strings.Contains(buf.String(), "cycle 3") {
		t.Fatalf("ClassfTo lost color or content: %q", buf.String())
	}

	buf.Reset()
	ClassfTo(&buf, ClassModel, "## Heading\n\n- one")
	if strings.Contains(buf.String(), "## Heading") {
		t.Fatalf("ClassfTo did not render Markdown: %q", buf.String())
	}
	for _, want := range []string{"Heading", "one"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("ClassfTo lost %q: %q", want, buf.String())
		}
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestLoggerSinkUpdatesAreConcurrentSafe(t *testing.T) {
	var terminal lockedBuffer
	l := &Logger{sinks: []logSink{{w: &terminal}}}
	l.rebuildWriterLocked()

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			l.PrintfClass("terminal\n", "plain\n")
		}()
		go func() {
			defer wg.Done()
			l.AddWriter(&terminal)
		}()
	}
	wg.Wait()
	if !strings.Contains(terminal.String(), "terminal") {
		t.Fatalf("writer lost output during sink updates: %q", terminal.String())
	}
}

func TestDisplayMarkdownWithoutLogger(t *testing.T) {
	old := logger
	logger = nil
	defer func() { logger = old }()

	DisplayMarkdown("# report")
}
