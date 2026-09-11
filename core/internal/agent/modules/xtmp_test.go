//go:build linux

package modules

import (
	"bytes"
	"strings"
	"testing"
)

// record builds a single fixed-size xtmp record padded with NULs.
func record(fill string) []byte {
	b := make([]byte, xtmpRecordSize)
	copy(b, fill)
	return b
}

func TestFilterXtmpRecordsRemovesMatchingRecord(t *testing.T) {
	keep1 := record("login alice from 10.0.0.1")
	drop := record("login bob from 10.0.0.2")
	keep2 := record("logout alice from 10.0.0.1")
	data := bytes.Join([][]byte{keep1, drop, keep2}, nil)

	got := filterXtmpRecords(data, "bob")

	if bytes.Contains(got, []byte("bob")) {
		t.Fatalf("filtered data still contains keyword: %q", got)
	}
	want := bytes.Join([][]byte{keep1, keep2}, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("filterXtmpRecords returned %d bytes, want %d", len(got), len(want))
	}
}

func TestFilterXtmpRecordsKeepsPartialTrailingRecord(t *testing.T) {
	full := record("login alice")
	// A corrupt/hostile partial record must not panic or be dropped.
	trailing := []byte("partial trailing data")
	data := append(append([]byte{}, full...), trailing...)

	got := filterXtmpRecords(data, "does-not-match")
	if !bytes.Equal(got, data) {
		t.Fatalf("filterXtmpRecords altered a non-matching buffer")
	}

	// It must also survive a keyword match on the partial trailing record.
	got = filterXtmpRecords(data, "partial")
	if bytes.Contains(got, []byte("partial")) {
		t.Fatalf("filterXtmpRecords did not strip the matching partial record: %q", got)
	}
}

func TestFilterLogLines(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		keyword string
		want    string
	}{
		{name: "drops matching middle line", in: "a\nsecret\nb\n", keyword: "secret", want: "a\nb\n"},
		{name: "preserves missing trailing newline", in: "a\nsecret\nb", keyword: "secret", want: "a\nb"},
		{name: "no match", in: "a\nb\n", keyword: "zzz", want: "a\nb\n"},
		{name: "drops all", in: "x\nx\n", keyword: "x", want: ""},
		{name: "empty input", in: "", keyword: "x", want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := filterLogLines([]byte(c.in), c.keyword); got != c.want {
				t.Errorf("filterLogLines(%q, %q) = %q, want %q", c.in, c.keyword, got, c.want)
			}
		})
	}
}

func TestFilterXtmpRecordsKeywordSpanningNothing(t *testing.T) {
	// Keyword split across a record boundary must not match either record.
	r1 := record("aaaa")
	r2 := record("bbbb")
	data := bytes.Join([][]byte{r1, r2}, nil)
	// "ab" only appears if the boundary itself were searched.
	got := filterXtmpRecords(data, "ab")
	if !bytes.Equal(got, data) {
		t.Fatal("filterXtmpRecords matched across a record boundary")
	}
	if strings.Count(string(got), "aaaa") != 1 || strings.Count(string(got), "bbbb") != 1 {
		t.Fatal("filterXtmpRecords corrupted record content")
	}
}
