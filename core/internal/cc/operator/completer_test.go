package operator

import (
	"reflect"
	"testing"

	"github.com/carapace-sh/carapace"
	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// encodeDents marshals dents the same way the agent's LsPath does, so the test
// exercises the real CBOR decode path used by remoteDirListing.
func encodeDents(t *testing.T, dents []util.Dentry) string {
	t.Helper()
	raw, err := cbor.Marshal(dents)
	if err != nil {
		t.Fatalf("marshal dents: %v", err)
	}
	return string(raw)
}

func TestRemoteDirListing(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		dents  []util.Dentry
		want   []string
	}{
		{
			name:   "disk directory",
			prefix: "/tmp/",
			dents: []util.Dentry{
				{Name: "sub", Ftype: "dir"},
				{Name: "a.txt", Ftype: "file"},
			},
			want: []string{"sub/", "a.txt"},
		},
		{
			name:   "disk entry with space is escaped",
			prefix: "/tmp/",
			dents: []util.Dentry{
				{Name: "my file", Ftype: "file"},
			},
			want: []string{"my\\ file"},
		},
		{
			name:   "terminal escapes in a filename are stripped",
			prefix: "/tmp/",
			dents: []util.Dentry{
				{Name: "evil\x1b[31m", Ftype: "file"},
			},
			want: []string{"evil"},
		},
		{
			name:   "memfs typed with two slashes keeps the third",
			prefix: "memfs://",
			dents: []util.Dentry{
				{Name: "memfs:///file1", Ftype: "file (mem)"},
				{Name: "memfs:///dir1/file3", Ftype: "file (mem)"},
				{Name: "memfs:///dir1/file4", Ftype: "file (mem)"},
				{Name: "memfs:///dir2/subdir/file5", Ftype: "file (mem)"},
			},
			want: []string{"/file1", "/dir1/", "/dir2/"},
		},
		{
			name:   "memfs partial root segment",
			prefix: "memfs:///",
			dents: []util.Dentry{
				{Name: "memfs:///file1", Ftype: "file (mem)"},
				{Name: "memfs:///dir1/file3", Ftype: "file (mem)"},
				{Name: "memfs:///dir2/subdir/file5", Ftype: "file (mem)"},
			},
			want: []string{"file1", "dir1/", "dir2/"},
		},
		{
			name:   "memfs subdirectory",
			prefix: "memfs:///dir1/",
			dents: []util.Dentry{
				{Name: "memfs:///dir1/file3", Ftype: "file (mem)"},
				{Name: "memfs:///dir1/sub/x", Ftype: "file (mem)"},
			},
			want: []string{"file3", "sub/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := remoteDirListing(tt.prefix, encodeDents(t, tt.dents))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("remoteDirListing(%q) = %v, want %v", tt.prefix, got, tt.want)
			}
		})
	}
}

func TestRemoteDirListingInvalidCBOR(t *testing.T) {
	// The old bug parsed raw CBOR as text; a non-CBOR payload must be rejected
	// rather than yielding garbage completion candidates.
	if got := remoteDirListing("/tmp/", "cwd\nsub/\nfile.txt"); got != nil {
		t.Errorf("remoteDirListing with invalid CBOR = %v, want nil", got)
	}
}

func TestCompletionSegment(t *testing.T) {
	tests := []struct {
		prefix, full, want string
	}{
		// memfs typed with two slashes: candidate supplies the missing slash
		{"memfs://", "memfs:///file1", "/file1"},
		{"memfs://", "memfs:///dir2/subdir/file5", "/dir2/"},
		// memfs canonical/dir prefixes
		{"memfs:///", "memfs:///file1", "file1"},
		{"memfs:///dir1/", "memfs:///dir1/file3", "file3"},
		{"memfs:///dir1/", "memfs:///dir1/sub/x", "sub/"},
		// disk
		{"/etc/", "/etc/hosts", "hosts"},
		{"/etc/", "/etc/ssl/certs", "ssl/"},
		{"/", "/tmp", "tmp"},
		// not under prefix
		{"/etc/", "/var/log", ""},
	}
	for _, tt := range tests {
		if got := completionSegment(tt.prefix, tt.full); got != tt.want {
			t.Errorf("completionSegment(%q, %q) = %q, want %q", tt.prefix, tt.full, got, tt.want)
		}
	}
}

func TestRemoteDirRequest(t *testing.T) {
	// parts are exactly what carapace's ActionMultiParts("/", ...) reports for
	// the typed value in each comment.
	tests := []struct {
		name       string
		parts      []string
		wantPrefix string
		wantDir    string
	}{
		{"no separator yet", nil, "", "/"},
		{"disk partial root", []string{""}, "/", "/"},
		{"disk directory with trailing slash", []string{"", "etc"}, "/etc/", "/etc"},
		{"relative directory", []string{"etc"}, "etc/", "etc"},
		{"disk dir whose name starts with memfs", []string{"memfsfoo"}, "memfsfoo/", "memfsfoo"},
		{"memfs single slash", []string{"memfs:"}, "memfs:/", "memfs:///"},
		{"memfs two slashes", []string{"memfs:", ""}, "memfs://", "memfs:///"},
		{"memfs partial segment", []string{"memfs:", "", ""}, "memfs:///", "memfs:///"},
		{"memfs subdirectory", []string{"memfs:", "", "", "dir1"}, "memfs:///dir1/", "memfs:///dir1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, dir := remoteDirRequest(tt.parts)
			if prefix != tt.wantPrefix || dir != tt.wantDir {
				t.Errorf("remoteDirRequest(%v) = (%q, %q), want (%q, %q)",
					tt.parts, prefix, dir, tt.wantPrefix, tt.wantDir)
			}
		})
	}
}

// carapaceParts invokes ActionMultiParts the same way the path completers do
// and returns the parts the callback observes, so remoteDirRequest's
// assumptions stay tied to real carapace behavior.
func carapaceParts(t *testing.T, value string) []string {
	t.Helper()
	var got carapace.Context
	action := carapace.ActionMultiParts("/", func(c carapace.Context) carapace.Action {
		got = c
		return carapace.ActionValues()
	})
	action.Invoke(carapace.Context{Value: value})
	return got.Parts
}

func TestRemoteDirRequestMatchesCarapaceParts(t *testing.T) {
	tests := map[string]struct {
		prefix, dir string
	}{
		"/etc/":          {"/etc/", "/etc"},
		"memfs:/":        {"memfs:/", "memfs:///"},
		"memfs://":       {"memfs://", "memfs:///"},
		"memfs:///dir1/": {"memfs:///dir1/", "memfs:///dir1"},
	}
	for value, want := range tests {
		prefix, dir := remoteDirRequest(carapaceParts(t, value))
		if prefix != want.prefix || dir != want.dir {
			t.Errorf("value %q: got (%q, %q), want (%q, %q)",
				value, prefix, dir, want.prefix, want.dir)
		}
	}
}
