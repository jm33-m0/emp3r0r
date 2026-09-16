//go:build windows

package main

import "testing"

func TestScanFlag(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		flag  string
		want  string
		found bool
	}{
		{"space", []string{"-bof", "x.o", "-config", "cfg.json"}, "config", "cfg.json", true},
		{"double dash", []string{"--module", "kerbeus_klist"}, "module", "kerbeus_klist", true},
		{"equals", []string{"--config=cfg.json"}, "config", "cfg.json", true},
		{"single equals", []string{"-module=mod"}, "module", "mod", true},
		{"missing", []string{"-bof", "x.o"}, "config", "", false},
		{"no value", []string{"-config"}, "config", "", false},
		{"after terminator", []string{"--", "-config", "cfg.json"}, "config", "", false},
		{"prefix is not a match", []string{"-configure", "x"}, "config", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := scanFlag(tc.args, tc.flag)
			if found != tc.found || got != tc.want {
				t.Fatalf("scanFlag(%v, %q) = (%q, %v), want (%q, %v)", tc.args, tc.flag, got, found, tc.want, tc.found)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	args, err := parseArgs("z:hello, Z:wide, i:1234, s:7, b:aGk=")
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(args) != 5 {
		t.Fatalf("got %d args, want 5", len(args))
	}
	wantTypes := []string{"z", "Z", "i", "s", "b"}
	for i, want := range wantTypes {
		if args[i].WireType != want {
			t.Errorf("arg %d wire = %q, want %q", i, args[i].WireType, want)
		}
	}
	if args[2].Value != int64(1234) {
		t.Errorf("int arg = %#v, want int64(1234)", args[2].Value)
	}

	if _, err := parseArgs("q:value"); err == nil {
		t.Error("expected an error for an unsupported wire type")
	}
	if _, err := parseArgs("i:not-a-number"); err == nil {
		t.Error("expected an error for a non-numeric int")
	}
}
