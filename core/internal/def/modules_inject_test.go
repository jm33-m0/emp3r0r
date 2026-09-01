package def

import "testing"

// TestInjectTokenOption verifies that the universal --token/--user/--ticket
// options are injected into regular modules, that module-declared options
// win, and that the token-management built-ins only get --token.
func TestInjectTokenOption(t *testing.T) {
	// Regular module: all three options injected.
	reg := &ModuleConfig{Name: "test_reg"}
	InjectTokenOption(reg)
	for _, opt := range []string{"token", "user", "ticket"} {
		if _, ok := reg.Options[opt]; !ok {
			t.Fatalf("regular module missing injected option %q", opt)
		}
		if !OptionWasInjected("test_reg", opt) {
			t.Fatalf("injected option %q not tracked", opt)
		}
	}

	// Module-declared options always win and are not marked injected.
	own := &ModuleConfig{Name: "test_own", Options: ModOptions{
		"user": {Name: "user", Desc: "module's own user param", Type: "wstr"},
	}}
	InjectTokenOption(own)
	if d := own.Options["user"].Desc; d != "module's own user param" {
		t.Fatalf("module-declared user option clobbered: %q", d)
	}
	if OptionWasInjected("test_own", "user") {
		t.Fatalf("module-declared user option marked as injected")
	}
	if _, ok := own.Options["ticket"]; !ok {
		t.Fatalf("module with own user still missing injected ticket")
	}

	// Token-management built-ins only get --token.
	for _, name := range []string{ModStealToken, ModListTokens, ModMakeToken, ModListSessions, ModImportTicket} {
		mod := &ModuleConfig{Name: name}
		InjectTokenOption(mod)
		if _, ok := mod.Options["token"]; !ok {
			t.Fatalf("%s missing token option", name)
		}
		if _, ok := mod.Options["user"]; ok {
			t.Fatalf("%s should not get injected --user", name)
		}
		if _, ok := mod.Options["ticket"]; ok {
			t.Fatalf("%s should not get injected --ticket", name)
		}
	}
}
