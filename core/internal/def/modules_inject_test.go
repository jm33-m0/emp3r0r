package def

import "testing"

// TestInjectTokenOption verifies that the universal --token/--user/--ticket
// options are injected context-aware: only into Windows agent modules whose
// execution kind actually runs under an impersonated token. Local modules,
// non-Windows modules and token-management built-ins must not surface flags
// they cannot honor.
func TestInjectTokenOption(t *testing.T) {
	// Windows starlark module: all three options injected.
	win := &ModuleConfig{
		Name:        "test_win_reg",
		Platform:    "Windows",
		AgentConfig: AgentModuleConfig{Type: "starlark"},
	}
	InjectTokenOption(win)
	for _, opt := range []string{"token", "user", "ticket"} {
		if _, ok := win.Options[opt]; !ok {
			t.Fatalf("windows module missing injected option %q", opt)
		}
		if !OptionWasInjected("test_win_reg", opt) {
			t.Fatalf("injected option %q not tracked", opt)
		}
	}

	// Module-declared options always win and are not marked injected.
	own := &ModuleConfig{
		Name:        "test_win_own",
		Platform:    "windows", // lowercase spelling must still match
		AgentConfig: AgentModuleConfig{Type: "coff"},
		Options: ModOptions{
			"user": {Name: "user", Desc: "module's own user param", Type: "wstr"},
		},
	}
	InjectTokenOption(own)
	if d := own.Options["user"].Desc; d != "module's own user param" {
		t.Fatalf("module-declared user option clobbered: %q", d)
	}
	if OptionWasInjected("test_win_own", "user") {
		t.Fatalf("module-declared user option marked as injected")
	}
	if _, ok := own.Options["ticket"]; !ok {
		t.Fatalf("module with own user still missing injected ticket")
	}

	// Local (C2 plugin) modules never execute on an agent: nothing injected,
	// even when they target Windows.
	local := &ModuleConfig{
		Name:        "test_local_win",
		IsLocal:     true,
		Platform:    "Windows",
		AgentConfig: AgentModuleConfig{Type: "coff"},
	}
	InjectTokenOption(local)
	for _, opt := range []string{"token", "user", "ticket"} {
		if _, ok := local.Options[opt]; ok {
			t.Fatalf("local module must not get injected option %q", opt)
		}
	}

	// Non-Windows modules (linux/generic/empty platform) get nothing.
	for name, platform := range map[string]string{
		"test_linux":   "Linux",
		"test_generic": "Generic",
		"test_unknown": "",
	} {
		mod := &ModuleConfig{
			Name:        name,
			Platform:    platform,
			AgentConfig: AgentModuleConfig{Type: "starlark"},
		}
		InjectTokenOption(mod)
		for _, opt := range []string{"token", "user", "ticket"} {
			if _, ok := mod.Options[opt]; ok {
				t.Fatalf("module %s (platform %q) must not get injected option %q", name, platform, opt)
			}
		}
	}

	// Windows modules that spawn child processes cannot be impersonated:
	// nothing injected.
	child := &ModuleConfig{
		Name:        "test_win_child",
		Platform:    "Windows",
		AgentConfig: AgentModuleConfig{Type: "powershell"},
	}
	InjectTokenOption(child)
	for _, opt := range []string{"token", "user", "ticket"} {
		if _, ok := child.Options[opt]; ok {
			t.Fatalf("child-process module must not get injected option %q", opt)
		}
	}

	// steal_token accepts --token (impersonate an existing token while
	// stealing); the other token-management built-ins get nothing.
	steal := &ModuleConfig{Name: ModStealToken, Platform: "Windows", AgentConfig: AgentModuleConfig{Type: "go"}}
	InjectTokenOption(steal)
	if _, ok := steal.Options["token"]; !ok {
		t.Fatalf("%s missing token option", ModStealToken)
	}
	if _, ok := steal.Options["user"]; ok {
		t.Fatalf("%s should not get injected --user", ModStealToken)
	}
	if _, ok := steal.Options["ticket"]; ok {
		t.Fatalf("%s should not get injected --ticket", ModStealToken)
	}
	for _, name := range []string{ModListTokens, ModListSessions} {
		mod := &ModuleConfig{Name: name, Platform: "Windows", AgentConfig: AgentModuleConfig{Type: "go"}}
		InjectTokenOption(mod)
		if len(mod.Options) != 0 {
			t.Fatalf("%s should get no injected options, got %v", name, mod.Options)
		}
	}
}
