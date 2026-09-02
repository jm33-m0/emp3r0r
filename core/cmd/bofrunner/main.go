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
//	bofrunner -bof /path/to/bof.o [-dll /path/to/COFFLoader.x64.dll] \
//	          [-entry go] [-args "z:arg1,i:1234"]
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/priv"
	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		dllPath     = flag.String("dll", "", "path to COFFLoader DLL (auto-detected when empty)")
		bofPath     = flag.String("bof", "", "path to BOF object file (.o)")
		entry       = flag.String("entry", "go", "BOF entry function name")
		argsStr     = flag.String("args", "", `comma-separated BOF args: z:str, Z:wide, i:int, s:short, b:base64/hex`)
		makeToken   = flag.String("make-token", "", "create a netonly make_token session for this user and run the BOF under it")
		domain      = flag.String("domain", ".", "domain for -make-token (default: local machine)")
		password    = flag.String("password", "dummy", "password for -make-token (never validated, netonly)")
		importTkt   = flag.String("import-ticket", "", "path to a .kirbi (or base64 string) to import into the session before running")
	)
	flag.Parse()

	if *bofPath == "" {
		fmt.Fprintln(os.Stderr, "usage: bofrunner -bof <bof.o> [-dll <COFFLoader.dll>] [-entry go] [-args z:str,i:int] [-make-token user] [-domain d] [-password p] [-import-ticket ticket.kirbi]")
		flag.PrintDefaults()
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

	args, err := parseArgs(*argsStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] parse args: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "[*] COFFLoader DLL: %s (%d bytes)\n", dllFile, len(dllData))
	fmt.Fprintf(os.Stderr, "[*] BOF: %s (entry=%s, %d args)\n", *bofPath, *entry, len(args))

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

	fmt.Fprintf(os.Stderr, "[*] Loading COFFLoader DLL in-memory and executing BOF...\n\n")

	out, execErr := coffloader.RunWindowsCOFFViaDLL(dllData, payload, *entry, args, token)
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
