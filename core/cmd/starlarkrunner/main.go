//go:build windows

// starlarkrunner is a standalone debug tool that runs a Starlark module the
// exact same way the agent does (lib/script.Run) — optionally under a
// make_token netonly session with an imported Kerberos ticket, mirroring the
// `--token <session>` flow. Use it to compare the starlark win_call path
// against the COFF/BOF path and to debug why a module misbehaves under a
// session.
//
// Usage:
//
//	starlarkrunner -script dir.star [-arg "\\server\share\*"] \
//	              [-make-token user -domain d -password p] \
//	              [-import-ticket ticket.kirbi] \
//	              [-direct-test "\\server\share\*"]
//
// -direct-test additionally exercises FindFirstFileW on the given UNC path
// with three impersonation patterns (no token / per-call like win_call /
// whole-block like the COFF PreExecHook) so the mechanisms can be compared.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/priv"
	"github.com/jm33-m0/emp3r0r/core/lib/script"
	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		scriptPath  = flag.String("script", "", "path to a .star module")
		arg         = flag.String("arg", "", "argument passed to main(*args) (repeatable: comma-separated)")
		makeToken   = flag.String("make-token", "", "create a netonly make_token session for this user")
		domain      = flag.String("domain", ".", "domain for -make-token")
		password    = flag.String("password", "dummy", "password for -make-token (never validated)")
		importTkt   = flag.String("import-ticket", "", "path to a .kirbi (or base64) to import into the session")
		directTest  = flag.String("direct-test", "", "UNC path to exercise with raw FindFirstFileW under 3 impersonation patterns")
	)
	flag.Parse()

	if _, err := syscall.GetRuntimeSyscallTable(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] syscall table: %v\n", err)
		return 1
	}

	// Wire the same hooks the agent wires (mod_windows.go init).
	script.ImpersonateFn = func(token uintptr) error {
		return priv.ImpersonateThread(windows.Handle(token))
	}
	script.RevertFn = func() { priv.RevertThread() }
	script.ExecWithToken = func(token uintptr, commandLine string) error {
		return priv.CreateProcessWithToken(windows.Handle(token), commandLine)
	}

	var token uintptr
	if *makeToken != "" {
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
	}

	if *directTest != "" {
		directTests(*directTest, token)
	}

	if *scriptPath == "" {
		fmt.Fprintln(os.Stderr, "no -script given; use -direct-test to compare impersonation patterns, or -script to run a module")
		return 2
	}

	src, err := os.ReadFile(*scriptPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] read script: %v\n", err)
		return 1
	}

	var argv []string
	for _, a := range strings.Split(*arg, ",") {
		if a != "" {
			argv = append(argv, a)
		}
	}
	fmt.Fprintf(os.Stderr, "[*] running %s (argv=%v) via script.Run under token=0x%x\n\n", *scriptPath, argv, token)
	out, runErr := script.Run(src, argv, nil, token)
	if out != "" {
		fmt.Print(out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Println()
		}
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "\n[!] starlark run failed: %v\n", runErr)
		return 1
	}
	return 0
}

// findFirstFileW is a direct FindFirstFileW call used by the pattern tests.
func findFirstFileW(unc string) error {
	p, err := windows.UTF16PtrFromString(unc)
	if err != nil {
		return err
	}
	var fd windows.Win32finddata
	h, err := windows.FindFirstFile(p, &fd)
	if err != nil {
		return err
	}
	windows.FindClose(h)
	return nil
}

// directTests compares three impersonation patterns for FindFirstFileW on a
// UNC path:
//
//	none            - process identity (no token)
//	per-call        - ImpersonateThread/RevertThread around the call (win_call)
//	whole-block     - ExecuteAsToken around the call (COFF PreExecHook pattern)
func directTests(unc string, token uintptr) {
	fmt.Fprintf(os.Stderr, "[*] direct FindFirstFileW tests on %s\n", unc)

	if err := findFirstFileW(unc); err != nil {
		fmt.Fprintf(os.Stderr, "    none         : %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "    none         : OK\n")
	}

	if token == 0 {
		fmt.Fprintf(os.Stderr, "    (no session token for the remaining patterns)\n")
		return
	}

	// per-call pattern (starlark runWithToken)
	err := func() error {
		if err := priv.ImpersonateThread(windows.Handle(token)); err != nil {
			return err
		}
		defer priv.RevertThread()
		return findFirstFileW(unc)
	}()
	if err != nil {
		fmt.Fprintf(os.Stderr, "    per-call     : %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "    per-call     : OK\n")
	}

	// whole-block pattern (COFF PreExecHook)
	err = priv.ExecuteAsToken(windows.Handle(token), func() error {
		return findFirstFileW(unc)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "    whole-block  : %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "    whole-block  : OK\n")
	}

	// thread-token identity while impersonated (whoami path)
	_ = priv.ExecuteAsToken(windows.Handle(token), func() error {
		var hTok windows.Token
		if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &hTok); err != nil {
			fmt.Fprintf(os.Stderr, "    thread token : open failed: %v\n", err)
			return nil
		}
		defer windows.CloseHandle(windows.Handle(hTok))
		fmt.Fprintf(os.Stderr, "    thread token : %s\n", priv.GetTokenFriendlyName(windows.Handle(hTok)))
		return nil
	})
}
