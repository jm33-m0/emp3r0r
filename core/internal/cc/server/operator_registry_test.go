package server

import "testing"

// TestUnregisterOperatorConnKeepsNewerRegistration verifies that a stale
// operator-tunnel teardown cannot remove a newer connection registered under
// the same session name. This is the cross-test race where a slow goroutine
// from a previous test deletes the next test's operator marker: the previous
// test closes its operator pipe in cleanup, but the tunnel goroutine only
// removes the registry entry once it observes the close, which can happen after
// the next test already called MarkOperatorOnline.
func TestUnregisterOperatorConnKeepsNewerRegistration(t *testing.T) {
	session := "test-stale-operator-teardown"
	op1 := &operator_t{sessionID: session}
	op2 := &operator_t{sessionID: session}
	OPERATORS.Store(session, op1)
	defer OPERATORS.Delete(session)

	// A newer connection replaces op1.
	OPERATORS.Store(session, op2)

	if unregisterOperatorConn(session, op1) {
		t.Fatal("stale teardown reported removing a registration it no longer owned")
	}
	if got, ok := OPERATORS.Load(session); !ok || got != op2 {
		t.Fatal("stale teardown removed the newer operator registration")
	}

	// The current owner can still remove itself.
	if !unregisterOperatorConn(session, op2) {
		t.Fatal("owner teardown did not remove its own registration")
	}
	if _, ok := OPERATORS.Load(session); ok {
		t.Fatal("owner registration still present after teardown")
	}
}
