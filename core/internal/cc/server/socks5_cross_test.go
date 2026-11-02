package server

// socks5_cross_test.go — a C agent always reports the result of the module it
// was dispatched, success included, so that answer and its relay stream cross.
// Whichever is decided first owns the CONNECT: a matched stream must never be
// torn down by the result that followed it.

import "testing"

func newTestProxyEntry(t *testing.T) *socks5ProxyEntry {
	t.Helper()
	return &socks5ProxyEntry{
		token:    "socks5-test",
		streamUp: make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// A stream that answered the CONNECT wins over the dispatch result, which is
// what keeps a live relay from being closed the moment the agent reports back.
func TestSocks5StreamWinsOverDispatchResult(t *testing.T) {
	entry := newTestProxyEntry(t)
	stream, peer := tcpPair(t)
	t.Cleanup(func() { _ = peer.Close() })

	entry.markStreamUp(stream)
	if entry.failResult() {
		t.Fatal("a matched CONNECT was failed by the dispatch result")
	}
	if entry.resultFailed() {
		t.Fatal("a matched CONNECT was marked failed")
	}
	select {
	case <-entry.streamUp:
	default:
		t.Fatal("streamUp was not closed when the stream matched")
	}
}

// A result with no stream behind it is a dial failure; a stream that arrives
// afterwards belongs to that failed attempt and must be dropped.
func TestSocks5FailedResultDropsLateStream(t *testing.T) {
	entry := newTestProxyEntry(t)
	if !entry.failResult() {
		t.Fatal("an unanswered CONNECT was not failed by the result")
	}
	if !entry.resultFailed() {
		t.Fatal("the failed CONNECT was not recorded")
	}
	select {
	case <-entry.streamUp:
		t.Fatal("a failed CONNECT reported its stream as up")
	default:
	}
}
