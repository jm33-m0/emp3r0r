package gui

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeHost is a ConsoleHost test double: Connect/Configure are no-ops,
// RunConsole blocks until released, SelectAgent just records the call.
type fakeHost struct {
	mu       sync.Mutex
	selected []string
	runBlock chan struct{}
	released bool
}

func newFakeHost() *fakeHost {
	return &fakeHost{runBlock: make(chan struct{})}
}

func (h *fakeHost) Connect(creds Creds) error { return nil }
func (h *fakeHost) Disconnect()               {}
func (h *fakeHost) ConfigureConsole()         {}
func (h *fakeHost) RunConsole() error {
	<-h.runBlock
	return nil
}
func (h *fakeHost) SelectAgent(tag string) bool {
	h.mu.Lock()
	h.selected = append(h.selected, tag)
	h.mu.Unlock()
	return true
}
func (h *fakeHost) Agents() []Agent { return nil }
func (h *fakeHost) release() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.released {
		h.released = true
		close(h.runBlock)
	}
}

// testClient is a registered websocket stand-in whose outbound queue is
// drained by a goroutine, so blocking broadcasts never stall the test.
func testClient(b *Backend) *wsClient {
	c := &wsClient{send: make(chan []byte, 256), closed: make(chan struct{})}
	b.mu.Lock()
	b.clients[c] = struct{}{}
	b.mu.Unlock()
	go func() {
		for {
			select {
			case <-c.send:
			case <-c.closed:
				return
			}
		}
	}()
	return c
}

func dropClient(b *Backend, c *wsClient) { b.removeClient(c) }

// TestRaceSmoke drives the message paths that several goroutines use at once
// (websocket handlers, pty output, log mirroring, shutdown) and runs it under
// `go test -race`. No pty is attached, so the session/console parts that need
// real stdio are not covered here (gui_shell/pty tests cover those).
func TestRaceSmoke(t *testing.T) {
	host := newFakeHost()
	b := newBackend(host, StartOptions{})
	client := testClient(b)
	defer dropClient(b, client)

	// Make sure requestExit's session-file clear does not fight LogSync.
	defer host.release()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	workers := []func(int){
		func(i int) {
			b.handleResize(wsMessage{Cols: uint16(100 + i%40), Rows: uint16(24 + i%20)})
		},
		func(i int) {
			_ = b.writePty([]byte(fmt.Sprintf("keystroke %d\n", i)))
		},
		func(i int) {
			b.Write([]byte(fmt.Sprintf("log line %d\n", i)))
		},
		func(i int) {
			b.handleMessage(client, []byte(fmt.Sprintf(`{"type":"select_agent","id":"agent-%d"}`, i%5)))
		},
		func(i int) {
			b.handleMessage(client, []byte(fmt.Sprintf(`{"type":"pty_input","data":"aGVsbG8="}`)))
		},
		func(i int) {
			LogSync("race smoke line %d", i)
		},
	}

	for w := 0; w < len(workers); w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
					workers[w](i)
					if i%50 == 0 {
						time.Sleep(time.Microsecond)
					}
				}
			}
		}()
	}

	// let the workers churn, then tear everything down mid-flight
	time.Sleep(300 * time.Millisecond)
	b.shutdown()
	close(stop)
	wg.Wait()

	if len(host.selected) == 0 {
		t.Fatal("expected at least one SelectAgent call")
	}
	_ = LogSync
}
