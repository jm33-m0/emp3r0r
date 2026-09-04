package gui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
)

// guiAssets embeds the entire static frontend (index.html, app.js, style.css
// and the build-time downloaded terminal assets) into the cc binary.
//
// The third-party JS/CSS (xterm.js, MIT) are NOT committed: run
//
//	go generate ./internal/cc/operator
//
// (or build through core/build.py, which fetches them automatically) before
// compiling, so the embed below always has a complete frontend.
//
//go:generate go run ./guiassets
//go:embed all:gui
var guiAssets embed.FS

// StartOptions carries the CLI flags that make sense for the GUI entry
// point (emp3r0r client --gui).
type StartOptions struct {
	// C2Host is the default C2 host to prefill in the login box (usually
	// 127.0.0.1 when the cc runs on the same machine as the server).
	C2Host string
	// OperatorPort default operator server port hint for the login box.
	OperatorPort int
	// CdnProxy starts a cdn2proxy relay after logging in (like the CLI flag).
	CdnProxy string
}

// backendRef is the running GUI backend while Run is executing; it is read
// from other goroutines (agent refreshes, console exit), so it is an atomic
// pointer rather than a plain global.
var backendRef atomic.Pointer[Backend]

// ActiveBackend returns the running GUI backend, or nil when none is up.
func ActiveBackend() *Backend {
	return backendRef.Load()
}

// wsClient is one connected browser frontend.
type wsClient struct {
	conn   *websocket.Conn
	send   chan []byte // outbound frames, drained by writeLoop
	closed chan struct{}
}

// trySend queues a frame for this client. When blocking is true the caller
// waits until the frame is queued or the client goes away (reliable frames
// like pty output); otherwise the frame is dropped when the queue is full
// (log spam must never stall the logger).
func (c *wsClient) trySend(payload []byte, blocking bool) {
	select {
	case <-c.closed:
		return
	default:
	}
	if blocking {
		select {
		case c.send <- payload:
		case <-c.closed:
		}
		return
	}
	select {
	case c.send <- payload:
	default:
	}
}

// writeLoop drains the client's outbound queue. It also pings the peer
// periodically so silently-dead browsers are reaped (removed + closed) even
// when there is no traffic to flush them out.
func (c *wsClient) writeLoop(g *Backend) {
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case payload := <-c.send:
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			err := c.conn.Write(ctx, websocket.MessageText, payload)
			cancel()
			if err != nil {
				g.removeClient(c)
				return
			}
		case <-ping.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := c.conn.Ping(ctx)
			cancel()
			if err != nil {
				g.removeClient(c)
				return
			}
		case <-c.closed:
			return
		}
	}
}

// removeClient drops a client from the hub and unblocks anyone waiting to
// enqueue frames for it. Idempotent: both the reader and the writer call it.
func (g *Backend) removeClient(c *wsClient) {
	g.mu.Lock()
	if _, ok := g.clients[c]; ok {
		delete(g.clients, c)
		close(c.closed)
	}
	g.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close(websocket.StatusNormalClosure, "")
	}
}

// wsMessage is a JSON frame coming from the frontend.
type wsMessage struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Data    string `json:"data"`
	ID      string `json:"id"`
	Cols    uint16 `json:"cols"`
	Rows    uint16 `json:"rows"`
}

// Backend hosts the operator GUI: the embedded web frontend, the websocket
// bridge to the interactive console pty, the log broadcast writer and the
// state of the current C2 session.
type Backend struct {
	mu      sync.Mutex
	clients map[*wsClient]struct{}
	ln      net.Listener
	srv     *http.Server
	bind    string
	bindIP  string
	port    int
	token   string

	defaults StartOptions

	sessionMu  sync.Mutex
	connected  bool
	connecting bool // a login flow (WireGuard/config/console start) is in flight
	creds      Creds
	ptyMaster  *os.File
	lastResize termSize
	host       ConsoleHost // operator console being presented (set by Run)
	ptyWriteMu sync.Mutex
	ptyBufMu   sync.Mutex
	ptyBuf     []byte

	// OS shell sessions (local, child processes on their own ptys)
	shellMu    sync.Mutex
	shells     map[string]*shellSession
	shellBufMu sync.Mutex
	shellBufs  map[string][]byte

	// consoleRunning is true while the interactive console session is alive
	// in the command pane (set at login, cleared when the console exits).
	consoleRunning atomic.Bool

	shutdownOnce sync.Once
	closeOnce    sync.Once
	shutdownC    chan struct{}
}

func newBackend(host ConsoleHost, opts StartOptions) *Backend {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		// extremely unlikely; fall back to a time-based token so the GUI can
		// still start
		tokenBytes = []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	return &Backend{
		clients:   make(map[*wsClient]struct{}),
		token:     hex.EncodeToString(tokenBytes),
		defaults:  opts,
		host:      host,
		shutdownC: make(chan struct{}),
		shells:    make(map[string]*shellSession),
		shellBufs: make(map[string][]byte),
	}
}

// Write implements io.Writer so the backend can be registered with
// logging.AddWriter(): every log line the operator console produces is
// forwarded to the GUI log pane (this is the GUI equivalent of tmux's Output
// pane, which cats the same stream).
func (g *Backend) Write(p []byte) (int, error) {
	g.broadcast(map[string]any{
		"type": "log",
		"msg":  string(p),
	}, false)
	return len(p), nil
}

func (g *Backend) closePty() {
	g.sessionMu.Lock()
	if g.ptyMaster != nil {
		_ = g.ptyMaster.Close()
		g.ptyMaster = nil
	}
	g.sessionMu.Unlock()
}

// Run starts the browser GUI for the given operator console host and blocks
// until the daemon exits. It is the lib/gui entry point; the operator console
// package (internal/cc/operator) owns the daemon preflight (stdio safety,
// reattach check, stub copy) and calls Run with itself as the host.
func Run(host ConsoleHost, opts StartOptions) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("gui.Run panicked: %v", r)
		}
	}()

	LogSync("GUI starting (pid %d, version %s)", os.Getpid(), def.Version)
	g := newBackend(host, opts)
	backendRef.Store(g)
	defer g.shutdown()
	defer func() { backendRef.Store(nil) }()

	// from here on, every operator log is mirrored to the GUI log pane
	logging.AddWriter(g)

	if err := g.serve(); err != nil {
		logging.Errorf("Failed to start GUI server: %v", err)
		return
	}

	logging.Successf("══════════════════ emp3r0r GUI ══════════════════")
	logging.Successf("Open:   %s", g.url())
	logging.Infof("Token:  %s", g.token)
	logging.Infof("This GUI only listens on %s; the token in the URL is your session credential.", g.bind)
	logging.Successf("Paste the C2 server's connection command into the login box to start.")
	LogSync("GUI server listening on %s, opening browser", g.url())
	g.openBrowser()
	LogSync("GUI waiting for operator session (pid %d)", os.Getpid())

	// If the operator connected to a C2 in a previous run and did not exit on
	// purpose, reconnect automatically: no WireGuard connection command needs
	// to be pasted again, whatever happened to the old daemon or the tab.
	go g.autoLoginSaved()

	// Log common termination signals synchronously (terminal close = SIGHUP,
	// Ctrl+C = SIGINT, ...) so an external kill is never a silent mystery.
	// The GUI is terminal-independent: SIGHUP (controlling terminal went
	// away) and SIGPIPE (writing to a closed terminal) must NOT kill it —
	// only SIGINT/SIGTERM/SIGQUIT (or the Exit button) stop it.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGPIPE)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP, syscall.SIGPIPE:
				LogSync("GUI received %v — ignoring (GUI is terminal-independent)", sig)
			default:
				LogSync("GUI received signal %v — shutting down", sig)
				g.shutdown()
				if s, ok := sig.(syscall.Signal); ok {
					os.Exit(128 + int(s))
				}
				os.Exit(1)
			}
		}
	}()

	<-g.shutdownC
	LogSync("GUI wait returned — process exiting cleanly")
}

// serve binds the local HTTP server (random free port on 127.0.0.1 by
// default; override with EMP3R0R_GUI_BIND=host:port).
func (g *Backend) serve() error {
	g.bind = os.Getenv("EMP3R0R_GUI_BIND")
	if g.bind == "" {
		g.bind = "127.0.0.1"
	}
	host, portStr, err := net.SplitHostPort(g.bind)
	if err != nil {
		host = g.bind
		portStr = ""
	}
	port := 0
	if portStr != "" {
		if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 && p < 65536 {
			port = p
		}
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		// fall back to an ephemeral port
		ln, err = net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			return err
		}
	}
	g.ln = ln
	g.port = ln.Addr().(*net.TCPAddr).Port
	g.bindIP = host
	g.srv = &http.Server{Handler: g.handler()}
	go func() {
		if serr := g.srv.Serve(ln); serr != nil && serr != http.ErrServerClosed {
			logging.Errorf("GUI http server: %v", serr)
		}
	}()
	return nil
}

func (g *Backend) url() string {
	ip := g.bindIP
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		ip = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s/?token=%s", net.JoinHostPort(ip, strconv.Itoa(g.port)), g.token)
}

func (g *Backend) openBrowser() {
	launchBrowser(g.url())
}

func (g *Backend) handler() http.Handler {
	sub, err := fs.Sub(guiAssets, "gui")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/ws", g.handleWS)
	return mux
}

func (g *Backend) handleWS(w http.ResponseWriter, r *http.Request) {
	defer guiRecover("gui websocket handler")
	if r.URL.Query().Get("token") != g.token {
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(1 << 20)

	c := &wsClient{
		conn:   conn,
		send:   make(chan []byte, 4096),
		closed: make(chan struct{}),
	}
	g.mu.Lock()
	g.clients[c] = struct{}{}
	g.mu.Unlock()

	go c.writeLoop(g)
	g.pushInitial(c)

	defer g.removeClient(c)

	ctx := r.Context()
	for {
		_, data, rerr := conn.Read(ctx)
		if rerr != nil {
			return
		}
		g.handleMessage(c, data)
	}
}

func (g *Backend) pushInitial(c *wsClient) {
	g.sessionMu.Lock()
	connected := g.connected
	server := ""
	if g.creds.C2Host != "" {
		server = g.creds.C2Host
	}
	g.sessionMu.Unlock()
	g.sendTo(c, map[string]any{
		"type":      "state",
		"connected": connected,
		"server":    server,
		"console":   g.consoleRunning.Load(),
		"gui":       def.Version,
	}, false)
	if g.host != nil {
		if ags := g.host.Agents(); len(ags) > 0 {
			g.sendTo(c, agentListMessage{Type: "agents", Agents: ags}, false)
		}
	}
}

// sendTo queues a frame on a single client.
func (g *Backend) sendTo(c *wsClient, v any, blocking bool) {
	payload, err := json.Marshal(v)
	if err != nil {
		return
	}
	c.trySend(payload, blocking)
}

// broadcast marshals and queues a frame to every connected frontend. blocking
// frames (pty output, agent lists, login results) are reliable; non-blocking
// frames (log lines) may be dropped for slow clients. Clients are snapshotted
// under the lock but enqueued without it, so one slow browser never stalls
// the logger or the pty reader.
func (g *Backend) broadcast(v any, blocking bool) {
	payload, err := json.Marshal(v)
	if err != nil {
		return
	}
	g.mu.Lock()
	clients := make([]*wsClient, 0, len(g.clients))
	for c := range g.clients {
		clients = append(clients, c)
	}
	g.mu.Unlock()
	for _, c := range clients {
		c.trySend(payload, blocking)
	}
}

// publish is an alias used by gui_agents.go.
func (g *Backend) publish(v any, blocking bool) {
	g.broadcast(v, blocking)
}

func (g *Backend) handleMessage(c *wsClient, data []byte) {
	var msg wsMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		logging.Debugf("gui: bad message: %v", err)
		return
	}
	switch msg.Type {
	case "ping":
		g.sendTo(c, map[string]any{"type": "pong"}, false)
	case "login":
		g.handleLogin(c, msg.Command)
	case "pty_input":
		if msg.Data == "" {
			return
		}
		raw, err := decodeBase64(msg.Data)
		if err != nil {
			logging.Debugf("gui: bad pty input: %v", err)
			return
		}
		if err := g.writePty(raw); err != nil {
			logging.Debugf("gui: pty input dropped: %v", err)
		}
	case "pty_resize":
		g.handleResize(msg)
	case "term_ready":
		// send any pty output produced before this frontend attached
		if buf := g.ptyBufSnapshot(); len(buf) > 0 {
			g.sendTo(c, map[string]any{
				"type": "pty_out",
				"data": encodeBase64(buf),
			}, true)
		}
	case "select_agent":
		if msg.ID == "" || g.host == nil {
			return
		}
		g.host.SelectAgent(msg.ID)
	case "shell_open":
		g.handleShellOpen(c, msg)
	case "shell_input":
		if msg.Data == "" {
			return
		}
		raw, err := decodeBase64(msg.Data)
		if err != nil {
			logging.Debugf("gui: bad shell input: %v", err)
			return
		}
		if err := g.writeShell(msg.ID, raw); err != nil {
			logging.Debugf("gui: shell input dropped: %v", err)
		}
	case "shell_resize":
		g.resizeShell(msg)
	case "shell_close":
		g.closeShell(msg.ID)
	case "exit":
		// The Exit button must always take the whole GUI daemon down, even
		// when the console is wedged (readline blocked waiting on a terminal
		// query / user input) and can never process an "exit\n" written to
		// its pty. Ask the console to quit cleanly first, but never leave
		// the daemon behind: force the shutdown shortly after if the console
		// does not die on its own (its exit path os.Exit(0)s the process).
		g.sessionMu.Lock()
		connected := g.connected
		g.sessionMu.Unlock()
		if connected && g.consoleRunning.Load() {
			_ = g.writePty([]byte("exit\n"))
			go func() {
				time.Sleep(3 * time.Second)
				if g.consoleRunning.Load() {
					LogSync("Console did not exit on its own — forcing GUI shutdown")
				}
				g.requestExit()
			}()
			return
		}
		g.requestExit()
	}
}

func (g *Backend) handleLogin(c *wsClient, rawCmd string) {
	creds, err := ParseConnectionCommand(rawCmd)
	if err != nil {
		g.sendTo(c, map[string]any{"type": "login_result", "ok": false, "error": err.Error()}, true)
		return
	}
	g.sessionMu.Lock()
	already := g.connected
	busy := g.connecting
	if !busy {
		g.connecting = true
	}
	g.sessionMu.Unlock()
	if already {
		g.sendTo(c, map[string]any{"type": "login_result", "ok": true}, true)
		return
	}
	if busy {
		// A login is already being established (WireGuard/config/console).
		// Running two connect flows concurrently would each dup2 their own
		// pty over fds 0/1/2 and start EMP3R0R_CONSOLE.Start() twice on the
		// same console object — the two readline loops then split stdin and
		// typing dies (duplicated prompts, input goes nowhere).
		g.sendTo(c, map[string]any{
			"type":  "login_result",
			"ok":    false,
			"error": "login already in progress — wait for it to finish",
		}, true)
		return
	}

	// The connect flow (WireGuard up, config download, console start) runs in
	// the background; progress shows up in the log pane of the login box.
	go g.runLogin(creds)
}

// runLogin performs the connect flow (WG up, config download, console start)
// for the given credentials and broadcasts the outcome to every frontend. It
// is the shared body of the login box flow and the saved-session auto-login.
func (g *Backend) runLogin(creds Creds) {
	defer guiRecover("gui login")
	defer func() {
		g.sessionMu.Lock()
		g.connecting = false
		g.sessionMu.Unlock()
	}()
	loginErr := g.startSession(creds)
	if loginErr != nil {
		logging.Errorf("Login failed: %v", loginErr)
		g.broadcast(map[string]any{"type": "login_result", "ok": false, "error": loginErr.Error()}, true)
		return
	}
	// remember the successful connection so the next daemon start can
	// reconnect automatically (cleared only when the operator exits on purpose)
	guiSaveSessionCreds(creds)
	g.broadcast(map[string]any{"type": "login_result", "ok": true}, true)
	g.sessionMu.Lock()
	server := g.creds.C2Host
	g.sessionMu.Unlock()
	g.broadcast(map[string]any{"type": "state", "connected": true, "server": server, "console": g.consoleRunning.Load(), "gui": def.Version}, false)
	if g.defaults.CdnProxy != "" {
		guiStartCdn2Proxy(g.defaults.CdnProxy)
	}
}

// autoLoginSaved reconnects to the last C2 without any operator input when
// the daemon starts and a previous session was saved. The login box stays
// available if the reconnect fails (server down, WG keys revoked, ...).
func (g *Backend) autoLoginSaved() {
	creds, ok := guiLoadSessionCreds()
	if !ok {
		return
	}
	g.sessionMu.Lock()
	busy := g.connecting
	already := g.connected
	if !busy && !already {
		g.connecting = true
	}
	g.sessionMu.Unlock()
	if busy || already {
		return
	}
	logging.Infof("Auto-reconnecting to C2 %s with the saved session", creds.C2Host)
	LogSync("auto-login: reconnecting to C2 %s (saved session — no connection command needed)", creds.C2Host)
	go g.runLogin(creds)
}

func (g *Backend) handleResize(msg wsMessage) {
	if msg.Cols == 0 || msg.Rows == 0 {
		return
	}
	g.sessionMu.Lock()
	g.lastResize = termSize{Cols: msg.Cols, Rows: msg.Rows}
	master := g.ptyMaster
	g.sessionMu.Unlock()
	if master != nil {
		_ = guiSetPtySize(master, msg.Cols, msg.Rows)
	}
}

func (g *Backend) ptyBufSnapshot() []byte {
	g.ptyBufMu.Lock()
	defer g.ptyBufMu.Unlock()
	if len(g.ptyBuf) == 0 {
		return nil
	}
	out := make([]byte, len(g.ptyBuf))
	copy(out, g.ptyBuf)
	return out
}

// requestExit asks GuiMain to return (used when the console exits).
func (g *Backend) requestExit() {
	// Leaving on purpose (Exit button / force-exit after a wedged console):
	// forget the saved session so the next start shows the login box again.
	// A daemon that dies on its own keeps the file, so a restart can
	// auto-reconnect without re-entering the connection command.
	ClearSession()
	g.closeOnce.Do(func() {
		close(g.shutdownC)
	})
}

// shutdown tears the whole GUI down: console session pty, WireGuard tunnel,
// websocket clients and the HTTP server.
func (g *Backend) shutdown() {
	g.shutdownOnce.Do(func() {
		g.closeOnce.Do(func() {
			close(g.shutdownC)
		})
		if g.host != nil {
			g.host.Disconnect()
		}
		g.closePty()
		g.closeShells()
		g.mu.Lock()
		for c := range g.clients {
			close(c.closed)
		}
		g.clients = make(map[*wsClient]struct{})
		g.mu.Unlock()
		if g.srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = g.srv.Shutdown(ctx)
			cancel()
		}
		if g.ln != nil {
			_ = g.ln.Close()
		}
	})
}

// ExitProcess is what the operator console calls when the operator quits
// from inside the console (typing `exit`, Ctrl+D, ...): log synchronously
// (the async logger would lose this line on os.Exit), forget the saved
// session so the next start shows the login box, tear the GUI down (WireGuard
// tunnel, pty, shells, HTTP server) and leave.
func ExitProcess() {
	LogSync("Exiting emp3r0r... Goodbye!")
	ClearSession()
	if b := backendRef.Load(); b != nil {
		b.shutdown()
	}
	os.Exit(0)
}

// startCdn2ProxyServer wraps the vendored cdn2proxy server used by the cc
// binary in client mode.
func startCdn2ProxyServer(port, destAddr string, logOutput *os.File) error {
	return cdn2proxy.StartServer(port, destAddr, "ws", logOutput)
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
