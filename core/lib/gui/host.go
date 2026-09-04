// Package gui hosts the browser operator console for emp3r0r: the embedded
// web frontend, the websocket bridge to the interactive readline console, the
// OS shell sessions, agent table/mesh data and session persistence.
//
// It is deliberately decoupled from the operator console package
// (internal/cc/operator): everything lib/gui needs from the console goes
// through the ConsoleHost interface below, which the operator implements and
// passes to Run. Agent records and display helpers stay in the operator;
// lib/gui only receives the ready-made Agent DTOs, mirroring how lib/cli
// stays independent of it.
package gui

// ConsoleHost is the operator console that lib/gui presents in the browser.
// It is implemented by internal/cc/operator and handed to Run.
type ConsoleHost interface {
	// Connect brings the C2 link up for creds: WireGuard tunnel to the C2
	// server, operator config download/load and operator background jobs.
	// It returns once the operator is connected (the console is not started
	// yet) and must clean up after itself when it returns an error.
	Connect(creds Creds) error
	// Disconnect tears the C2 link down (WireGuard tunnel, ...). It is
	// called exactly once on GUI shutdown.
	Disconnect()
	// ConfigureConsole runs the one-time operator console setup (modules,
	// command tree, prompt, history). It needs a loaded operator config,
	// i.e. it must be called after Connect succeeded.
	ConfigureConsole()
	// RunConsole blocks while the interactive operator console runs on the
	// pty that lib/gui has attached to fds 0/1/2. It returns when the
	// console exits (by error or by the operator quitting).
	RunConsole() error
	// SelectAgent targets an agent by tag — the same effect as the console
	// `target` command.
	SelectAgent(tag string) bool
	// Agents returns the current agent snapshot (wire DTOs) for the table
	// and mesh views, built by the operator from its agent registry.
	Agents() []Agent
}

// PublishAgents hands a fresh agent snapshot to the GUI frontends. It is the
// sink the operator's agent-list refresher calls (in GUI mode) instead of
// writing into its tmux pane; it is a no-op when no GUI backend is running.
func PublishAgents(agents []Agent) {
	if b := ActiveBackend(); b != nil {
		b.publishAgents(agents)
	}
}
