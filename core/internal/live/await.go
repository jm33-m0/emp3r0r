package live

import (
	"fmt"
	"time"
)

// replySlack covers the round trip and the agent-side work a command triggers
// (dialing a target, reading a file) once the agent has picked the command up.
// A var so tests can shorten the wait.
var replySlack = 15 * time.Second

// AgentReplyTimeout bounds how long an agent-side reaction to a dispatched
// command may take.
//
// Agents pick commands up only when they poll, so any wait shorter than one
// poll interval times out on an agent that is not currently in its command
// window. Every request/response path over the command tunnel has to bound its
// wait this way: a command result, an FTP stream, a SOCKS5 relay stream or a
// DNS reply all start with the agent polling.
//
// The bound covers one poll interval with its jitter, the window in which the
// agent waits for commands after check-in, and the round trip.
func AgentReplyTimeout() time.Duration {
	cfg := GetRuntimeConfig()
	interval := cfg.PollInterval
	if interval <= 0 {
		interval = 60
	}
	jitter := cfg.Jitter
	if jitter < 0 {
		jitter = 0
	}
	window := cfg.PollWindow
	if window < 0 {
		window = 0
	}

	polled := time.Duration(interval*(100+jitter)/100+window) * time.Second
	return polled + replySlack
}

// AwaitCmdResult sends a command and returns the agent's result for jobID.
//
// The notification channel is registered before send runs, so a reply that
// arrives immediately cannot be missed. A zero timeout uses AgentReplyTimeout.
// The cached result and the registration are dropped before returning.
func AwaitCmdResult(jobID string, timeout time.Duration, send func() error) (string, error) {
	if send == nil {
		return "", fmt.Errorf("no command to send")
	}
	if timeout <= 0 {
		timeout = AgentReplyTimeout()
	}

	ready := make(chan struct{}, 1)
	CmdResultsReady.Store(jobID, ready)
	defer CmdResultsReady.Delete(jobID)

	// A caller that dispatches first and waits afterwards can observe a result
	// that was cached before the waiter existed; the notification channel will
	// never be signalled in that case.
	if res, ok := CmdResultString(jobID); ok {
		CmdResults.Delete(jobID)
		return res, nil
	}

	if err := send(); err != nil {
		return "", err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ready:
	case <-timer.C:
		return "", fmt.Errorf("no result from agent after %s", timeout)
	}

	res, ok := CmdResultString(jobID)
	if !ok {
		return "", fmt.Errorf("agent result for job %s was not cached", jobID)
	}
	CmdResults.Delete(jobID)
	return res, nil
}
