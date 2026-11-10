package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/assistant"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	maxAgentTypeBytes = 128
	maxAgentPathBytes = 4096
	maxTransportOpts  = 32
	maxTransportKey   = 128
	maxTransportValue = 4096
)

// generateTools returns the agent generation tools. They build a payload on the
// host running this MCP server, using the same builder as the console's
// generate and generate_c commands.
func (a *Actions) generateTools() map[string]assistant.Tool {
	return map[string]assistant.Tool{
		"generate": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:        "generate",
					Description: "Build a Go agent payload on this operator host. Defaults match the console: payload type linux_so and architecture amd64. Windows executable and DLL builds are also converted to Donut shellcode automatically; the result includes shellcode_file for use with loader_windows. Omit cc to use the configured C2 address. The call is screened and audited like other mutating tools.",
					Parameters: assistant.ObjectSchema(map[string]any{
						"type": map[string]any{
							"type":        "string",
							"enum":        builder.PayloadTypeList,
							"description": "Payload type. Default linux_so.",
						},
						"arch": map[string]any{
							"type":        "string",
							"enum":        builder.ArchListAll,
							"description": "Target architecture. Default amd64; valid values depend on type.",
						},
						"cc":                     assistant.StringProp("C2 hostname, or an explicit http(s) URL for TLS. Omit to use the C2 address already configured on this operator; never guess or substitute 127.0.0.1."),
						"c2_channel_mode":        assistant.StringProp("C2 channel mode. Default http_poll."),
						"allow_custom_transport": assistant.BooleanProp("Allow a c2_channel_mode that is not built into this C2. The agent build must include the matching dialer."),
						"transport_options": map[string]any{
							"type":                 "object",
							"description":          "Custom transport options as key to value.",
							"additionalProperties": map[string]any{"type": "string"},
						},
						"quic_standard_key":     assistant.BooleanProp("QUIC only: speak stock QUIC instead of the custom static-key obfuscation."),
						"proxy":                 assistant.StringProp("Hard-coded proxy URL for the agent C2 transport, for example socks5://127.0.0.1:9050."),
						"doh":                   assistant.StringProp("DNS over HTTPS resolver URL."),
						"ech":                   assistant.StringProp("ECH: DNS name whose HTTPS RR carries the ECHConfigList, fetched over doh."),
						"cc_http_port":          assistant.StringProp("HTTP polling port baked into the agent."),
						"interval":              assistant.IntegerProp("Beacon interval in seconds."),
						"jitter":                assistant.IntegerProp("Beacon jitter percentage, 0-100."),
						"operator_idle_timeout": assistant.IntegerProp("C2 operator idle timeout in seconds. Default 1800; 0 disables it."),
						"p2p":                   assistant.BooleanProp("Enable P2P mesh networking."),
						"p2p_transport":         assistant.StringProp("P2P mesh transport: kcp/mtls, or smb for Windows payloads."),
						"p2p_relay_port":        assistant.StringProp("Custom P2P relay port."),
						"mesh_gossip_port":      assistant.StringProp("Custom mesh gossip port."),
						"direct_c2":             assistant.BooleanProp("Gateway mode: contact C2 directly and relay for silent nodes."),
						"persistent_router":     assistant.BooleanProp("Keep the current router while it is alive."),
						"peers": map[string]any{
							"type":        "array",
							"items":       map[string]any{"type": "string"},
							"description": "Gossip bootstrap peers in ip:port form.",
						},
						"ncsi":   assistant.BooleanProp("Check Internet connectivity with NCSI before connecting to C2."),
						"stager": assistant.BooleanProp("Build for the stager: enables memory encryption and suspension."),
					}),
				},
			},
			Destructive: true,
			Run:         a.generateGoAgent,
		},
		"generate_c": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:        "generate_c",
					Description: "Build the native C agent on this operator host. type selects the libc ABI and arch selects the C toolchain target; format=shellcode produces a malasada-wrapped raw PIC blob. Omit cc to use the configured C2 address. The call is screened and audited like other mutating tools.",
					Parameters: assistant.ObjectSchema(map[string]any{
						"type": map[string]any{
							"type":        "string",
							"enum":        builder.CAgentLibcs,
							"description": "libc ABI. Default glibc.",
						},
						"arch": map[string]any{
							"type":        "string",
							"enum":        builder.CAgentArches,
							"description": "C toolchain target architecture. Default amd64.",
						},
						"cc":                     assistant.StringProp("C2 hostname, or an explicit http(s) URL for TLS. Omit to use the C2 address already configured on this operator; never guess or substitute 127.0.0.1."),
						"cc_http_port":           assistant.StringProp("HTTP polling port baked into the agent."),
						"doh":                    assistant.StringProp("DNS over HTTPS resolver URL."),
						"c2_channel_mode":        assistant.StringProp("C2 channel mode. Default http_poll."),
						"allow_custom_transport": assistant.BooleanProp("Allow a custom c2_channel_mode and transport provider shipped under the C agent source tree."),
						"transport_options": map[string]any{
							"type":                 "object",
							"description":          "Custom transport options as key to value.",
							"additionalProperties": map[string]any{"type": "string"},
						},
						"crypto":        map[string]any{"type": "string", "enum": builder.CAgentCryptoProviders, "description": "Crypto provider. Default openssl."},
						"format":        map[string]any{"type": "string", "enum": builder.CAgentFormats, "description": "Artifact format: exe, so, or shellcode. Default exe."},
						"gzip":          map[string]any{"type": "string", "enum": builder.CAgentGzipProviders, "description": "Compression provider. Default miniz."},
						"transport":     assistant.StringProp("Transport provider: libcurl, http_raw, libssl, tor, or a custom provider name with allow_custom_transport."),
						"dynload":       map[string]any{"type": "string", "enum": builder.CAgentDynloadModes, "description": "libc dynamic-loader symbols. Default libc_dl; musl forces public."},
						"glibc_version": map[string]any{"type": "string", "enum": builder.CAgentGlibcVersions, "description": "Oldest glibc ABI to link against. Default 2.17."},
						"bof":           assistant.BooleanProp("Include COFF/BOF support. Default true."),
						"rvvm":          assistant.BooleanProp("Include RISC-V BOF support. Default true."),
						"interval":      assistant.IntegerProp("Beacon interval in seconds. Default 60."),
						"jitter":        assistant.IntegerProp("Beacon jitter percentage, 0-100. Default 50."),
						"poll_window":   assistant.IntegerProp("Seconds to wait for commands after hello before masked sleep. Default 5."),
						"offline_grace": assistant.IntegerProp("Seconds a sleeping agent stays listed before removal. Default 0."),
					}),
				},
			},
			Destructive: true,
			Run:         a.generateCAgent,
		},
	}
}

type goGenerateArgs struct {
	Type                 string            `json:"type"`
	Arch                 string            `json:"arch"`
	CC                   *string           `json:"cc"`
	C2ChannelMode        *string           `json:"c2_channel_mode"`
	AllowCustomTransport bool              `json:"allow_custom_transport"`
	TransportOptions     map[string]string `json:"transport_options"`
	QUICStandardKey      bool              `json:"quic_standard_key"`
	Proxy                *string           `json:"proxy"`
	DoH                  *string           `json:"doh"`
	ECH                  *string           `json:"ech"`
	CCHTTPPort           *string           `json:"cc_http_port"`
	Interval             *int              `json:"interval"`
	Jitter               *int              `json:"jitter"`
	OperatorIdleTimeout  *int              `json:"operator_idle_timeout"`
	P2P                  bool              `json:"p2p"`
	P2PTransport         *string           `json:"p2p_transport"`
	P2PRelayPort         *string           `json:"p2p_relay_port"`
	MeshGossipPort       *string           `json:"mesh_gossip_port"`
	DirectC2             bool              `json:"direct_c2"`
	PersistentRouter     bool              `json:"persistent_router"`
	Peers                *[]string         `json:"peers"`
	NCSI                 bool              `json:"ncsi"`
	Stager               bool              `json:"stager"`
}

type goBuildSpec struct {
	PayloadType string
	Arch        string
	CC          string
	Config      builder.AgentConfig
	IdleTimeout int
	SetIdle     bool
	Flags       map[string]string
}

func newGoBuildSpec(args goGenerateArgs) (*goBuildSpec, error) {
	return newGoBuildSpecWithCC(args, "")
}

func newGoBuildSpecWithCC(args goGenerateArgs, defaultCC string) (*goBuildSpec, error) {
	payloadType := strings.TrimSpace(args.Type)
	if payloadType == "" {
		payloadType = builder.PayloadTypeLinuxSO
	}
	arch := strings.TrimSpace(args.Arch)
	if arch == "" {
		arch = "amd64"
	}
	if len(payloadType) > maxAgentTypeBytes || len(arch) > maxAgentTypeBytes {
		return nil, fmt.Errorf("type or arch is too long")
	}
	if !validChoice(payloadType, builder.PayloadTypeList) {
		return nil, fmt.Errorf("unknown payload type %q (available: %v)", payloadType, builder.PayloadTypeList)
	}
	if !builder.IsArchValid(payloadType, arch) {
		return nil, fmt.Errorf("invalid arch %q for payload type %q (available: %v)", arch, payloadType, builder.ArchListAll)
	}
	cc, err := resolveCCAddress(args.CC, defaultCC)
	if err != nil {
		return nil, err
	}
	transportOptions, err := normalizeTransportOptions(args.TransportOptions)
	if err != nil {
		return nil, err
	}
	idleTimeout := 1800
	if args.OperatorIdleTimeout != nil {
		idleTimeout = *args.OperatorIdleTimeout
	}
	if idleTimeout < 0 {
		return nil, fmt.Errorf("operator_idle_timeout must be >= 0")
	}
	peers, err := normalizePeers(args.Peers)
	if err != nil {
		return nil, err
	}
	opts := builder.AgentConfig{
		CCAddress:            &cc,
		C2TransportProxy:     trimStringPtr(args.Proxy),
		DoHServer:            trimStringPtr(args.DoH),
		ECHServerName:        trimStringPtr(args.ECH),
		C2ChannelMode:        trimStringPtr(args.C2ChannelMode),
		AllowCustomTransport: args.AllowCustomTransport,
		TransportOptions:     transportOptions,
		QUICStandardKey:      args.QUICStandardKey,
		InitialPeers:         peers,
		P2PTransport:         trimStringPtr(args.P2PTransport),
		P2PRelayPort:         trimStringPtr(args.P2PRelayPort),
		MeshGossipPort:       trimStringPtr(args.MeshGossipPort),
		CCHTTPPort:           trimStringPtr(args.CCHTTPPort),
		PollInterval:         args.Interval,
		Jitter:               args.Jitter,
		OperatorIdleTimeout:  &idleTimeout,
		IsP2PEnabled:         args.P2P,
		IsDirectC2:           args.DirectC2,
		PersistentRouter:     args.PersistentRouter,
		IsNCSIEnabled:        args.NCSI,
		IsStager:             args.Stager,
	}
	return &goBuildSpec{
		PayloadType: payloadType,
		Arch:        arch,
		CC:          cc,
		Config:      opts,
		IdleTimeout: idleTimeout,
		SetIdle:     args.OperatorIdleTimeout != nil,
		Flags: map[string]string{
			"type": payloadType,
			"arch": arch,
			"cc":   cc,
		},
	}, nil
}

func (a *Actions) generateGoAgent(_ context.Context, raw json.RawMessage) (any, error) {
	var args goGenerateArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	spec, err := newGoBuildSpecWithCC(args, a.DefaultCC)
	if err != nil {
		return nil, err
	}
	return a.runGoBuild(spec), nil
}

func (a *Actions) runGoBuild(spec *goBuildSpec) map[string]any {
	review := buildReview("Go agent")
	decision, auditErr := a.screen("generate", "", "", nil, review)
	if !decision.Allowed {
		blocked := actionBlocked("generate", "", "", nil, review, decision, auditErr)
		blocked["type"] = spec.PayloadType
		blocked["arch"] = spec.Arch
		return blocked
	}

	a.generateMu.Lock()
	defer a.generateMu.Unlock()

	var warnings []string
	if spec.SetIdle {
		if err := client.UpdateOperatorIdleConfig(spec.IdleTimeout); err != nil {
			warnings = append(warnings, "update operator idle timeout: "+err.Error())
		}
	}
	res, err := builder.GenerateAgentWorkflow(spec.Config, spec.PayloadType, spec.Arch, client.SignAgent)

	result := map[string]any{
		"executed":  err == nil,
		"type":      spec.PayloadType,
		"arch":      spec.Arch,
		"cc":        spec.CC,
		"opsec":     review,
		"decision":  decision,
		"transport": builder.DescribeGoAgentTransport(),
	}
	if len(decision.Warnings) > 0 {
		result["warnings"] = decision.Warnings
	}
	outputFile := ""
	size := 0
	if res != nil && res.BuildResult != nil {
		result["agent_uuid"] = res.BuildResult.AgentUUID
		result["output_file"] = res.BuildResult.OutputFile
		result["stub_file"] = res.BuildResult.StubFile
		result["config_size"] = res.BuildResult.ConfigSize
		outputFile = res.BuildResult.OutputFile
		size = res.BuildResult.ConfigSize
		if res.ShellcodeFile != "" {
			result["shellcode_file"] = res.ShellcodeFile
		}
		if res.ShellcodeErr != nil {
			result["shellcode_error"] = res.ShellcodeErr.Error()
		}
	}
	if err != nil {
		result["error"] = err.Error()
	}
	if len(warnings) > 0 {
		result["warnings"] = warnings
	}
	if auditErr != nil {
		result["audit_error"] = auditErr.Error()
	}
	if logErr := a.Audit.Log(AuditRecord{
		Operator: a.Operator, Tool: "generate", Flags: spec.Flags,
		Rules: review.Rules, Noise: review.Noise, Phase: "result",
		Allowed: decision.Allowed, Reason: decision.Reason,
		Path: outputFile, Bytes: size, Error: errorString(err),
	}); logErr != nil {
		result["audit_error"] = logErr.Error()
		logging.Errorf("mcp audit: %v", logErr)
	}
	return result
}

type cGenerateArgs struct {
	Type                 string            `json:"type"`
	Arch                 string            `json:"arch"`
	CC                   *string           `json:"cc"`
	CCHTTPPort           *string           `json:"cc_http_port"`
	DoH                  *string           `json:"doh"`
	C2ChannelMode        *string           `json:"c2_channel_mode"`
	AllowCustomTransport bool              `json:"allow_custom_transport"`
	TransportOptions     map[string]string `json:"transport_options"`
	Crypto               string            `json:"crypto"`
	Format               string            `json:"format"`
	Gzip                 string            `json:"gzip"`
	Transport            *string           `json:"transport"`
	Dynload              *string           `json:"dynload"`
	GlibcVersion         string            `json:"glibc_version"`
	Bof                  *bool             `json:"bof"`
	Rvvm                 *bool             `json:"rvvm"`
	Interval             *int              `json:"interval"`
	Jitter               *int              `json:"jitter"`
	PollWindow           *int              `json:"poll_window"`
	OfflineGrace         *int              `json:"offline_grace"`
}

type cBuildSpec struct {
	Config      builder.AgentConfig
	Providers   builder.CAgentProviders
	ChannelMode string
	CC          string
	Flags       map[string]string
}

func newCBuildSpec(args cGenerateArgs) (*cBuildSpec, error) {
	return newCBuildSpecWithCC(args, "")
}

func newCBuildSpecWithCC(args cGenerateArgs, defaultCC string) (*cBuildSpec, error) {
	libc := defaultAgentChoice(args.Type, builder.CAgentLibcs[0])
	arch := defaultAgentChoice(args.Arch, builder.CAgentArches[0])
	crypto := defaultAgentChoice(args.Crypto, builder.CAgentCryptoProviders[0])
	format := defaultAgentChoice(args.Format, builder.CAgentFormats[0])
	gzip := defaultAgentChoice(args.Gzip, builder.CAgentGzipProviders[0])
	glibc := defaultAgentChoice(args.GlibcVersion, builder.CAgentGlibcVersions[0])
	channelMode := defaultAgentChoice(pointerValue(args.C2ChannelMode), def.C2ChannelModeDefault)
	if len(libc) > maxAgentTypeBytes || len(arch) > maxAgentTypeBytes || len(crypto) > maxAgentTypeBytes ||
		len(format) > maxAgentTypeBytes || len(gzip) > maxAgentTypeBytes || len(glibc) > maxAgentTypeBytes {
		return nil, fmt.Errorf("a provider choice is too long")
	}
	for name, choice := range map[string]struct {
		value  string
		values []string
	}{
		"type":          {libc, builder.CAgentLibcs},
		"arch":          {arch, builder.CAgentArches},
		"crypto":        {crypto, builder.CAgentCryptoProviders},
		"format":        {format, builder.CAgentFormats},
		"gzip":          {gzip, builder.CAgentGzipProviders},
		"glibc_version": {glibc, builder.CAgentGlibcVersions},
	} {
		if !validChoice(choice.value, choice.values) {
			return nil, fmt.Errorf("unknown %s %q", name, choice.value)
		}
	}
	cc, err := resolveCCAddress(args.CC, defaultCC)
	if err != nil {
		return nil, err
	}
	transportOptions, err := normalizeTransportOptions(args.TransportOptions)
	if err != nil {
		return nil, err
	}
	transport := builder.CAgentTransportProviders[0]
	if args.Transport != nil && strings.TrimSpace(*args.Transport) != "" {
		transport = strings.TrimSpace(*args.Transport)
	}
	transport, err = builder.ResolveCAgentTransport(channelMode, transport, args.Transport != nil && strings.TrimSpace(*args.Transport) != "", args.AllowCustomTransport)
	if err != nil {
		return nil, err
	}
	dynload := builder.CAgentDynloadModes[0]
	dynloadSet := args.Dynload != nil && strings.TrimSpace(*args.Dynload) != ""
	if dynloadSet {
		dynload = strings.TrimSpace(*args.Dynload)
	}
	dynload = builder.CAgentDynloadForLibc(libc, dynload, dynloadSet)

	interval := intOrDefault(args.Interval, 60)
	jitter := intOrDefault(args.Jitter, 50)
	pollWindow := intOrDefault(args.PollWindow, 5)
	offlineGrace := intOrDefault(args.OfflineGrace, 0)
	if pollWindow < 1 {
		return nil, fmt.Errorf("poll_window must be >= 1 second")
	}
	if offlineGrace < 0 {
		return nil, fmt.Errorf("offline_grace must be >= 0 seconds")
	}
	if err := builder.ValidateCAgentPollTiming(interval, jitter); err != nil {
		return nil, fmt.Errorf("invalid beacon timing: %w", err)
	}
	bof := true
	if args.Bof != nil {
		bof = *args.Bof
	}
	rvvm := true
	if args.Rvvm != nil {
		rvvm = *args.Rvvm
	}

	providers := builder.CAgentProviders{
		Crypto:               crypto,
		Gzip:                 gzip,
		Transport:            transport,
		Dynload:              dynload,
		Glibc:                glibc,
		Libc:                 libc,
		Arch:                 arch,
		Format:               format,
		Bof:                  builder.BoolProvider(bof),
		Rvvm:                 builder.BoolProvider(rvvm),
		AllowCustomTransport: args.AllowCustomTransport,
	}
	opts := builder.AgentConfig{
		CCAddress:            &cc,
		CCHTTPPort:           trimStringPtr(args.CCHTTPPort),
		DoHServer:            trimStringPtr(args.DoH),
		C2ChannelMode:        &channelMode,
		AllowCustomTransport: args.AllowCustomTransport,
		TransportOptions:     transportOptions,
		PollInterval:         &interval,
		PollWindow:           &pollWindow,
		OfflineGrace:         &offlineGrace,
		Jitter:               &jitter,
		IsStager:             builder.CAgentStagerMode(providers.Format),
	}
	return &cBuildSpec{
		Config:      opts,
		Providers:   providers,
		ChannelMode: channelMode,
		CC:          cc,
		Flags: map[string]string{
			"type":      libc,
			"arch":      arch,
			"cc":        cc,
			"format":    format,
			"transport": transport,
			"channel":   channelMode,
		},
	}, nil
}

func (a *Actions) generateCAgent(_ context.Context, raw json.RawMessage) (any, error) {
	var args cGenerateArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	spec, err := newCBuildSpecWithCC(args, a.DefaultCC)
	if err != nil {
		return nil, err
	}
	return a.runCBuild(spec), nil
}

func (a *Actions) runCBuild(spec *cBuildSpec) map[string]any {
	review := buildReview("C agent")
	decision, auditErr := a.screen("generate_c", "", "", nil, review)
	if !decision.Allowed {
		blocked := actionBlocked("generate_c", "", "", nil, review, decision, auditErr)
		blocked["type"] = spec.Providers.Libc
		blocked["arch"] = spec.Providers.Arch
		blocked["format"] = spec.Providers.Format
		return blocked
	}

	a.generateMu.Lock()
	defer a.generateMu.Unlock()

	res, err := builder.GenerateCAgentWorkflow(spec.Config, spec.Providers, client.SignAgent)
	endpoint := builder.CAgentEndpoint(live.RuntimeConfig.CCAddress, live.RuntimeConfig.CCHTTPPort, spec.ChannelMode)
	result := map[string]any{
		"executed":     err == nil,
		"type":         spec.Providers.Libc,
		"arch":         spec.Providers.Arch,
		"format":       spec.Providers.Format,
		"cc":           spec.CC,
		"transport":    spec.Providers.Transport,
		"channel_mode": spec.ChannelMode,
		"endpoint":     endpoint,
		"opsec":        review,
		"decision":     decision,
	}
	if len(decision.Warnings) > 0 {
		result["warnings"] = decision.Warnings
	}
	outputFile := ""
	size := 0
	if res != nil {
		result["agent_uuid"] = res.AgentUUID
		result["output_file"] = res.OutputFile
		result["source_dir"] = res.StubFile
		result["config_size"] = res.ConfigSize
		outputFile = res.OutputFile
		size = res.ConfigSize
	}
	if err != nil {
		result["error"] = err.Error()
	}
	if strings.HasPrefix(endpoint, "https://") && spec.Providers.Transport == "http_raw" {
		result["warnings"] = []string{"http_raw does not support TLS; use transport libcurl or libssl"}
	}
	if auditErr != nil {
		result["audit_error"] = auditErr.Error()
	}
	if logErr := a.Audit.Log(AuditRecord{
		Operator: a.Operator, Tool: "generate_c", Flags: spec.Flags,
		Rules: review.Rules, Noise: review.Noise, Phase: "result",
		Allowed: decision.Allowed, Reason: decision.Reason,
		Path: outputFile, Bytes: size, Error: errorString(err),
	}); logErr != nil {
		result["audit_error"] = logErr.Error()
		logging.Errorf("mcp audit: %v", logErr)
	}
	return result
}

func buildReview(kind string) def.OpsecReview {
	return def.OpsecReview{
		Noise:      "low",
		Reversible: true,
		Reasons:    []string{"local " + kind + " build; no target execution"},
		Artifacts:  []string{"local " + kind + " artifact"},
	}
}

// resolveCCAddress returns the caller-supplied C2 address or the address
// captured when the MCP session started. Builders mutate live.RuntimeConfig,
// so the fallback is passed in rather than read here; an earlier explicit cc
// must not leak into later builds.
func resolveCCAddress(value *string, fallback string) (string, error) {
	if value != nil {
		if s := strings.TrimSpace(*value); s != "" {
			if len(s) > maxAgentPathBytes {
				return "", fmt.Errorf("cc is too long")
			}
			return s, nil
		}
	}
	if s := strings.TrimSpace(fallback); s != "" {
		if len(s) > maxAgentPathBytes {
			return "", fmt.Errorf("configured cc is too long")
		}
		return strings.TrimSuffix(s, "/"), nil
	}
	return "", fmt.Errorf("cc is required: no C2 address is configured on this operator; pass the C2 hostname explicitly")
}

func normalizeTransportOptions(options map[string]string) (map[string]string, error) {
	if len(options) == 0 {
		return nil, nil
	}
	if len(options) > maxTransportOpts {
		return nil, fmt.Errorf("too many transport options (max %d)", maxTransportOpts)
	}
	out := make(map[string]string, len(options))
	for key, value := range options {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			return nil, fmt.Errorf("transport option key is empty")
		}
		if len(key) > maxTransportKey || len(value) > maxTransportValue {
			return nil, fmt.Errorf("transport option %q is too long", key)
		}
		out[key] = value
	}
	return out, nil
}

func trimStringPtr(value *string) *string {
	if value == nil {
		return nil
	}
	s := strings.TrimSpace(*value)
	if s == "" {
		return nil
	}
	return &s
}

func normalizePeers(value *[]string) (*[]string, error) {
	if value == nil || len(*value) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(*value))
	for _, item := range *value {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if len(item) > maxAgentPathBytes {
			return nil, fmt.Errorf("a peer address is too long")
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return &out, nil
}

func defaultAgentChoice(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func validChoice(value string, values []string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func pointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func intOrDefault(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}
