package mcp

import (
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestGenerateToolDefinitions(t *testing.T) {
	actions := &Actions{}
	tools := actions.Tools()
	for _, name := range []string{"generate", "generate_c"} {
		tool, ok := tools[name]
		if !ok {
			t.Fatalf("missing tool %q", name)
		}
		if !tool.Destructive {
			t.Fatalf("%s must be destructive", name)
		}
		params := tool.Def.Function.Parameters
		required, _ := params["required"].([]string)
		if len(required) != 0 {
			t.Fatalf("%s required = %v, want cc to be optional", name, required)
		}
	}
}

func TestNewGoBuildSpecDefaults(t *testing.T) {
	spec, err := newGoBuildSpec(goGenerateArgs{CC: new("c2.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if spec.PayloadType != builder.PayloadTypeLinuxSO || spec.Arch != "amd64" {
		t.Fatalf("defaults = %s/%s", spec.PayloadType, spec.Arch)
	}
	if spec.IdleTimeout != 1800 {
		t.Fatalf("idle timeout = %d, want 1800", spec.IdleTimeout)
	}
	if spec.Config.CCAddress == nil || *spec.Config.CCAddress != "c2.example.com" {
		t.Fatalf("cc = %v", spec.Config.CCAddress)
	}
}

func TestNewGoBuildSpecRejectsBadInput(t *testing.T) {
	if _, err := newGoBuildSpec(goGenerateArgs{}); err == nil {
		t.Fatal("missing cc accepted")
	}
	if _, err := newGoBuildSpec(goGenerateArgs{
		CC:   new("c2.example.com"),
		Type: builder.PayloadTypeWindowsExecutable,
		Arch: "mips",
	}); err == nil {
		t.Fatal("invalid payload arch accepted")
	}
	if _, err := newGoBuildSpec(goGenerateArgs{
		CC:               new("c2.example.com"),
		TransportOptions: map[string]string{" ": "x"},
	}); err == nil {
		t.Fatal("empty transport option key accepted")
	}
}

func TestBuildSpecsDefaultToConfiguredCC(t *testing.T) {
	goSpec, err := newGoBuildSpecWithCC(goGenerateArgs{}, "https://c2.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if goSpec.CC != "https://c2.example.com" {
		t.Fatalf("go cc = %q, want the configured address without a trailing slash", goSpec.CC)
	}
	if goSpec.Config.CCAddress == nil || *goSpec.Config.CCAddress != goSpec.CC {
		t.Fatalf("go config cc = %v, want %q", goSpec.Config.CCAddress, goSpec.CC)
	}

	cSpec, err := newCBuildSpecWithCC(cGenerateArgs{}, "https://c2.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if cSpec.CC != "https://c2.example.com" {
		t.Fatalf("C cc = %q, want the configured address without a trailing slash", cSpec.CC)
	}
	if cSpec.Config.CCAddress == nil || *cSpec.Config.CCAddress != cSpec.CC {
		t.Fatalf("C config cc = %v, want %q", cSpec.Config.CCAddress, cSpec.CC)
	}
}

func TestBuildSpecsIgnoreMutatedRuntimeCC(t *testing.T) {
	old := live.GetRuntimeConfig()
	t.Cleanup(func() { live.SetRuntimeConfig(old) })
	live.SetRuntimeConfig(&def.Config{CCAddress: "https://mutated.example.com"})

	goSpec, err := newGoBuildSpecWithCC(goGenerateArgs{}, "https://initial.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if goSpec.CC != "https://initial.example.com" {
		t.Fatalf("go cc = %q, want the captured session address", goSpec.CC)
	}
	cSpec, err := newCBuildSpecWithCC(cGenerateArgs{}, "https://initial.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cSpec.CC != "https://initial.example.com" {
		t.Fatalf("C cc = %q, want the captured session address", cSpec.CC)
	}
}

func TestNewCBuildSpecDefaults(t *testing.T) {
	spec, err := newCBuildSpec(cGenerateArgs{CC: new("c2.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	want := builder.CAgentProviders{
		Crypto: builder.CAgentCryptoProviders[0], Gzip: builder.CAgentGzipProviders[0],
		Transport: "libcurl", Dynload: "libc_dl", Glibc: builder.CAgentGlibcVersions[0],
		Libc: builder.CAgentLibcs[0], Arch: builder.CAgentArches[0],
		Format: builder.CAgentFormats[0], Bof: "1", Rvvm: "1",
	}
	if spec.Providers != want {
		t.Fatalf("providers = %+v, want %+v", spec.Providers, want)
	}
	if spec.ChannelMode != "http_poll" {
		t.Fatalf("channel = %q", spec.ChannelMode)
	}
	if spec.Config.PollInterval == nil || *spec.Config.PollInterval != 60 {
		t.Fatalf("interval = %v", spec.Config.PollInterval)
	}
}

func TestNewCBuildSpecMuslDynload(t *testing.T) {
	spec, err := newCBuildSpec(cGenerateArgs{
		CC:   new("c2.example.com"),
		Type: "musl",
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Providers.Dynload != "public" {
		t.Fatalf("musl dynload = %q, want public", spec.Providers.Dynload)
	}
}

func TestNewCBuildSpecCustomTransport(t *testing.T) {
	if _, err := newCBuildSpec(cGenerateArgs{
		CC:            new("c2.example.com"),
		C2ChannelMode: new("tor"),
	}); err == nil {
		t.Fatal("custom channel without allow_custom_transport accepted")
	}
	spec, err := newCBuildSpec(cGenerateArgs{
		CC:                   new("c2.example.com"),
		C2ChannelMode:        new("tor"),
		AllowCustomTransport: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Providers.Transport != "tor" {
		t.Fatalf("custom transport = %q, want tor", spec.Providers.Transport)
	}
	if _, err := newCBuildSpec(cGenerateArgs{
		CC:                   new("c2.example.com"),
		C2ChannelMode:        new("tor"),
		Transport:            new("libcurl"),
		AllowCustomTransport: true,
	}); err == nil {
		t.Fatal("mismatched custom transport accepted")
	}
	if _, err := newCBuildSpec(cGenerateArgs{
		CC:        new("c2.example.com"),
		Transport: new("tor"),
	}); err == nil {
		t.Fatal("custom transport on a built-in channel accepted")
	}
}

func TestNewCBuildSpecRejectsBadTiming(t *testing.T) {
	if _, err := newCBuildSpec(cGenerateArgs{CC: new("c2.example.com"), Interval: new(0)}); err == nil {
		t.Fatal("zero interval accepted")
	}
	if _, err := newCBuildSpec(cGenerateArgs{CC: new("c2.example.com"), PollWindow: new(0)}); err == nil {
		t.Fatal("zero poll window accepted")
	}
}

func TestGenerateSchemasExposeProviderChoices(t *testing.T) {
	actions := &Actions{}
	tools := actions.Tools()
	generate := tools["generate"].Def.Function.Parameters
	arch := generate["properties"].(map[string]any)["arch"].(map[string]any)
	if len(arch["enum"].([]string)) != len(builder.ArchListAll) {
		t.Fatalf("arch enum = %v", arch["enum"])
	}
	generateC := tools["generate_c"].Def.Function.Parameters
	format := generateC["properties"].(map[string]any)["format"].(map[string]any)
	if len(format["enum"].([]string)) != len(builder.CAgentFormats) {
		t.Fatalf("format enum = %v", format["enum"])
	}
	if _, ok := tools["generate_c"].Def.Function.Parameters["properties"].(map[string]any)["transport"]; !ok {
		t.Fatal("generate_c schema is missing transport")
	}
}

func TestGenerationReviewHasNoTargetCapabilities(t *testing.T) {
	for _, kind := range []string{"Go agent", "C agent"} {
		review := buildReview(kind)
		if len(review.Rules) != 0 {
			t.Fatalf("%s rules = %v, want no target capabilities", kind, review.Rules)
		}
		if review.Noise != "low" {
			t.Fatalf("%s noise = %q, want low", kind, review.Noise)
		}
	}
}
