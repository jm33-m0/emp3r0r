package operator

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/reeflective/console"
	"github.com/spf13/cobra"
)

func TestMsgTunDecoding(t *testing.T) {
	// 1. Prepare a sample message
	originalMsg := &def.OperatorMsg{
		Tag:      "test-agent",
		JobID:    "cmd-123",
		CmdSlice: []string{"ls", "-la"},
		Response: []byte("file1\nfile2"),
	}

	// 2. Encode it to CBOR (simulating the server)
	var buf bytes.Buffer
	encoder := cbor.NewEncoder(&buf)
	err := encoder.Encode(originalMsg)
	if err != nil {
		t.Fatalf("Failed to encode message: %v", err)
	}

	// 3. Decode it using CBOR decoder (simulating the operator)
	decoder := cbor.NewDecoder(&buf)
	decodedMsg := new(def.OperatorMsg)
	err = decoder.Decode(decodedMsg)
	if err != nil {
		t.Fatalf("Failed to decode message: %v", err)
	}

	// 4. Verify the content
	if decodedMsg.Tag != originalMsg.Tag {
		t.Errorf("Tag mismatch: got %s, want %s", decodedMsg.Tag, originalMsg.Tag)
	}
	if decodedMsg.JobID != originalMsg.JobID {
		t.Errorf("JobID mismatch: got %s, want %s", decodedMsg.JobID, originalMsg.JobID)
	}
	if len(decodedMsg.CmdSlice) != len(originalMsg.CmdSlice) {
		t.Errorf("CmdSlice length mismatch")
	} else {
		for i, v := range decodedMsg.CmdSlice {
			if v != originalMsg.CmdSlice[i] {
				t.Errorf("CmdSlice[%d] mismatch: got %s, want %s", i, v, originalMsg.CmdSlice[i])
			}
		}
	}
	if string(decodedMsg.Response) != string(originalMsg.Response) {
		t.Errorf("Response mismatch: got %s, want %s", decodedMsg.Response, originalMsg.Response)
	}
}

func TestConsoleMenuMismatchFix(t *testing.T) {
	c := console.New("test-app")
	// Retrieve active menu to register commands
	mainMenu := c.ActiveMenu()

	executed := false
	cmd := &cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {
			executed = true
		},
	}
	mainMenu.SetCommands(func() *cobra.Command {
		root := &cobra.Command{}
		root.AddCommand(cmd)
		return root
	})

	// Retrieve active menu, which console runs with
	activeMenu := c.ActiveMenu()
	// Trigger command execution via the public API (this internally calls resetPreRun and executes)
	err := activeMenu.RunCommandLine(context.Background(), "test")
	if err != nil {
		t.Fatalf("Failed to run command line: %v", err)
	}

	if !executed {
		t.Error("Test command was not executed; the active menu did not resolve the commands")
	}
}

func TestGenerateCommandsDocumentTransportPorts(t *testing.T) {
	generate := gen_agent_cmd()
	for _, want := range []string{
		"http_poll", "h2conn", "quic",
		"CCHTTPPort", "CCH2Port",
		"https://front.example.com",
		"--cc-http-port",
	} {
		if !strings.Contains(generate.Long, want) {
			t.Errorf("generate help does not mention %q", want)
		}
	}

	generateC := gen_c_cmd()
	for _, want := range []string{"http_poll", "--cc-http-port", "https://", "libssl", "libcurl"} {
		if !strings.Contains(generateC.Long, want) {
			t.Errorf("generate_c help does not mention %q", want)
		}
	}
}

func TestCAgentEndpointPreservesTLSURL(t *testing.T) {
	if got := cAgentEndpoint("https://front.example.com:8443/", "8080"); got != "https://front.example.com:8443" {
		t.Fatalf("cAgentEndpoint(TLS URL) = %q", got)
	}
	if got := cAgentEndpoint("c2.example.com", "8080"); got != "http://c2.example.com:8080" {
		t.Fatalf("cAgentEndpoint(host) = %q", got)
	}
}

func TestC2AddressAndPortCompletions(t *testing.T) {
	previous := live.GetRuntimeConfig()
	live.SetRuntimeConfig(&def.Config{
		CCAddress:  "c2.example.com",
		CCHTTPPort: "8080",
		CCH2Port:   "8443",
	})
	t.Cleanup(func() { live.SetRuntimeConfig(previous) })

	addresses := c2AddressCompletions()
	for _, want := range []string{
		"c2.example.com",
		"https://c2.example.com",
		"http://c2.example.com",
		"https://c2.example.com:8443",
		"http://c2.example.com:8080",
	} {
		if !slices.Contains(addresses, want) {
			t.Errorf("c2AddressCompletions() missing %q: %v", want, addresses)
		}
	}

	ports := c2PortCompletions()
	for _, want := range []string{"8080", "8443", "443"} {
		if !slices.Contains(ports, want) {
			t.Errorf("c2PortCompletions() missing %q: %v", want, ports)
		}
	}

	live.GetRuntimeConfig().CCAddress = "https://front.example.com"
	if got := c2AddressCompletions(); !slices.Contains(got, "https://front.example.com") {
		t.Errorf("c2AddressCompletions() did not preserve explicit URL: %v", got)
	}
}
