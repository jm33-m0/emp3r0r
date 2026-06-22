package operator

import (
	"bytes"
	"context"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/reeflective/console"
	"github.com/spf13/cobra"
)

func TestMsgTunDecoding(t *testing.T) {
	// 1. Prepare a sample message
	originalMsg := &def.MsgTunData{
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
	decodedMsg := new(def.MsgTunData)
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
