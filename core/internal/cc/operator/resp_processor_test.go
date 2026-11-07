package operator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/paths"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestProcessAgentDataOnlyRecordsResult(t *testing.T) {
	live.ClearAgents()
	t.Cleanup(live.ClearAgents)
	live.PublishAgent(&live.AgentRecord{Agent: &def.Emp3r0rAgent{UUID: "uuid-1", Tag: "tag-1"}})
	const jobID = "job-1"
	t.Cleanup(func() { live.CmdResults.Delete(jobID) })

	ProcessAgentDataOnly(&def.OperatorMsg{
		Tag:      "tag-1",
		JobID:    jobID,
		CmdSlice: []string{"whoami"},
		Response: []byte("root"),
	})

	out, ok := live.CmdResultString(jobID)
	if !ok || out != "root" {
		t.Fatalf("cached result = %q, %v; want root, true", out, ok)
	}
}

// TestProcessAgentDataOnlyCompletesJob covers the job status the MCP
// list_jobs tool reports. The response is the only signal that a delivered
// command finished, so the local job record must leave the pending state.
func TestProcessAgentDataOnlyCompletesJob(t *testing.T) {
	live.ClearAgents()
	t.Cleanup(live.ClearAgents)
	live.PublishAgent(&live.AgentRecord{Agent: &def.Emp3r0rAgent{UUID: "uuid-job", Tag: "tag-job"}})

	job := jobs.CreateJob("probe", "probe", "tag-job")
	t.Cleanup(func() {
		jobs.Jobs.Delete(job.ID)
		live.CmdResults.Delete(job.ID)
	})

	ProcessAgentDataOnly(&def.OperatorMsg{
		Tag:      "tag-job",
		JobID:    job.ID,
		CmdSlice: []string{"probe"},
		Response: []byte("done"),
	})

	updated := jobs.GetJob(job.ID)
	if updated == nil {
		t.Fatal("job disappeared")
	}
	if updated.Status != def.JobStatusCompleted {
		t.Fatalf("status = %v, want completed", updated.Status)
	}
	if updated.Finished.IsZero() {
		t.Fatal("Finished was not recorded")
	}
}

// TestProcessAgentDataOnlyServesWWWRelay covers the MCP/headless handler: an
// agent asking this operator for a hosted module file arrives as a tunnel
// message, and the file must be streamed back. Treating the tag as an agent
// name instead leaves the agent waiting forever and its job pending.
func TestProcessAgentDataOnlyServesWWWRelay(t *testing.T) {
	oldRoot := paths.WWWRoot
	paths.WWWRoot = t.TempDir() + string(os.PathSeparator)
	t.Cleanup(func() { paths.WWWRoot = oldRoot })

	frames := make(chan *def.OperatorMsg, 4)
	oldSend := relaySend
	relaySend = func(msg *def.OperatorMsg) error {
		frames <- msg
		return nil
	}
	t.Cleanup(func() { relaySend = oldSend })

	const name = "test_module.x64.o"
	payload := []byte("COFF payload")
	if err := os.WriteFile(filepath.Join(paths.WWWRoot, name), payload, 0o600); err != nil {
		t.Fatalf("write hosted file: %v", err)
	}
	key := network.LocalWWWDownloadKey(name)
	network.WWWDownloads.Store(key, &network.WWWDownload{Name: name, AgentUUID: "uuid-1"})
	t.Cleanup(func() { network.WWWDownloads.Delete(key) })

	ProcessAgentDataOnly(&def.OperatorMsg{Tag: def.TagWWWRelayRequestPrefix + name})

	var served []byte
	deadline := time.After(3 * time.Second)
	for {
		select {
		case frame := <-frames:
			switch {
			case strings.HasPrefix(frame.Tag, def.TagWWWRelayDataPrefix):
				served = append(served, frame.Response...)
			case strings.HasPrefix(frame.Tag, def.TagWWWRelayDonePrefix):
				if string(served) != string(payload) {
					t.Fatalf("relay served %q, want %q", served, payload)
				}
				return
			case strings.HasPrefix(frame.Tag, def.TagWWWRelayErrorPrefix):
				t.Fatalf("relay failed: %s", frame.Response)
			}
		case <-deadline:
			t.Fatalf("relay never served %q (got %q); the request was not dispatched", name, served)
		}
	}
}
